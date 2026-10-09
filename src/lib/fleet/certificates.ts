import crypto from "node:crypto";
import { query } from "@/lib/db";
import { recordHashChainEvent } from "@/lib/fleet/fleet";

export interface EndpointCertificateRecord {
  id: string;
  agent_id: string;
  tenant_id: string;
  serial_number: string;
  certificate_pem: string;
  fingerprint_sha256: string;
  issued_at: string;
  expires_at: string;
  revoked_at?: string | null;
  revocation_reason?: string | null;
}

// In-memory fallback for testing and development environments
export const MOCK_ENDPOINT_CERTIFICATES: EndpointCertificateRecord[] = [];

// ---------------------------------------------------------------------------
// Lightweight ASN.1 DER Encoding Engine for RFC 5280 X.509 v3 Certificates
// ---------------------------------------------------------------------------

function derLength(len: number): Buffer {
  if (len < 128) return Buffer.from([len]);
  const bytes: number[] = [];
  let temp = len;
  while (temp > 0) {
    bytes.unshift(temp & 0xff);
    temp >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTag(tag: number, content: Buffer | string): Buffer {
  const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
  return Buffer.concat([Buffer.from([tag]), derLength(buf.length), buf]);
}

function derSeq(items: Buffer[]): Buffer {
  return derTag(0x30, Buffer.concat(items));
}

function derInt(num: number | Buffer): Buffer {
  let buf: Buffer;
  if (Buffer.isBuffer(num)) {
    buf = num;
  } else {
    let hex = num.toString(16);
    if (hex.length % 2) hex = "0" + hex;
    buf = Buffer.from(hex, "hex");
  }
  // Strip redundant leading 0x00 bytes if the next byte does not have MSB set
  let start = 0;
  while (start < buf.length - 1 && buf[start] === 0x00 && !(buf[start + 1] & 0x80)) {
    start++;
  }
  buf = buf.subarray(start);
  if (buf[0] & 0x80) {
    buf = Buffer.concat([Buffer.from([0x00]), buf]);
  }
  return derTag(0x02, buf);
}

function derOid(oidStr: string): Buffer {
  const parts = oidStr.split(".").map(Number);
  const bytes = [40 * parts[0] + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let val = parts[i];
    const octets: number[] = [];
    octets.unshift(val & 0x7f);
    val >>= 7;
    while (val > 0) {
      octets.unshift(0x80 | (val & 0x7f));
      val >>= 7;
    }
    bytes.push(...octets);
  }
  return derTag(0x06, Buffer.from(bytes));
}

function derUtcTime(date: Date): Buffer {
  const pad = (n: number) => String(n).padStart(2, "0");
  const str =
    String(date.getUTCFullYear()).slice(2) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    "Z";
  return derTag(0x17, Buffer.from(str, "ascii"));
}

function derUtf8(str: string): Buffer {
  return derTag(0x0c, Buffer.from(str, "utf8"));
}

function derPrintable(str: string): Buffer {
  return derTag(0x13, Buffer.from(str, "ascii"));
}

function derName(attrs: [string, string, boolean?][]): Buffer {
  return derSeq(
    attrs.map(([oid, val, isPrintable]) =>
      derTag(0x31, derSeq([derOid(oid), isPrintable ? derPrintable(val) : derUtf8(val)]))
    )
  );
}

// Algorithm identifier: sha256WithRSAEncryption = 1.2.840.113549.1.1.11
const SHA256_WITH_RSA = derSeq([derOid("1.2.840.113549.1.1.11"), Buffer.from([0x05, 0x00])]);

// ---------------------------------------------------------------------------
// ShieldDesk Internal Root CA Keypair Management
// ---------------------------------------------------------------------------

let cachedCA: {
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
  caCertificatePem: string;
} | null = null;

export function getOrCreateControlPlaneCA(): {
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
  caCertificatePem: string;
} {
  if (cachedCA) return cachedCA;

  const envCaKey = process.env.CONTROL_PLANE_CA_PRIVATE_KEY;
  const envCaCert = process.env.CONTROL_PLANE_CA_CERTIFICATE;

  if (envCaKey && envCaCert) {
    const priv = crypto.createPrivateKey(envCaKey);
    const pub = crypto.createPublicKey(envCaCert);
    cachedCA = { privateKey: priv, publicKey: pub, caCertificatePem: envCaCert };
    return cachedCA;
  }

  // Generate ephemeral 2048-bit Root CA for dev/test
  const keyPair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const caSpki = keyPair.publicKey.export({ type: "spki", format: "der" });

  const now = new Date();
  const expiresAt = new Date(Date.now() + 365 * 86400 * 1000); // 1-year Root CA
  const serialBuf = crypto.randomBytes(16);

  const caIssuer = derName([
    ["2.5.4.3", "ShieldDesk Root CA", false],
    ["2.5.4.10", "ShieldDesk Control Plane", false],
    ["2.5.4.11", "Security Services", false],
  ]);

  const validity = derSeq([derUtcTime(now), derUtcTime(expiresAt)]);

  const tbs = derSeq([
    derTag(0xa0, derInt(2)), // v3
    derInt(serialBuf),
    SHA256_WITH_RSA,
    caIssuer,
    validity,
    caIssuer, // self-signed
    caSpki,
  ]);

  const signer = crypto.createSign("SHA256");
  signer.update(tbs);
  const sig = signer.sign(keyPair.privateKey);
  const sigBits = derTag(0x03, Buffer.concat([Buffer.from([0x00]), sig]));

  const certDer = derSeq([tbs, SHA256_WITH_RSA, sigBits]);
  const pem =
    "-----BEGIN CERTIFICATE-----\n" +
    certDer.toString("base64").match(/.{1,64}/g)?.join("\n") +
    "\n-----END CERTIFICATE-----\n";

  cachedCA = {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    caCertificatePem: pem,
  };

  return cachedCA;
}

export function getRootCACertificatePem(): string {
  return getOrCreateControlPlaneCA().caCertificatePem;
}

// ---------------------------------------------------------------------------
// SD-008: Endpoint Certificate Issuance Pipeline
// ---------------------------------------------------------------------------

export async function issueEndpointCertificate({
  agentId,
  tenantId,
  clientPublicKeyPem,
  validityDays = 90,
}: {
  agentId: string;
  tenantId: string;
  clientPublicKeyPem?: string;
  validityDays?: number;
}): Promise<{
  certificatePem: string;
  caCertificatePem: string;
  serialNumber: string;
  fingerprintSha256: string;
  expiresAt: string;
  privateKeyPem?: string;
}> {
  const ca = getOrCreateControlPlaneCA();

  let clientPubKey: crypto.KeyObject;
  let generatedPrivateKeyPem: string | undefined;

  if (clientPublicKeyPem) {
    clientPubKey = crypto.createPublicKey(clientPublicKeyPem);
  } else {
    // Generate fresh RSA-2048 keypair on behalf of agent
    const generated = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    clientPubKey = crypto.createPublicKey(generated.publicKey);
    generatedPrivateKeyPem = generated.privateKey;
  }

  const clientSpkiDer = clientPubKey.export({ type: "spki", format: "der" });

  const now = new Date();
  const expiresDate = new Date(Date.now() + validityDays * 86400 * 1000);
  const serialBytes = crypto.randomBytes(16);
  const serialHex = serialBytes.toString("hex").toUpperCase();

  const issuer = derName([
    ["2.5.4.3", "ShieldDesk Root CA", false],
    ["2.5.4.10", "ShieldDesk Control Plane", false],
    ["2.5.4.11", "Security Services", false],
  ]);

  const subject = derName([
    ["2.5.4.3", `agent-${agentId}`, false],
    ["2.5.4.10", "ShieldDesk", false],
    ["2.5.4.11", tenantId, false],
  ]);

  const validity = derSeq([derUtcTime(now), derUtcTime(expiresDate)]);

  const tbs = derSeq([
    derTag(0xa0, derInt(2)), // X.509 v3
    derInt(serialBytes),
    SHA256_WITH_RSA,
    issuer,
    validity,
    subject,
    clientSpkiDer,
  ]);

  const signer = crypto.createSign("SHA256");
  signer.update(tbs);
  const signature = signer.sign(ca.privateKey);
  const sigBits = derTag(0x03, Buffer.concat([Buffer.from([0x00]), signature]));

  const certDer = derSeq([tbs, SHA256_WITH_RSA, sigBits]);
  const certificatePem =
    "-----BEGIN CERTIFICATE-----\n" +
    certDer.toString("base64").match(/.{1,64}/g)?.join("\n") +
    "\n-----END CERTIFICATE-----\n";

  const x509 = new crypto.X509Certificate(certificatePem);
  const fingerprintSha256 = x509.fingerprint256;
  const expiresAt = expiresDate.toISOString();
  const recordId = crypto.randomUUID();

  const record: EndpointCertificateRecord = {
    id: recordId,
    agent_id: agentId,
    tenant_id: tenantId,
    serial_number: serialHex,
    certificate_pem: certificatePem,
    fingerprint_sha256: fingerprintSha256,
    issued_at: now.toISOString(),
    expires_at: expiresAt,
  };

  try {
    await query(
      `INSERT INTO endpoint_certificates (id, agent_id, tenant_id, serial_number, certificate_pem, fingerprint_sha256, issued_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8);`,
      [
        record.id,
        record.agent_id,
        record.tenant_id,
        record.serial_number,
        record.certificate_pem,
        record.fingerprint_sha256,
        record.issued_at,
        record.expires_at,
      ]
    );
  } catch {
    MOCK_ENDPOINT_CERTIFICATES.push(record);
  }

  await recordHashChainEvent({
    tenantId,
    eventType: "ENDPOINT_CERTIFICATE_ISSUED",
    actorId: `agent:${agentId}`,
    payload: {
      certificateId: recordId,
      agentId,
      serialNumber: serialHex,
      fingerprintSha256,
      expiresAt,
    },
  });

  return {
    certificatePem,
    caCertificatePem: ca.caCertificatePem,
    serialNumber: serialHex,
    fingerprintSha256,
    expiresAt,
    privateKeyPem: generatedPrivateKeyPem,
  };
}

// ---------------------------------------------------------------------------
// SD-009: Certificate Rotation & Revocation
// ---------------------------------------------------------------------------

export async function rotateEndpointCertificate({
  agentId,
  tenantId,
  currentSerialNumber,
  newClientPublicKeyPem,
}: {
  agentId: string;
  tenantId: string;
  currentSerialNumber: string;
  newClientPublicKeyPem?: string;
}): Promise<{
  success: boolean;
  newCertificate?: {
    certificatePem: string;
    caCertificatePem: string;
    serialNumber: string;
    fingerprintSha256: string;
    expiresAt: string;
  };
  error?: string;
}> {
  // 1. Verify current certificate is active and not already revoked
  let currentCert: EndpointCertificateRecord | undefined;

  try {
    const res = await query<EndpointCertificateRecord>(
      `SELECT * FROM endpoint_certificates WHERE UPPER(serial_number) = UPPER($1) AND agent_id = $2 AND tenant_id = $3 LIMIT 1;`,
      [currentSerialNumber, agentId, tenantId]
    );
    currentCert = res.rows[0];
  } catch {
    currentCert = MOCK_ENDPOINT_CERTIFICATES.find(
      (c) =>
        (c.serial_number.toUpperCase() === currentSerialNumber.toUpperCase() ||
          c.serial_number.replace(/^0+/, "").toUpperCase() ===
            currentSerialNumber.replace(/^0+/, "").toUpperCase()) &&
        c.agent_id === agentId &&
        c.tenant_id === tenantId
    );
  }

  if (!currentCert) {
    return { success: false, error: "Active certificate not found for rotation" };
  }

  if (currentCert.revoked_at) {
    return { success: false, error: "Cannot rotate an already revoked certificate" };
  }

  // 2. Issue fresh replacement certificate
  const freshCert = await issueEndpointCertificate({
    agentId,
    tenantId,
    clientPublicKeyPem: newClientPublicKeyPem,
    validityDays: 90,
  });

  // 3. Mark old certificate as superseded
  await revokeEndpointCertificate({
    serialNumber: currentSerialNumber,
    reason: `ROTATED_BY_AGENT (Superseded by serial ${freshCert.serialNumber})`,
    revokedBy: `agent:${agentId}`,
  });

  await recordHashChainEvent({
    tenantId,
    eventType: "ENDPOINT_CERTIFICATE_ROTATED",
    actorId: `agent:${agentId}`,
    payload: {
      agentId,
      oldSerialNumber: currentSerialNumber,
      newSerialNumber: freshCert.serialNumber,
      expiresAt: freshCert.expiresAt,
    },
  });

  return {
    success: true,
    newCertificate: freshCert,
  };
}

export async function revokeEndpointCertificate({
  serialNumber,
  reason,
  revokedBy,
}: {
  serialNumber: string;
  reason: string;
  revokedBy: string;
}): Promise<{ success: boolean; error?: string }> {
  const normSerial = serialNumber.trim();
  try {
    const res = await query<EndpointCertificateRecord>(
      `UPDATE endpoint_certificates
       SET revoked_at = now(), revocation_reason = $1
       WHERE UPPER(serial_number) = UPPER($2) AND revoked_at IS NULL
       RETURNING *;`,
      [reason, normSerial]
    );

    if (res.rows.length > 0) {
      const revoked = res.rows[0];
      await recordHashChainEvent({
        tenantId: revoked.tenant_id,
        eventType: "ENDPOINT_CERTIFICATE_REVOKED",
        actorId: revokedBy,
        payload: {
          serialNumber: normSerial,
          reason,
          agentId: revoked.agent_id,
        },
      });

      return { success: true };
    }
  } catch {
    // Database query threw (e.g. no DB configured in test/dev environment) — fall back to memory store below
  }

  // Fallback to in-memory store
  const cert = MOCK_ENDPOINT_CERTIFICATES.find(
    (c) =>
      (c.serial_number.toUpperCase() === normSerial.toUpperCase() ||
        c.serial_number.replace(/^0+/, "").toUpperCase() ===
          normSerial.replace(/^0+/, "").toUpperCase()) &&
      !c.revoked_at
  );

  if (!cert) {
    return { success: false, error: "Certificate not found or already revoked" };
  }

  cert.revoked_at = new Date().toISOString();
  cert.revocation_reason = reason;

  await recordHashChainEvent({
    tenantId: cert.tenant_id,
    eventType: "ENDPOINT_CERTIFICATE_REVOKED",
    actorId: revokedBy,
    payload: {
      serialNumber: normSerial,
      reason,
      agentId: cert.agent_id,
    },
  });

  return { success: true };
}

// ---------------------------------------------------------------------------
// Certificate Verification (mTLS Gateway Guard)
// ---------------------------------------------------------------------------

export async function validateEndpointCertificate({
  certificatePem,
  expectedAgentId,
  expectedTenantId,
}: {
  certificatePem: string;
  expectedAgentId?: string;
  expectedTenantId?: string;
}): Promise<{
  valid: boolean;
  serialNumber?: string;
  agentId?: string;
  tenantId?: string;
  error?: string;
}> {
  try {
    const ca = getOrCreateControlPlaneCA();
    const x509 = new crypto.X509Certificate(certificatePem);

    // 1. Verify cryptographic signature against Root CA
    const verified = x509.verify(ca.publicKey);
    if (!verified) {
      return { valid: false, error: "Certificate signature invalid or not signed by ShieldDesk Root CA" };
    }

    // 2. Check temporal validity window
    const now = Date.now();
    const validFrom = new Date(x509.validFrom).getTime();
    const validTo = new Date(x509.validTo).getTime();

    if (now < validFrom || now > validTo) {
      return { valid: false, error: "Certificate is expired or not yet valid" };
    }

    // 3. Extract Subject attributes (CN=agent-{id}, OU={tenantId})
    const subject = x509.subject;
    const cnMatch = subject.match(/CN=agent-([a-f0-9\-]+)/i);
    const ouMatch = subject.match(/OU=([^,\n]+)/i);

    const agentId = cnMatch ? cnMatch[1] : undefined;
    const tenantId = ouMatch ? ouMatch[1] : undefined;

    if (expectedAgentId && agentId !== expectedAgentId) {
      return { valid: false, error: `Certificate CN does not match expected agent ${expectedAgentId}` };
    }

    if (expectedTenantId && tenantId !== expectedTenantId) {
      return { valid: false, error: `Certificate OU does not match expected tenant ${expectedTenantId}` };
    }

    const serialNumber = x509.serialNumber;

    // 4. Check revocation status in database / memory
    try {
      const res = await query<{ revoked_at: string | null }>(
        `SELECT revoked_at FROM endpoint_certificates WHERE UPPER(serial_number) = UPPER($1) LIMIT 1;`,
        [serialNumber]
      );
      if (res.rows[0]?.revoked_at) {
        return { valid: false, error: "Certificate has been revoked by security policy" };
      }
    } catch {
      const mock = MOCK_ENDPOINT_CERTIFICATES.find(
        (c) =>
          c.serial_number.toUpperCase() === serialNumber.toUpperCase() ||
          c.serial_number.replace(/^0+/, "").toUpperCase() ===
            serialNumber.replace(/^0+/, "").toUpperCase()
      );
      if (mock?.revoked_at) {
        return { valid: false, error: "Certificate has been revoked by security policy" };
      }
    }

    return {
      valid: true,
      serialNumber,
      agentId,
      tenantId,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Malformed certificate";
    return { valid: false, error: msg };
  }
}

export async function getEndpointCertificateByAgent(
  agentId: string,
  tenantId?: string
): Promise<(EndpointCertificateRecord & { public_key?: string }) | undefined> {
  let cert: EndpointCertificateRecord | undefined;
  try {
    const res = await query<EndpointCertificateRecord>(
      `SELECT * FROM endpoint_certificates 
       WHERE agent_id = $1 
         AND revoked_at IS NULL 
         ${tenantId ? "AND tenant_id = $2" : ""}
       ORDER BY issued_at DESC 
       LIMIT 1;`,
      tenantId ? [agentId, tenantId] : [agentId]
    );
    cert = res.rows[0];
  } catch {
    cert = MOCK_ENDPOINT_CERTIFICATES.slice().reverse().find(
      (c) => c.agent_id === agentId && (!tenantId || c.tenant_id === tenantId) && !c.revoked_at
    );
  }

  if (!cert) return undefined;

  let public_key: string | undefined;
  try {
    const x509 = new crypto.X509Certificate(cert.certificate_pem);
    public_key = x509.publicKey.export({ type: "spki", format: "pem" }).toString();
  } catch {
    // fallback if raw pem cannot be parsed
  }

  return { ...cert, public_key };
}
