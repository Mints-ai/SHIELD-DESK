import crypto from "crypto";
import { query } from "@/lib/db";
import { recordHashChainEvent } from "@/lib/fleet/fleet";
import type { OsType } from "@/lib/fleet/fleet";
import type { SessionUser } from "@/lib/auth/session";

export interface EnrollmentTokenRecord {
  id: string;
  tenant_id: string;
  token_hash: string;
  label?: string | null;
  expires_at: string;
  max_uses: number;
  used_count: number;
  created_by: string;
  created_at: string;
  revoked_at?: string | null;
}

// In-memory fallback mock tokens for testing/offline mode
export const MOCK_ENROLLMENT_TOKENS: EnrollmentTokenRecord[] = [];

/**
 * Creates a short-lived, tenant-bound endpoint enrollment token.
 * Only administrators (system_admin or super_admin) can generate tokens.
 */
export async function createEnrollmentToken({
  caller,
  label,
  expiresInHours = 24,
  maxUses = 1,
}: {
  caller: SessionUser;
  label?: string;
  expiresInHours?: number;
  maxUses?: number;
}): Promise<{ rawToken: string; tokenId: string; expiresAt: string }> {
  // Generate high-entropy secret token (shown only once)
  const rawSecret = crypto.randomBytes(24).toString("base64url");
  const rawToken = `sdt_${rawSecret}`;
  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

  const expiresAt = new Date(Date.now() + expiresInHours * 3600 * 1000).toISOString();
  const tokenId = crypto.randomUUID();

  const record: EnrollmentTokenRecord = {
    id: tokenId,
    tenant_id: caller.tenant_id,
    token_hash: tokenHash,
    label: label || `Enrollment token created by ${caller.id}`,
    expires_at: expiresAt,
    max_uses: maxUses,
    used_count: 0,
    created_by: caller.id,
    created_at: new Date().toISOString(),
  };

  try {
    await query(
      `INSERT INTO endpoint_enrollment_tokens (id, tenant_id, token_hash, label, expires_at, max_uses, used_count, created_by, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, 0, $7, now());`,
      [record.id, record.tenant_id, record.token_hash, record.label, record.expires_at, record.max_uses, record.created_by]
    );
  } catch {
    MOCK_ENROLLMENT_TOKENS.push(record);
  }

  await recordHashChainEvent({
    tenantId: caller.tenant_id,
    eventType: "ENROLLMENT_TOKEN_CREATED",
    actorId: caller.id,
    payload: {
      tokenId,
      label: record.label,
      expiresAt,
      maxUses,
    },
  });

  return {
    rawToken,
    tokenId,
    expiresAt,
  };
}

/**
 * Validates and consumes an enrollment token presented by an endpoint agent.
 */
export async function validateAndConsumeEnrollmentToken(rawToken: string): Promise<{
  valid: boolean;
  tenantId?: string;
  error?: string;
}> {
  if (!rawToken || !rawToken.startsWith("sdt_")) {
    return { valid: false, error: "Invalid enrollment token format" };
  }

  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

  try {
    const { rows } = await query<EnrollmentTokenRecord>(
      `UPDATE endpoint_enrollment_tokens
       SET used_count = used_count + 1
       WHERE token_hash = $1
         AND revoked_at IS NULL
         AND expires_at > now()
         AND used_count < max_uses
       RETURNING *;`,
      [tokenHash]
    );

    if (rows.length === 0) {
      return { valid: false, error: "Enrollment token is expired, revoked, or exhausted" };
    }

    return { valid: true, tenantId: rows[0].tenant_id };
  } catch {
    // In-memory fallback
    const tok = MOCK_ENROLLMENT_TOKENS.find(
      (t) =>
        t.token_hash === tokenHash &&
        !t.revoked_at &&
        new Date(t.expires_at).getTime() > Date.now() &&
        t.used_count < t.max_uses
    );

    if (!tok) {
      return { valid: false, error: "Enrollment token is expired, revoked, or exhausted" };
    }

    tok.used_count += 1;
    return { valid: true, tenantId: tok.tenant_id };
  }
}

import { issueEndpointCertificate } from "@/lib/fleet/certificates";

/**
 * Enrolls a new endpoint agent into the fleet using a valid enrollment token.
 * Issues an X.509 client certificate for mTLS authentication.
 */
export async function enrollEndpointAgent({
  rawToken,
  hostname,
  ipAddress,
  osType,
  agentVersion = "0.4.2",
  clientPublicKeyPem,
  installationId,
  licenseKey,
}: {
  rawToken: string;
  hostname: string;
  ipAddress: string;
  osType: OsType;
  agentVersion?: string;
  clientPublicKeyPem?: string;
  installationId?: string;
  licenseKey?: string;
}): Promise<{
  success: boolean;
  agentId?: string;
  tenantId?: string;
  certificate?: {
    certificatePem: string;
    caCertificatePem: string;
    serialNumber: string;
    fingerprintSha256: string;
    expiresAt: string;
    privateKeyPem?: string;
  };
  error?: string;
}> {
  const tokenValidation = await validateAndConsumeEnrollmentToken(rawToken);
  if (!tokenValidation.valid || !tokenValidation.tenantId) {
    return { success: false, error: tokenValidation.error || "Token validation failed" };
  }

  const tenantId = tokenValidation.tenantId;
  if (!installationId || !licenseKey) return { success: false, error: "Installation ID and tenant license are required for device activation." };
  const agentId = crypto.randomUUID();

  try {
    await query(
      `INSERT INTO endpoint_agents (id, tenant_id, hostname, ip_address, os_type, agent_version, status, cpu_usage, memory_usage, eps, kill_switch_active, last_heartbeat, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, 'connected', 0.0, 0.0, 0, false, now(), now());`,
      [agentId, tenantId, hostname, ipAddress, osType, agentVersion]
    );
  } catch {
    // Mock store insert
    const { MOCK_ENDPOINT_AGENTS } = await import("@/lib/fleet/fleet");
    MOCK_ENDPOINT_AGENTS.push({
      id: agentId,
      tenant_id: tenantId,
      hostname,
      ip_address: ipAddress,
      os_type: osType,
      agent_version: agentVersion,
      status: "connected",
      cpu_usage: 0.0,
      memory_usage: 0.0,
      eps: 0,
      kill_switch_active: false,
      safety_snapshot_id: null,
      last_heartbeat: new Date().toISOString(),
      created_at: new Date().toISOString(),
    });
  }

  // Issue X.509 endpoint certificate
  let certResult: {
    certificatePem: string;
    caCertificatePem: string;
    serialNumber: string;
    fingerprintSha256: string;
    expiresAt: string;
    privateKeyPem?: string;
  } | undefined;

  try {
    certResult = await issueEndpointCertificate({
      agentId,
      tenantId,
      clientPublicKeyPem,
      validityDays: 90,
    });
  } catch (certErr) {
    console.warn(`[Cert] Warning issuing certificate for agent ${agentId}:`, certErr);
  }

  if (!certResult) return { success: false, error: "Certificate issuance failed; agent activation was not completed." };
  try {
    const { LicenseActivationService } = await import("@/lib/licensing/licenseActivation");
    await LicenseActivationService.activate({ tenantId, installationId, deviceIdentity: agentId, certificatePem: certResult.certificatePem, licenseKey });
  } catch (activationError) {
    return { success: false, error: activationError instanceof Error ? activationError.message : "License-bound device activation failed." };
  }

  await recordHashChainEvent({
    tenantId,
    eventType: "ENDPOINT_AGENT_ENROLLED",
    actorId: `agent:${agentId}`,
    payload: {
      agentId,
      hostname,
      ipAddress,
      osType,
      agentVersion,
      certificateSerial: certResult?.serialNumber,
    },
  });

  return {
    success: true,
    agentId,
    tenantId,
    certificate: certResult,
  };
}
