import crypto from "crypto";
import fs from "fs";
import path from "path";

declare global {
  // eslint-disable-next-line no-var
  var __shieldDeskControlPlanePrivateKey: string | undefined;
  // eslint-disable-next-line no-var
  var __shieldDeskControlPlanePublicKey: string | undefined;
}

const CANDIDATE_KEY_PATHS = [
  path.join(process.cwd(), "control-plane-key.pem"),
  path.join(process.cwd(), ".control-plane-dev-key.pem"),
];

const CANDIDATE_PUB_PATHS = [
  path.join(process.cwd(), "control-plane-pub.pem"),
  path.join(process.cwd(), ".control-plane-dev-pub.pem"),
];

function getFallbackKeys(): { privateKey: string; publicKey: string } {
  if (global.__shieldDeskControlPlanePrivateKey && global.__shieldDeskControlPlanePublicKey) {
    return {
      privateKey: global.__shieldDeskControlPlanePrivateKey,
      publicKey: global.__shieldDeskControlPlanePublicKey,
    };
  }

  // Load from disk if present
  for (let i = 0; i < CANDIDATE_KEY_PATHS.length; i++) {
    try {
      const kPath = CANDIDATE_KEY_PATHS[i];
      const pPath = CANDIDATE_PUB_PATHS[i];
      if (fs.existsSync(kPath) && fs.existsSync(pPath)) {
        const priv = fs.readFileSync(kPath, "utf8");
        const pub = fs.readFileSync(pPath, "utf8");
        if (priv && pub && priv.includes("BEGIN") && pub.includes("BEGIN")) {
          global.__shieldDeskControlPlanePrivateKey = priv;
          global.__shieldDeskControlPlanePublicKey = pub;
          return { privateKey: priv, publicKey: pub };
        }
      }
    } catch {}
  }

  // Fallback generation if no disk keys exist
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  global.__shieldDeskControlPlanePrivateKey = privateKey;
  global.__shieldDeskControlPlanePublicKey = publicKey;

  try {
    fs.writeFileSync(CANDIDATE_KEY_PATHS[0], privateKey, "utf8");
    fs.writeFileSync(CANDIDATE_PUB_PATHS[0], publicKey, "utf8");
  } catch {}

  return { privateKey, publicKey };
}

/**
 * Produces a deterministic canonical payload string to avoid JSON serialization
 * or whitespace discrepancies between Node.js and Go.
 */
export function formatCanonicalCommandPayload(
  agentId: string,
  command: string,
  nonce: string,
  tier: string
): string {
  return `${agentId}|${command}|${nonce}|${tier}`;
}

/**
 * Cryptographically signs a command payload using RSA-SHA256.
 */
export function signCommand(payload: {
  agentId: string;
  command: string;
  nonce: string;
  tier: string;
}): string {
  const canonical = formatCanonicalCommandPayload(
    payload.agentId,
    payload.command,
    payload.nonce,
    payload.tier
  );

  const privateKey = process.env.CONTROL_PLANE_PRIVATE_KEY || getFallbackKeys().privateKey;

  const signer = crypto.createSign("RSA-SHA256");
  signer.update(canonical, "utf8");
  return signer.sign(privateKey, "base64");
}

/**
 * Cryptographically verifies an agent command signature using RSA-SHA256.
 */
export function verifyCommandSignature(payload: {
  agentId: string;
  command: string;
  nonce: string;
  tier: string;
  signature: string;
}): boolean {
  try {
    const canonical = formatCanonicalCommandPayload(
      payload.agentId,
      payload.command,
      payload.nonce,
      payload.tier
    );

    const publicKey = process.env.CONTROL_PLANE_PUBLIC_KEY || getFallbackKeys().publicKey;

    const verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(canonical, "utf8");
    return verifier.verify(publicKey, payload.signature, "base64");
  } catch {
    return false;
  }
}

/**
 * Returns the public key (PEM format) used to verify commands.
 */
export function getControlPlanePublicKey(): string {
  return process.env.CONTROL_PLANE_PUBLIC_KEY || getFallbackKeys().publicKey;
}

/**
 * Cryptographically signs arbitrary string data using the control plane RSA private key.
 */
export function signControlPlaneData(data: string): string {
  const privateKey = process.env.CONTROL_PLANE_PRIVATE_KEY || getFallbackKeys().privateKey;
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(data, "utf8");
  return signer.sign(privateKey, "base64");
}

/**
 * Cryptographically verifies arbitrary string data signature using the control plane RSA public key.
 */
export function verifyControlPlaneData(data: string, signature: string): boolean {
  try {
    const publicKey = getControlPlanePublicKey();
    const verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(data, "utf8");
    return verifier.verify(publicKey, signature, "base64");
  } catch {
    return false;
  }
}

