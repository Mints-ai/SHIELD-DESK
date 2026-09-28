import crypto from "crypto";

// Fallback in-memory RSA keypair for development and test execution
let fallbackPrivateKey: string | null = null;
let fallbackPublicKey: string | null = null;

function getFallbackKeys(): { privateKey: string; publicKey: string } {
  if (!fallbackPrivateKey || !fallbackPublicKey) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    fallbackPrivateKey = privateKey;
    fallbackPublicKey = publicKey;
  }
  return { privateKey: fallbackPrivateKey, publicKey: fallbackPublicKey };
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
