import "server-only";
import crypto from "node:crypto";
import type { ShieldDeskRole } from "@/lib/permissions";

export interface SessionPayload {
  uid: string;
  tenantId: string;
  role: ShieldDeskRole;
  exp: number; // Unix timestamp in seconds
  iat: number; // Unix timestamp in seconds
}

function getSessionSecret(): Buffer {
  const secret = process.env.SHIELDDESK_SESSION_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === "production") {
      throw new Error(
        "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_SESSION_SECRET must be configured in production environments."
      );
    }
    // Deterministic dev-fallback secret for non-production environments
    return Buffer.from("shielddesk-dev-insecure-session-secret-min32bytes!", "utf8");
  }
  return Buffer.from(secret, "utf8");
}

function base64UrlEncode(data: string | Buffer): string {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  return buf.toString("base64url");
}

function base64UrlDecode(str: string): string {
  return Buffer.from(str, "base64url").toString("utf8");
}

/**
 * Creates a cryptographically signed HMAC-SHA256 session token.
 * Format: <base64url(payload)>.<base64url(signature)>
 */
export function createSessionToken(
  user: { uid: string; tenantId: string; role: ShieldDeskRole },
  ttlSeconds = 7 * 86400
): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: SessionPayload = {
    uid: user.uid,
    tenantId: user.tenantId,
    role: user.role,
    iat: now,
    exp: now + ttlSeconds,
  };

  const secret = getSessionSecret();
  const serialized = JSON.stringify(payload);
  const encodedPayload = base64UrlEncode(serialized);

  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(encodedPayload);
  const signature = base64UrlEncode(hmac.digest());

  return `${encodedPayload}.${signature}`;
}

/**
 * Verifies a signed session token.
 * Enforces cryptographic authenticity, timing-safe equality, and expiration checks.
 */
export function verifySessionToken(token: string): SessionPayload | null {
  if (!token || typeof token !== "string") return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [encodedPayload, receivedSig] = parts;
  if (!encodedPayload || !receivedSig) return null;

  try {
    const secret = getSessionSecret();
    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(encodedPayload);
    const expectedSig = base64UrlEncode(hmac.digest());

    const receivedSigBuf = Buffer.from(receivedSig);
    const expectedSigBuf = Buffer.from(expectedSig);

    if (
      receivedSigBuf.length !== expectedSigBuf.length ||
      !crypto.timingSafeEqual(receivedSigBuf, expectedSigBuf)
    ) {
      return null;
    }

    const payloadJson = base64UrlDecode(encodedPayload);
    const payload: SessionPayload = JSON.parse(payloadJson);

    const now = Math.floor(Date.now() / 1000);
    if (!payload.exp || now > payload.exp) {
      return null; // Expired token
    }

    if (!payload.uid || !payload.tenantId || !payload.role) {
      return null; // Incomplete payload
    }

    return payload;
  } catch {
    return null;
  }
}
