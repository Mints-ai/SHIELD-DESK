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

// Cache an ephemeral key for the lifetime of the dev process if no secret configured
let ephemeralDevSecret: Buffer | null = null;

function getSessionSecret(): Buffer {
  const secret = process.env.SHIELDDESK_SESSION_SECRET;
  if (!secret) {
    if (process.env.NODE_ENV === "production") {
      throw new Error(
        "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_SESSION_SECRET must be configured in production environments."
      );
    }
    if (!ephemeralDevSecret) {
      ephemeralDevSecret = crypto.randomBytes(32);
    }
    return ephemeralDevSecret;
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
  user: { uid: string; tenantId: string; role: ShieldDeskRole; email?: string },
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

/**
 * Creates a short-lived access token (default: 15 minutes / 900 seconds)
 * as mandated by Section 16 of the Master Prompt.
 */
export function createAccessToken(
  user: { uid: string; tenantId: string; role: ShieldDeskRole; email?: string },
  ttlSeconds = 15 * 60
): string {
  return createSessionToken(user, ttlSeconds);
}

export interface RefreshTokenPayload {
  uid: string;
  tenantId: string;
  role: ShieldDeskRole;
  familyId: string;
  tokenId: string;
  type: "refresh";
  exp: number;
  iat: number;
}

// In-memory revocation registers (persisted or mirrored in Redis/DB in cluster deployments)
export const REVOKED_REFRESH_FAMILIES = new Set<string>();
export const CONSUMED_REFRESH_TOKENS = new Set<string>();

/**
 * Creates a long-lived refresh token (default: 30 days) bound to a rotation family.
 */
export function createRefreshToken(
  user: { uid: string; tenantId: string; role: ShieldDeskRole },
  familyId?: string,
  ttlSeconds = 30 * 86400
): { token: string; familyId: string; tokenId: string } {
  const now = Math.floor(Date.now() / 1000);
  const resolvedFamilyId = familyId || crypto.randomUUID();
  const tokenId = crypto.randomUUID();

  const payload: RefreshTokenPayload = {
    uid: user.uid,
    tenantId: user.tenantId,
    role: user.role,
    familyId: resolvedFamilyId,
    tokenId,
    type: "refresh",
    iat: now,
    exp: now + ttlSeconds,
  };

  const secret = getSessionSecret();
  const serialized = JSON.stringify(payload);
  const encodedPayload = base64UrlEncode(serialized);

  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(encodedPayload);
  const signature = base64UrlEncode(hmac.digest());

  return {
    token: `${encodedPayload}.${signature}`,
    familyId: resolvedFamilyId,
    tokenId,
  };
}

/**
 * Verifies a refresh token format, cryptographic authenticity, and freshness.
 */
export function verifyRefreshToken(token: string): RefreshTokenPayload | null {
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
    const payload: RefreshTokenPayload = JSON.parse(payloadJson);

    if (payload.type !== "refresh") return null;

    const now = Math.floor(Date.now() / 1000);
    if (!payload.exp || now > payload.exp) return null;

    if (REVOKED_REFRESH_FAMILIES.has(payload.familyId)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

/**
 * Rotates a refresh token:
 * - Detects token reuse (if an already-consumed token is presented, the entire family is revoked).
 * - Issues a new 15-minute access token and a fresh refresh token in the same family.
 */
export function rotateRefreshToken(token: string): {
  accessToken: string;
  refreshToken: string;
} | null {
  const payload = verifyRefreshToken(token);
  if (!payload) return null;

  // Replay Attack Detection: If token was already consumed, revoke the entire token family!
  if (CONSUMED_REFRESH_TOKENS.has(payload.tokenId)) {
    REVOKED_REFRESH_FAMILIES.add(payload.familyId);
    return null;
  }

  // Mark token as consumed
  CONSUMED_REFRESH_TOKENS.add(payload.tokenId);

  // Issue new access token (15 minutes)
  const accessToken = createAccessToken({
    uid: payload.uid,
    tenantId: payload.tenantId,
    role: payload.role,
  });

  // Issue next refresh token in the same family
  const nextRefresh = createRefreshToken(
    {
      uid: payload.uid,
      tenantId: payload.tenantId,
      role: payload.role,
    },
    payload.familyId
  );

  return {
    accessToken,
    refreshToken: nextRefresh.token,
  };
}

/**
 * Revokes an entire token family (e.g., on logout or password reset).
 */
export function revokeRefreshFamily(familyId: string): void {
  REVOKED_REFRESH_FAMILIES.add(familyId);
}
