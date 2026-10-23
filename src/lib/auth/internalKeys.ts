import "server-only";
import crypto from "node:crypto";
import type { ShieldDeskRole } from "@/lib/permissions";
import { isProduction } from "@/lib/config/environment";

/**
 * Insecure development default secret strings that must NEVER be accepted in production.
 */
export const INSECURE_DEV_DEFAULTS = new Set([
  "sd_internal_dev_secret_key_8000",
  "secret",
  "password",
  "admin",
  "12345678",
  "changeme",
  "sd_test_internal_key_min_32_characters_long_entropy_secure!",
  "",
]);

let cachedInternalKey: string | null = null;
let cachedAssertionSecret: string | null = null;

/**
 * Retrieves and validates the service-to-service internal authentication key.
 * Fails closed in production if missing, weak (< 32 chars), or matching known defaults.
 */
export function getInternalServiceKey(): string {
  if (cachedInternalKey) return cachedInternalKey;

  const key = (process.env.SHIELDDESK_INTERNAL_KEY || "").trim();
  const isProd = isProduction() || process.env.NODE_ENV === "production";

  if (isProd) {
    if (!key) {
      throw new Error(
        "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_INTERNAL_KEY must be configured in production."
      );
    }
    if (INSECURE_DEV_DEFAULTS.has(key)) {
      throw new Error(
        "CRITICAL SECURITY CONFIGURATION ERROR: Insecure default SHIELDDESK_INTERNAL_KEY detected in production. Refusing to run."
      );
    }
    if (key.length < 32) {
      throw new Error(
        "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_INTERNAL_KEY is too weak (minimum 32 characters required in production)."
      );
    }
    cachedInternalKey = key;
    return key;
  }

  // Development / Test: require explicit key or generate unique ephemeral key per process
  if (!key) {
    cachedInternalKey = crypto.randomBytes(32).toString("hex");
    return cachedInternalKey;
  }

  cachedInternalKey = key;
  return key;
}

/**
 * Retrieves and validates the cryptographic signing secret for administrator identity assertions.
 * Cryptographically isolated from the internal service authentication key.
 * Fails closed in production if missing, weak (< 32 chars), matching known defaults,
 * or identical to SHIELDDESK_INTERNAL_KEY or SHIELDDESK_SESSION_SECRET.
 */
export function getAdminAssertionSecret(): string {
  if (cachedAssertionSecret) return cachedAssertionSecret;

  const sec = (process.env.SHIELDDESK_ADMIN_ASSERTION_SECRET || "").trim();
  const isProd = isProduction() || process.env.NODE_ENV === "production";

  if (isProd) {
    if (!sec) {
      throw new Error(
        "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_ADMIN_ASSERTION_SECRET must be configured in production."
      );
    }
    if (INSECURE_DEV_DEFAULTS.has(sec)) {
      throw new Error(
        "CRITICAL SECURITY CONFIGURATION ERROR: Insecure default SHIELDDESK_ADMIN_ASSERTION_SECRET detected in production. Refusing to run."
      );
    }
    if (sec.length < 32) {
      throw new Error(
        "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_ADMIN_ASSERTION_SECRET is too weak (minimum 32 characters required in production)."
      );
    }

    const internalKey = (process.env.SHIELDDESK_INTERNAL_KEY || "").trim();
    if (sec === internalKey) {
      throw new Error(
        "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_ADMIN_ASSERTION_SECRET must not be identical to SHIELDDESK_INTERNAL_KEY. Separate keys are required."
      );
    }

    const sessionSec = (process.env.SHIELDDESK_SESSION_SECRET || "").trim();
    if (sessionSec && sec === sessionSec) {
      throw new Error(
        "CRITICAL SECURITY CONFIGURATION ERROR: SHIELDDESK_ADMIN_ASSERTION_SECRET must not be identical to SHIELDDESK_SESSION_SECRET. Dedicated keys are required."
      );
    }

    cachedAssertionSecret = sec;
    return sec;
  }

  // Non-production: fallback to session secret (if >= 32 and safe) or unique ephemeral key
  if (!sec) {
    const sessionSecret = (process.env.SHIELDDESK_SESSION_SECRET || "").trim();
    if (sessionSecret && sessionSecret.length >= 32 && !INSECURE_DEV_DEFAULTS.has(sessionSecret)) {
      cachedAssertionSecret = sessionSecret;
      return cachedAssertionSecret;
    }
    cachedAssertionSecret = crypto.randomBytes(32).toString("hex");
    return cachedAssertionSecret;
  }

  cachedAssertionSecret = sec;
  return sec;
}

/**
 * Allows test fixtures to re-evaluate environment configuration and reset state.
 */
export function resetCachedKeysForTesting(): void {
  cachedInternalKey = null;
  cachedAssertionSecret = null;
}

export interface AdminAssertionParams {
  operatorId: string;
  role: ShieldDeskRole;
  operation: string;
  targetId?: string;
  ttlSeconds?: number;
  nonce?: string;
  secret?: string;
}

/**
 * Creates a cryptographically signed HMAC-SHA256 administrator assertion token.
 * Uses SHIELDDESK_ADMIN_ASSERTION_SECRET by default (cryptographically separate from internal service key).
 * Binds operator ID, role, operation, candidate target, and nonce with short TTL (default 300s).
 */
export function createAdminAssertionToken(params: AdminAssertionParams): string {
  if (params.role !== "system_admin" && params.role !== "super_admin") {
    throw new Error(`Unauthorized role for administrative assertion: ${params.role}`);
  }

  const sec = params.secret || getAdminAssertionSecret();
  const now = Math.floor(Date.now() / 1000);
  const ttl = params.ttlSeconds ?? 300;
  const payload = {
    operator_id: params.operatorId,
    role: params.role,
    operation: params.operation,
    target_id: params.targetId,
    nonce: params.nonce || crypto.randomUUID(),
    iat: now,
    exp: now + ttl,
  };

  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", sec).update(encodedPayload).digest("base64url");
  return `${encodedPayload}.${signature}`;
}
