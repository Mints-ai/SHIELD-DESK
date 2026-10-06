import "server-only";
import crypto from "node:crypto";
import type { Permission } from "@/lib/permissions";

export interface ApiKeyRecord {
  id: string;
  tenant_id: string;
  name: string;
  prefix: string; // e.g. "sdk_live" or "sdk_test"
  key_hash: string; // SHA-256 hex
  scopes: Permission[];
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
}

export interface GeneratedApiKey {
  rawKey: string;
  keyRecord: ApiKeyRecord;
}

// In-memory key store for dev/testing when PostgreSQL is offline
export const MOCK_API_KEYS: ApiKeyRecord[] = [];

/**
 * Computes a SHA-256 hash of an API key for safe storage.
 */
export function hashApiKey(rawKey: string): string {
  return crypto.createHash("sha256").update(rawKey).digest("hex");
}

/**
 * Generates a new API key with prefix identification and stores its SHA-256 hash.
 * The raw key is returned ONLY upon generation and must be copied by the user.
 */
export function generateApiKey(params: {
  tenantId: string;
  name: string;
  scopes: Permission[];
  mode?: "live" | "test";
  expiresInDays?: number;
}): GeneratedApiKey {
  const prefix = params.mode === "test" ? "sdk_test" : "sdk_live";
  const entropy = crypto.randomBytes(24).toString("base64url");
  const rawKey = `${prefix}_${entropy}`;
  const keyHash = hashApiKey(rawKey);

  const now = new Date();
  const expiresAt = params.expiresInDays
    ? new Date(now.getTime() + params.expiresInDays * 86400 * 1000).toISOString()
    : null;

  const keyRecord: ApiKeyRecord = {
    id: `key_${crypto.randomUUID()}`,
    tenant_id: params.tenantId,
    name: params.name,
    prefix,
    key_hash: keyHash,
    scopes: params.scopes,
    created_at: now.toISOString(),
    expires_at: expiresAt,
    revoked_at: null,
    last_used_at: null,
  };

  MOCK_API_KEYS.push(keyRecord);

  return {
    rawKey,
    keyRecord,
  };
}

/**
 * Verifies an incoming API key against stored hashed records and scopes.
 */
export function verifyApiKey(
  rawKey: string,
  requiredScope?: Permission
): { valid: boolean; tenantId?: string; keyRecord?: ApiKeyRecord; reason?: string } {
  if (!rawKey || typeof rawKey !== "string") {
    return { valid: false, reason: "Missing API key." };
  }

  if (!rawKey.startsWith("sdk_live_") && !rawKey.startsWith("sdk_test_")) {
    return { valid: false, reason: "Invalid API key prefix. Must begin with sdk_live_ or sdk_test_." };
  }

  const computedHash = hashApiKey(rawKey);
  const record = MOCK_API_KEYS.find((k) => k.key_hash === computedHash);

  if (!record) {
    return { valid: false, reason: "API key not found or invalid." };
  }

  if (record.revoked_at) {
    return { valid: false, reason: "API key has been revoked." };
  }

  if (record.expires_at && new Date(record.expires_at).getTime() < Date.now()) {
    return { valid: false, reason: "API key has expired." };
  }

  if (requiredScope && !record.scopes.includes(requiredScope)) {
    return {
      valid: false,
      tenantId: record.tenant_id,
      reason: `Insufficient API key scope. Required: ${requiredScope}.`,
    };
  }

  record.last_used_at = new Date().toISOString();

  return {
    valid: true,
    tenantId: record.tenant_id,
    keyRecord: record,
  };
}

/**
 * Revokes an API key by ID.
 */
export function revokeApiKey(keyId: string, tenantId: string): boolean {
  const record = MOCK_API_KEYS.find((k) => k.id === keyId && k.tenant_id === tenantId);
  if (!record) return false;
  record.revoked_at = new Date().toISOString();
  return true;
}
