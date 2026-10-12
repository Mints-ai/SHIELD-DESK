import "server-only";
import crypto from "node:crypto";

export interface IngestAuthResult {
  authenticated: boolean;
  tenantId?: string;
  errorStatus?: number;
  error?: string;
}

/**
 * Resolves and validates the authenticated tenant from the supplied API key.
 * Enforces fail-closed authentication, constant-time comparison, and multi-tenant key binding (S6).
 */
export function authenticateIngestKey(apiKeyHeader: string | null): IngestAuthResult {
  const configuredSingleKey = process.env.SHIELDDESK_INGEST_API_KEY;
  const configuredMultiKeysJson = process.env.SHIELDDESK_INGEST_API_KEYS;

  // Fail closed if no ingestion keys are configured on the server
  if (!configuredSingleKey && !configuredMultiKeysJson) {
    return {
      authenticated: false,
      errorStatus: 503,
      error: "Service Unavailable: Ingestion API key is not configured on this server.",
    };
  }

  if (!apiKeyHeader) {
    return {
      authenticated: false,
      errorStatus: 401,
      error: "Unauthorized: Missing API Key.",
    };
  }

  const rawKey = apiKeyHeader.replace(/^Bearer\s+/i, "").trim();
  const rawKeyBuf = Buffer.from(rawKey, "utf8");

  // 1. Check multi-tenant key mapping (API Key -> Tenant ID)
  if (configuredMultiKeysJson) {
    try {
      const keyMap: Record<string, string> = JSON.parse(configuredMultiKeysJson);
      for (const [validKey, boundTenant] of Object.entries(keyMap)) {
        const validKeyBuf = Buffer.from(validKey, "utf8");
        if (
          rawKeyBuf.length === validKeyBuf.length &&
          crypto.timingSafeEqual(rawKeyBuf, validKeyBuf)
        ) {
          return { authenticated: true, tenantId: boundTenant };
        }
      }
    } catch {
      console.error("[Ingest] Invalid JSON in SHIELDDESK_INGEST_API_KEYS configuration.");
    }
  }

  // 2. Check primary single key
  if (configuredSingleKey) {
    const configuredKeyBuf = Buffer.from(configuredSingleKey, "utf8");
    if (
      rawKeyBuf.length === configuredKeyBuf.length &&
      crypto.timingSafeEqual(rawKeyBuf, configuredKeyBuf)
    ) {
      // Single key bound to default tenant or configured tenant
      const defaultTenant = process.env.SHIELDDESK_INGEST_TENANT || "acme-tenant";
      return { authenticated: true, tenantId: defaultTenant };
    }
  }

  return {
    authenticated: false,
    errorStatus: 401,
    error: "Unauthorized: Invalid API Key.",
  };
}
