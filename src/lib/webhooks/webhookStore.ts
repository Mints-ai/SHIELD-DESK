import { query } from "@/lib/db";
import { shouldFailClosed } from "@/lib/config/environment";
import crypto from "crypto";

export interface TenantWebhookEndpoint {
  id: string;
  tenant_id: string;
  name: string;
  type: "discord" | "slack" | "teams" | "generic";
  destination: string;
  secret_key?: string | null;
  events: string[];
  min_severity: "low" | "medium" | "high" | "critical";
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface WebhookDeliveryLog {
  id: string;
  delivery_id: string;
  tenant_id: string;
  endpoint_id: string;
  endpoint_name?: string;
  event_type: string;
  severity?: string;
  status_code?: number;
  latency_ms?: number;
  payload?: Record<string, unknown>;
  response_body?: string;
  success: boolean;
  created_at: string;
}

// In-memory fallback stores for offline dev / test environments
const inMemoryEndpoints = new Map<string, TenantWebhookEndpoint>();
const inMemoryDeliveryLogs: WebhookDeliveryLog[] = [];

/**
 * Validate webhook destination URL to prevent SSRF (Server-Side Request Forgery).
 */
export function validateWebhookUrl(urlStr: string): { valid: boolean; reason?: string } {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { valid: false, reason: "Destination must use http or https protocol" };
    }

    const hostname = parsed.hostname.toLowerCase();
    if (!hostname) {
      return { valid: false, reason: "Destination URL missing hostname" };
    }

    const isDevOrTest = process.env.NODE_ENV !== "production" && process.env.APP_ENV !== "production";

    // Block cloud metadata addresses regardless of environment
    if (
      hostname === "169.254.169.254" ||
      hostname.startsWith("169.254.") ||
      hostname === "metadata.google.internal" ||
      hostname === "fd00:ec2::254"
    ) {
      return { valid: false, reason: "SSRF blocked: Cloud metadata service destination is forbidden" };
    }

    // In production, block private/loopback addresses
    if (!isDevOrTest) {
      if (
        hostname === "localhost" ||
        hostname === "127.0.0.1" ||
        hostname === "::1" ||
        hostname.startsWith("10.") ||
        hostname.startsWith("192.168.") ||
        (hostname.startsWith("172.") &&
          parseInt(hostname.split(".")[1] || "0", 10) >= 16 &&
          parseInt(hostname.split(".")[1] || "0", 10) <= 31)
      ) {
        return { valid: false, reason: "SSRF blocked: Private loopback or RFC1918 internal addresses are forbidden in production" };
      }

      if (parsed.protocol !== "https:") {
        return { valid: false, reason: "Insecure plaintext HTTP is forbidden for external webhooks in production" };
      }
    }

    return { valid: true };
  } catch {
    return { valid: false, reason: "Invalid destination URL format" };
  }
}

/**
 * Retrieve all configured webhook endpoints for a tenant.
 */
export async function getTenantWebhookEndpoints(tenantId: string): Promise<TenantWebhookEndpoint[]> {
  try {
    const res = await query<TenantWebhookEndpoint>(
      `SELECT id, tenant_id, name, type, destination, secret_key, events, min_severity, enabled, created_at, updated_at
       FROM tenant_webhook_endpoints
       WHERE tenant_id = $1
       ORDER BY created_at DESC`,
      [tenantId]
    );
    return res.rows;
  } catch (err) {
    if (shouldFailClosed()) {
      throw new Error(`Database error retrieving webhook endpoints: ${err instanceof Error ? err.message : "DB error"}`);
    }
    // In-memory fallback
    return Array.from(inMemoryEndpoints.values()).filter((ep) => ep.tenant_id === tenantId);
  }
}

/**
 * Create a new tenant webhook endpoint.
 */
export async function createTenantWebhookEndpoint(params: {
  tenantId: string;
  name: string;
  type: "discord" | "slack" | "teams" | "generic";
  destination: string;
  secretKey?: string;
  events?: string[];
  minSeverity?: "low" | "medium" | "high" | "critical";
  enabled?: boolean;
}): Promise<TenantWebhookEndpoint> {
  const validation = validateWebhookUrl(params.destination);
  if (!validation.valid) {
    throw new Error(validation.reason || "Invalid destination URL");
  }

  const id = `wh_${crypto.randomBytes(12).toString("hex")}`;
  const now = new Date().toISOString();
  const events = params.events && params.events.length > 0
    ? params.events
    : ["threat_detected", "approval_required", "incident_created", "lockdown.activated"];
  const minSeverity = params.minSeverity || "medium";
  const enabled = params.enabled !== undefined ? params.enabled : true;

  try {
    const res = await query<TenantWebhookEndpoint>(
      `INSERT INTO tenant_webhook_endpoints 
       (id, tenant_id, name, type, destination, secret_key, events, min_severity, enabled, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
       RETURNING *`,
      [
        id,
        params.tenantId,
        params.name,
        params.type,
        params.destination,
        params.secretKey || null,
        events,
        minSeverity,
        enabled,
        now,
      ]
    );
    return res.rows[0];
  } catch (err) {
    if (shouldFailClosed()) {
      throw new Error(`Database error saving webhook endpoint: ${err instanceof Error ? err.message : "DB error"}`);
    }
    // In-memory fallback
    const endpoint: TenantWebhookEndpoint = {
      id,
      tenant_id: params.tenantId,
      name: params.name,
      type: params.type,
      destination: params.destination,
      secret_key: params.secretKey || null,
      events,
      min_severity: minSeverity,
      enabled,
      created_at: now,
      updated_at: now,
    };
    inMemoryEndpoints.set(id, endpoint);
    return endpoint;
  }
}

/**
 * Update an existing tenant webhook endpoint.
 */
export async function updateTenantWebhookEndpoint(
  id: string,
  tenantId: string,
  params: Partial<Omit<TenantWebhookEndpoint, "id" | "tenant_id" | "created_at" | "updated_at">>
): Promise<TenantWebhookEndpoint | null> {
  if (params.destination) {
    const validation = validateWebhookUrl(params.destination);
    if (!validation.valid) {
      throw new Error(validation.reason || "Invalid destination URL");
    }
  }

  const now = new Date().toISOString();

  try {
    const updates: string[] = ["updated_at = $3"];
    const values: unknown[] = [id, tenantId, now];
    let idx = 4;

    if (params.name !== undefined) {
      updates.push(`name = $${idx++}`);
      values.push(params.name);
    }
    if (params.type !== undefined) {
      updates.push(`type = $${idx++}`);
      values.push(params.type);
    }
    if (params.destination !== undefined) {
      updates.push(`destination = $${idx++}`);
      values.push(params.destination);
    }
    if (params.secret_key !== undefined) {
      updates.push(`secret_key = $${idx++}`);
      values.push(params.secret_key);
    }
    if (params.events !== undefined) {
      updates.push(`events = $${idx++}`);
      values.push(params.events);
    }
    if (params.min_severity !== undefined) {
      updates.push(`min_severity = $${idx++}`);
      values.push(params.min_severity);
    }
    if (params.enabled !== undefined) {
      updates.push(`enabled = $${idx++}`);
      values.push(params.enabled);
    }

    const res = await query<TenantWebhookEndpoint>(
      `UPDATE tenant_webhook_endpoints
       SET ${updates.join(", ")}
       WHERE id = $1 AND tenant_id = $2
       RETURNING *`,
      values
    );

    return res.rows[0] || null;
  } catch (err) {
    if (shouldFailClosed()) {
      throw new Error(`Database error updating webhook endpoint: ${err instanceof Error ? err.message : "DB error"}`);
    }
    const existing = inMemoryEndpoints.get(id);
    if (!existing || existing.tenant_id !== tenantId) return null;

    const cleanUpdates: Partial<TenantWebhookEndpoint> = {};
    if (params.name !== undefined) cleanUpdates.name = params.name;
    if (params.type !== undefined) cleanUpdates.type = params.type;
    if (params.destination !== undefined) cleanUpdates.destination = params.destination;
    if (params.secret_key !== undefined) cleanUpdates.secret_key = params.secret_key;
    if (params.events !== undefined) cleanUpdates.events = params.events;
    if (params.min_severity !== undefined) cleanUpdates.min_severity = params.min_severity;
    if (params.enabled !== undefined) cleanUpdates.enabled = params.enabled;

    const updated: TenantWebhookEndpoint = {
      ...existing,
      ...cleanUpdates,
      updated_at: now,
    };
    inMemoryEndpoints.set(id, updated);
    return updated;
  }
}

/**
 * Delete a tenant webhook endpoint.
 */
export async function deleteTenantWebhookEndpoint(id: string, tenantId: string): Promise<boolean> {
  try {
    const res = await query(
      `DELETE FROM tenant_webhook_endpoints WHERE id = $1 AND tenant_id = $2`,
      [id, tenantId]
    );
    return (res.rowCount ?? 0) > 0;
  } catch (err) {
    if (shouldFailClosed()) {
      throw new Error(`Database error deleting webhook endpoint: ${err instanceof Error ? err.message : "DB error"}`);
    }
    const existing = inMemoryEndpoints.get(id);
    if (existing && existing.tenant_id === tenantId) {
      inMemoryEndpoints.delete(id);
      return true;
    }
    return false;
  }
}

/**
 * Record a webhook delivery log for auditability & DLQ retry.
 */
export async function recordWebhookDeliveryLog(log: {
  deliveryId: string;
  tenantId: string;
  endpointId: string;
  endpointName?: string;
  eventType: string;
  severity?: string;
  statusCode?: number;
  latencyMs?: number;
  payload?: Record<string, unknown>;
  responseBody?: string;
  success: boolean;
}): Promise<WebhookDeliveryLog> {
  const id = `log_${crypto.randomBytes(12).toString("hex")}`;
  const now = new Date().toISOString();

  const record: WebhookDeliveryLog = {
    id,
    delivery_id: log.deliveryId,
    tenant_id: log.tenantId,
    endpoint_id: log.endpointId,
    endpoint_name: log.endpointName,
    event_type: log.eventType,
    severity: log.severity,
    status_code: log.statusCode,
    latency_ms: log.latencyMs,
    payload: log.payload,
    response_body: log.responseBody,
    success: log.success,
    created_at: now,
  };

  try {
    await query(
      `INSERT INTO webhook_delivery_logs
       (id, delivery_id, tenant_id, endpoint_id, endpoint_name, event_type, severity, status_code, latency_ms, payload, response_body, success, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      [
        id,
        log.deliveryId,
        log.tenantId,
        log.endpointId,
        log.endpointName || null,
        log.eventType,
        log.severity || null,
        log.statusCode || null,
        log.latencyMs || null,
        log.payload ? JSON.stringify(log.payload) : null,
        log.responseBody || null,
        log.success,
        now,
      ]
    );
  } catch {
    // In-memory fallback
    inMemoryDeliveryLogs.unshift(record);
    if (inMemoryDeliveryLogs.length > 100) {
      inMemoryDeliveryLogs.pop();
    }
  }

  return record;
}

/**
 * Retrieve recent delivery logs for audit / DLQ display.
 */
export async function getRecentWebhookDeliveryLogs(tenantId: string, limit: number = 30): Promise<WebhookDeliveryLog[]> {
  try {
    const res = await query<WebhookDeliveryLog>(
      `SELECT id, delivery_id, tenant_id, endpoint_id, endpoint_name, event_type, severity, status_code, latency_ms, payload, response_body, success, created_at
       FROM webhook_delivery_logs
       WHERE tenant_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [tenantId, limit]
    );
    return res.rows;
  } catch {
    return inMemoryDeliveryLogs.filter((l) => l.tenant_id === tenantId).slice(0, limit);
  }
}
