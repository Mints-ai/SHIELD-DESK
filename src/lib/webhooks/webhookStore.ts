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
  attempts: number;
  is_dlq: boolean;
  status: "DELIVERED" | "DEAD_LETTER" | "RETRIED" | "PERMANENT_FAILURE";
  error_message?: string;
  destination?: string;
  last_attempt_at?: string;
  created_at: string;
}

export interface WebhookMetrics {
  total_dispatches: number;
  delivered_count: number;
  dlq_pending_count: number;
  retried_count: number;
  success_rate: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
  status_code_breakdown: {
    "2xx": number;
    "4xx": number;
    "5xx": number;
    timeout: number;
  };
}

// In-memory fallback stores for offline dev / test environments
const inMemoryEndpoints = new Map<string, TenantWebhookEndpoint>();
const inMemoryDeliveryLogs: WebhookDeliveryLog[] = [];

/**
 * Reset memory state for testing purposes.
 */
export function clearInMemoryStore(): void {
  inMemoryEndpoints.clear();
  inMemoryDeliveryLogs.length = 0;
}

/**
 * Automatically detects webhook platform from destination URL.
 */
export function detectWebhookPlatform(urlStr: string): "discord" | "slack" | "teams" | "generic" {
  try {
    const url = new URL(urlStr);
    const host = url.hostname.toLowerCase();
    const pathname = url.pathname.toLowerCase();

    if (host.includes("discord.com") || host.includes("discordapp.com")) {
      if (pathname.includes("/api/webhooks")) return "discord";
    }
    if (host.includes("slack.com") || host.includes("hooks.slack.com")) {
      return "slack";
    }
    if (
      host.includes("office.com") ||
      host.includes("office365.com") ||
      host.includes("webhook.office.com") ||
      pathname.includes("incomingwebhook")
    ) {
      return "teams";
    }
    return "generic";
  } catch {
    return "generic";
  }
}

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
 * Create a new tenant webhook endpoint with auto-platform detection.
 */
export async function createTenantWebhookEndpoint(params: {
  tenantId: string;
  name: string;
  type?: "discord" | "slack" | "teams" | "generic";
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

  // Auto-detect platform if not provided or set to generic
  let finalType = params.type || "generic";
  if (finalType === "generic") {
    const detected = detectWebhookPlatform(params.destination);
    if (detected !== "generic") {
      finalType = detected;
    }
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
        finalType,
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
      type: finalType,
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
 * Unifies SSRF validation, millisecond timer calculation, HMAC signing, and format serialization.
 */
export async function executeWebhookDispatch(params: {
  destination: string;
  type?: "discord" | "slack" | "teams" | "generic";
  eventType: string;
  severity?: string;
  tenantId: string;
  payload: Record<string, unknown>;
  deliveryId?: string;
  secretKey?: string | null;
  timeoutMs?: number;
}): Promise<{
  statusCode: number;
  latencyMs: number;
  responseBody: string;
  success: boolean;
  errorMessage?: string;
}> {
  const validation = validateWebhookUrl(params.destination);
  if (!validation.valid) {
    return {
      statusCode: 400,
      latencyMs: 1,
      responseBody: validation.reason || "Invalid destination URL",
      success: false,
      errorMessage: validation.reason || "SSRF blocked destination",
    };
  }

  const deliveryId = params.deliveryId || `del_${crypto.randomBytes(12).toString("hex")}`;
  const nowEpoch = Math.floor(Date.now() / 1000);
  const type = params.type || detectWebhookPlatform(params.destination);
  const payloadString = JSON.stringify(params.payload);

  const secret =
    params.secretKey ||
    process.env.SHIELDDESK_WEBHOOK_SECRET ||
    (process.env.NODE_ENV !== "production" ? "sd_webhook_dev_secret" : "");

  const hmacHex = secret
    ? crypto.createHmac("sha256", secret).update(`${nowEpoch}.${payloadString}`).digest("hex")
    : "";
  const signature = hmacHex ? `t=${nowEpoch},v1=${hmacHex}` : "";
  const legacySig = secret
    ? `sha256=${crypto.createHmac("sha256", secret).update(payloadString).digest("hex")}`
    : "";

  let body: string;
  const severityStr = (params.severity || "standard").toUpperCase();

  if (type === "discord") {
    body = JSON.stringify({
      content: params.severity === "critical"
        ? "🚨 **[ShieldDesk Critical Security Alert]**"
        : "🛡️ **[ShieldDesk SOC]** Webhook Alert Dispatch",
      embeds: [
        {
          title: (params.payload.title as string) || `ShieldDesk Event: ${params.eventType}`,
          description: (params.payload.description as string) || (params.payload.message as string) || "Security event notification",
          color: params.severity === "critical" ? 0xdc2626 : params.severity === "high" ? 0xea580c : 0x10b981,
          fields: [
            { name: "Tenant", value: params.tenantId, inline: true },
            { name: "Event Type", value: params.eventType, inline: true },
            { name: "Severity", value: severityStr, inline: true },
            { name: "Delivery ID", value: deliveryId, inline: false },
          ],
          footer: { text: "ShieldDesk Autonomous EDR / SOC" },
          timestamp: new Date().toISOString(),
        },
      ],
    });
  } else if (type === "slack") {
    body = JSON.stringify({
      text: `🛡️ *[ShieldDesk SOC]* Webhook Alert Dispatch (${params.eventType})`,
      attachments: [
        {
          color: params.severity === "critical" ? "#dc2626" : params.severity === "high" ? "#ea580c" : "#10b981",
          title: (params.payload.title as string) || `ShieldDesk Event: ${params.eventType}`,
          text: (params.payload.description as string) || (params.payload.message as string) || "",
          fields: [
            { title: "Tenant", value: params.tenantId, short: true },
            { title: "Severity", value: severityStr, short: true },
            { title: "Delivery ID", value: deliveryId, short: false },
          ],
          footer: "ShieldDesk Autonomous SOC Platform",
          ts: nowEpoch,
        },
      ],
    });
  } else if (type === "teams") {
    body = JSON.stringify({
      "@type": "MessageCard",
      "@context": "http://schema.org/extensions",
      themeColor: params.severity === "critical" ? "dc2626" : "10b981",
      summary: (params.payload.title as string) || `ShieldDesk Alert: ${params.eventType}`,
      sections: [
        {
          activityTitle: `ShieldDesk SOC: ${params.payload.title || params.eventType}`,
          activitySubtitle: `Tenant: ${params.tenantId} | Severity: ${severityStr}`,
          text: (params.payload.description as string) || (params.payload.message as string) || "",
        },
      ],
    });
  } else {
    body = payloadString;
  }

  const startTime = Date.now();
  let statusCode = 200;
  let responseBody = "";
  let success = false;
  let errorMessage: string | undefined;

  try {
    const res = await fetch(params.destination, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-Event": params.eventType,
        "X-ShieldDesk-Delivery-Id": deliveryId,
        "X-ShieldDesk-Timestamp": String(nowEpoch),
        ...(signature ? {
          "X-ShieldDesk-Signature": signature,
          "X-ShieldDesk-Signature-Legacy": legacySig,
        } : {}),
      },
      body,
      signal: AbortSignal.timeout(params.timeoutMs || 5000),
    });

    statusCode = res.status;
    responseBody = await res.text().catch(() => "");
    success = res.ok || res.status === 204;
    if (!success) {
      errorMessage = `Destination returned HTTP ${statusCode}: ${responseBody.slice(0, 300)}`;
    }
  } catch (err) {
    statusCode = 504;
    errorMessage = err instanceof Error ? err.message : "Network delivery timeout";
    responseBody = errorMessage;
    success = false;
  }

  const latencyMs = Math.max(1, Date.now() - startTime);

  return {
    statusCode,
    latencyMs,
    responseBody,
    success,
    errorMessage,
  };
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
  success?: boolean;
  attempts?: number;
  isDlq?: boolean;
  status?: "DELIVERED" | "DEAD_LETTER" | "RETRIED" | "PERMANENT_FAILURE";
  errorMessage?: string;
  destination?: string;
  lastAttemptAt?: string;
}): Promise<WebhookDeliveryLog> {
  const id = `log_${crypto.randomBytes(12).toString("hex")}`;
  const now = new Date().toISOString();

  const isSuccess = log.success !== undefined
    ? log.success
    : (log.statusCode !== undefined ? log.statusCode >= 200 && log.statusCode < 300 : false);

  let status: "DELIVERED" | "DEAD_LETTER" | "RETRIED" | "PERMANENT_FAILURE" = log.status || (isSuccess ? "DELIVERED" : "DEAD_LETTER");
  let isDlq = log.isDlq !== undefined ? log.isDlq : !isSuccess;

  // Determine DLQ flags if not explicitly provided
  if (!log.status) {
    if (isSuccess) {
      status = "DELIVERED";
      isDlq = false;
    } else {
      status = "DEAD_LETTER";
      isDlq = true;
    }
  }

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
    success: isSuccess,
    attempts: log.attempts || 1,
    is_dlq: isDlq,
    status,
    error_message: log.errorMessage,
    destination: log.destination,
    last_attempt_at: log.lastAttemptAt || now,
    created_at: now,
  };

  try {
    await query(
      `INSERT INTO webhook_delivery_logs
       (id, delivery_id, tenant_id, endpoint_id, endpoint_name, event_type, severity, status_code, latency_ms, payload, response_body, success, attempts, is_dlq, status, error_message, destination, last_attempt_at, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
      [
        id,
        record.delivery_id,
        record.tenant_id,
        record.endpoint_id,
        record.endpoint_name || null,
        record.event_type,
        record.severity || null,
        record.status_code || null,
        record.latency_ms || null,
        record.payload ? JSON.stringify(record.payload) : null,
        record.response_body || null,
        record.success,
        record.attempts,
        record.is_dlq,
        record.status,
        record.error_message || null,
        record.destination || null,
        record.last_attempt_at,
        record.created_at,
      ]
    );
  } catch {
    // In-memory fallback
    inMemoryDeliveryLogs.unshift(record);
    if (inMemoryDeliveryLogs.length > 200) {
      inMemoryDeliveryLogs.pop();
    }
  }

  return record;
}

/**
 * Retrieve recent delivery logs for audit / DLQ display.
 */
export async function getRecentWebhookDeliveryLogs(
  tenantId: string,
  limit: number = 50,
  filter?: { isDlq?: boolean; status?: string }
): Promise<WebhookDeliveryLog[]> {
  try {
    const conditions: string[] = ["tenant_id = $1"];
    const params: unknown[] = [tenantId];
    let idx = 2;

    if (filter?.isDlq !== undefined) {
      conditions.push(`is_dlq = $${idx++}`);
      params.push(filter.isDlq);
    }
    if (filter?.status) {
      conditions.push(`status = $${idx++}`);
      params.push(filter.status);
    }

    params.push(limit);
    const queryStr = `
      SELECT id, delivery_id, tenant_id, endpoint_id, endpoint_name, event_type, severity, status_code, latency_ms, payload, response_body, success, attempts, is_dlq, status, error_message, destination, last_attempt_at, created_at
      FROM webhook_delivery_logs
      WHERE ${conditions.join(" AND ")}
      ORDER BY created_at DESC
      LIMIT $${idx}
    `;

    const res = await query<WebhookDeliveryLog>(queryStr, params);
    return res.rows;
  } catch {
    return inMemoryDeliveryLogs
      .filter((l) => {
        if (l.tenant_id !== tenantId) return false;
        if (filter?.isDlq !== undefined && l.is_dlq !== filter.isDlq) return false;
        if (filter?.status && l.status !== filter.status) return false;
        return true;
      })
      .slice(0, limit);
  }
}

/**
 * Calculates live webhook reliability & latency metrics for a tenant.
 */
export async function getWebhookMetrics(tenantId: string): Promise<WebhookMetrics> {
  let logs: WebhookDeliveryLog[] = [];
  try {
    const res = await query<WebhookDeliveryLog>(
      `SELECT status_code, latency_ms, success, is_dlq, status
       FROM webhook_delivery_logs
       WHERE tenant_id = $1
       ORDER BY created_at DESC
       LIMIT 500`,
      [tenantId]
    );
    logs = res.rows;
  } catch {
    logs = inMemoryDeliveryLogs.filter((l) => l.tenant_id === tenantId);
  }

  const total = logs.length;
  if (total === 0) {
    return {
      total_dispatches: 0,
      delivered_count: 0,
      dlq_pending_count: 0,
      retried_count: 0,
      success_rate: 100,
      avg_latency_ms: 0,
      p95_latency_ms: 0,
      status_code_breakdown: {
        "2xx": 0,
        "4xx": 0,
        "5xx": 0,
        timeout: 0,
      },
    };
  }

  let deliveredCount = 0;
  let dlqPendingCount = 0;
  let retriedCount = 0;
  const latencies: number[] = [];

  const breakdown = {
    "2xx": 0,
    "4xx": 0,
    "5xx": 0,
    timeout: 0,
  };

  for (const log of logs) {
    if (log.success || log.status === "DELIVERED") {
      deliveredCount++;
    }
    if (log.is_dlq) {
      dlqPendingCount++;
    }
    if (log.status === "RETRIED") {
      retriedCount++;
    }

    if (typeof log.latency_ms === "number" && log.latency_ms > 0) {
      latencies.push(log.latency_ms);
    }

    const code = log.status_code;
    if (code) {
      if (code >= 200 && code < 300) breakdown["2xx"]++;
      else if (code >= 400 && code < 500) breakdown["4xx"]++;
      else if (code === 504) breakdown.timeout++;
      else if (code >= 500 && code < 600) breakdown["5xx"]++;
      else breakdown.timeout++;
    } else {
      breakdown.timeout++;
    }
  }

  const successRate = total > 0 ? parseFloat(((deliveredCount / total) * 100).toFixed(1)) : 100;

  let avgLatency = 0;
  let p95Latency = 0;

  if (latencies.length > 0) {
    avgLatency = Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length);
    const sorted = [...latencies].sort((a, b) => a - b);
    const p95Index = Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95));
    p95Latency = sorted[p95Index];
  }

  return {
    total_dispatches: total,
    delivered_count: deliveredCount,
    dlq_pending_count: dlqPendingCount,
    retried_count: retriedCount,
    success_rate: successRate,
    avg_latency_ms: avgLatency,
    p95_latency_ms: p95Latency,
    status_code_breakdown: breakdown,
  };
}

/**
 * Replays a failed or dead-lettered webhook delivery.
 */
export async function retryWebhookDelivery(
  deliveryId: string,
  tenantId: string
): Promise<WebhookDeliveryLog> {
  let log: WebhookDeliveryLog | undefined;

  try {
    const res = await query<WebhookDeliveryLog>(
      `SELECT * FROM webhook_delivery_logs WHERE delivery_id = $1 AND tenant_id = $2 LIMIT 1`,
      [deliveryId, tenantId]
    );
    log = res.rows[0];
  } catch {
    log = inMemoryDeliveryLogs.find((l) => l.delivery_id === deliveryId && l.tenant_id === tenantId);
  }

  if (!log) {
    throw new Error(`Webhook delivery log '${deliveryId}' not found for tenant '${tenantId}'`);
  }

  // Resolve destination URL
  let targetUrl = log.destination;
  let targetType: "discord" | "slack" | "teams" | "generic" = "generic";
  let secretKey: string | undefined;

  if (!targetUrl) {
    // Look up endpoint
    const endpoints = await getTenantWebhookEndpoints(tenantId);
    const ep = endpoints.find((e) => e.id === log?.endpoint_id);
    if (ep) {
      targetUrl = ep.destination;
      targetType = ep.type;
      secretKey = ep.secret_key || undefined;
    } else if (log.endpoint_id === "wh-discord" && process.env.DISCORD_WEBHOOK_URL) {
      targetUrl = process.env.DISCORD_WEBHOOK_URL;
      targetType = "discord";
    } else if (log.endpoint_id === "wh-slack" && process.env.SLACK_WEBHOOK_URL) {
      targetUrl = process.env.SLACK_WEBHOOK_URL;
      targetType = "slack";
    } else if (log.endpoint_id === "wh-teams" && process.env.TEAMS_WEBHOOK_URL) {
      targetUrl = process.env.TEAMS_WEBHOOK_URL;
      targetType = "teams";
    }
  }

  if (!targetUrl) {
    throw new Error(`Cannot replay webhook: Destination URL unknown for endpoint '${log.endpoint_id}'`);
  }

  // Execute replay dispatch
  const result = await executeWebhookDispatch({
    destination: targetUrl,
    type: targetType,
    eventType: log.event_type,
    severity: log.severity,
    tenantId,
    payload: log.payload || {},
    deliveryId: log.delivery_id,
    secretKey,
  });

  const now = new Date().toISOString();
  const nextAttempts = (log.attempts || 1) + 1;

  const updatedLog: WebhookDeliveryLog = {
    ...log,
    status_code: result.statusCode,
    latency_ms: result.latencyMs,
    response_body: result.responseBody.slice(0, 500),
    success: result.success,
    attempts: nextAttempts,
    is_dlq: !result.success,
    status: result.success ? "RETRIED" : "DEAD_LETTER",
    error_message: result.success ? undefined : (result.errorMessage || `Failed with HTTP ${result.statusCode}`),
    destination: targetUrl,
    last_attempt_at: now,
  };

  try {
    await query(
      `UPDATE webhook_delivery_logs
       SET status_code = $1, latency_ms = $2, response_body = $3, success = $4, attempts = $5, is_dlq = $6, status = $7, error_message = $8, destination = $9, last_attempt_at = $10
       WHERE delivery_id = $11 AND tenant_id = $12`,
      [
        updatedLog.status_code,
        updatedLog.latency_ms,
        updatedLog.response_body,
        updatedLog.success,
        updatedLog.attempts,
        updatedLog.is_dlq,
        updatedLog.status,
        updatedLog.error_message || null,
        updatedLog.destination || null,
        updatedLog.last_attempt_at,
        deliveryId,
        tenantId,
      ]
    );
  } catch {
    // In-memory fallback
    const idx = inMemoryDeliveryLogs.findIndex((l) => l.delivery_id === deliveryId && l.tenant_id === tenantId);
    if (idx !== -1) {
      inMemoryDeliveryLogs[idx] = updatedLog;
    }
  }

  return updatedLog;
}

/**
 * Replays all pending dead-letter queue entries for a tenant in batch.
 */
export async function retryAllDlqDeliveries(tenantId: string): Promise<{
  total_dlq_found: number;
  retried_count: number;
  succeeded_count: number;
  failed_count: number;
  results: Array<{ deliveryId: string; success: boolean; statusCode: number }>;
}> {
  const dlqLogs = await getRecentWebhookDeliveryLogs(tenantId, 100, { isDlq: true });

  const results: Array<{ deliveryId: string; success: boolean; statusCode: number }> = [];
  let succeeded = 0;
  let failed = 0;

  for (const log of dlqLogs) {
    try {
      const updated = await retryWebhookDelivery(log.delivery_id, tenantId);
      results.push({
        deliveryId: log.delivery_id,
        success: updated.success,
        statusCode: updated.status_code || 0,
      });
      if (updated.success) {
        succeeded++;
      } else {
        failed++;
      }
    } catch {
      failed++;
      results.push({
        deliveryId: log.delivery_id,
        success: false,
        statusCode: 500,
      });
    }
  }

  return {
    total_dlq_found: dlqLogs.length,
    retried_count: results.length,
    succeeded_count: succeeded,
    failed_count: failed,
    results,
  };
}
