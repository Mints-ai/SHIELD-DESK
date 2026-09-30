import "server-only";

export type MetricType =
  | "active_endpoints"
  | "telemetry_bytes"
  | "remediations_executed"
  | "ai_tokens_consumed";

export interface TenantUsageRecord {
  tenantId: string;
  period: string; // YYYY-MM
  activeEndpoints: number;
  telemetryBytes: number;
  remediationsExecuted: number;
  aiTokensConsumed: number;
  lastUpdated: string;
}

export const MOCK_USAGE_STORE: Map<string, TenantUsageRecord> = new Map();

function getPeriodKey(tenantId: string, date = new Date()): string {
  const yyyy = date.getUTCFullYear();
  const mm = String(date.getUTCMonth() + 1).padStart(2, "0");
  return `${tenantId}:${yyyy}-${mm}`;
}

/**
 * Records a usage metric for a tenant.
 */
export function recordUsageMetric(
  tenantId: string,
  metric: MetricType,
  quantity: number
): TenantUsageRecord {
  const key = getPeriodKey(tenantId);
  const now = new Date().toISOString();

  let record = MOCK_USAGE_STORE.get(key);
  if (!record) {
    const period = key.split(":")[1];
    record = {
      tenantId,
      period,
      activeEndpoints: 0,
      telemetryBytes: 0,
      remediationsExecuted: 0,
      aiTokensConsumed: 0,
      lastUpdated: now,
    };
    MOCK_USAGE_STORE.set(key, record);
  }

  switch (metric) {
    case "active_endpoints":
      record.activeEndpoints = Math.max(record.activeEndpoints, quantity);
      break;
    case "telemetry_bytes":
      record.telemetryBytes += quantity;
      break;
    case "remediations_executed":
      record.remediationsExecuted += quantity;
      break;
    case "ai_tokens_consumed":
      record.aiTokensConsumed += quantity;
      break;
  }

  record.lastUpdated = now;
  return record;
}

/**
 * Retrieves the usage report for a tenant.
 */
export function getTenantUsageReport(
  tenantId: string,
  date = new Date()
): TenantUsageRecord {
  const key = getPeriodKey(tenantId, date);
  const existing = MOCK_USAGE_STORE.get(key);

  if (existing) {
    return existing;
  }

  const period = key.split(":")[1];
  return {
    tenantId,
    period,
    activeEndpoints: 0,
    telemetryBytes: 0,
    remediationsExecuted: 0,
    aiTokensConsumed: 0,
    lastUpdated: new Date().toISOString(),
  };
}

/**
 * Resets usage metrics for testing purposes.
 */
export function resetUsageMetrics(): void {
  MOCK_USAGE_STORE.clear();
}
