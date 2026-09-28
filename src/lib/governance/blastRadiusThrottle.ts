import { query } from "@/lib/db";

export const THROTTLE_WINDOW_MS = 5 * 60 * 1000;
export const DEFAULT_TIER1_LIMIT = 5;

export interface ThrottleCheckResult {
  allowed: boolean;
  count: number;
  limit: number;
}

// In-memory fallback tracking for tests and offline local execution
interface MockCommandEntry {
  tenantId: string;
  tier: string;
  timestamp: number;
}

export const MOCK_THROTTLE_ENTRIES: MockCommandEntry[] = [];

/**
 * Records a command execution/enqueue event in the in-memory throttle store.
 */
export function recordMockThrottleCommand(tenantId: string, tier: string = "Tier 1"): void {
  MOCK_THROTTLE_ENTRIES.push({
    tenantId,
    tier,
    timestamp: Date.now(),
  });
}

/**
 * Resets the in-memory throttle store (useful in test teardown/setup).
 */
export function resetMockThrottle(): void {
  MOCK_THROTTLE_ENTRIES.length = 0;
}

/**
 * Checks whether a tenant has exceeded the Tier 1 blast-radius throttle.
 * Window: sliding 5 minutes.
 * Default Limit: 5 Tier 1 commands.
 */
export async function checkThrottle(
  tenantId: string,
  limit: number = DEFAULT_TIER1_LIMIT
): Promise<ThrottleCheckResult> {
  const windowStart = new Date(Date.now() - THROTTLE_WINDOW_MS);

  try {
    const { rows } = await query<{ count: string }>(
      `SELECT count(*) FROM agent_commands
       WHERE tenant_id = $1 AND tier = 'Tier 1' AND created_at > now() - interval '5 minutes'`,
      [tenantId]
    );

    const count = Number(rows[0]?.count || 0);
    return {
      allowed: count < limit,
      count,
      limit,
    };
  } catch {
    // Fall back to in-memory tracking if database is offline or in unit tests
    const cutoff = Date.now() - THROTTLE_WINDOW_MS;
    const count = MOCK_THROTTLE_ENTRIES.filter(
      (entry) => entry.tenantId === tenantId && entry.tier === "Tier 1" && entry.timestamp >= cutoff
    ).length;

    return {
      allowed: count < limit,
      count,
      limit,
    };
  }
}
