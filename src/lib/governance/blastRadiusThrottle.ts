import { query } from "@/lib/db";
import { shouldFailClosed } from "@/lib/config/environment";

export const THROTTLE_WINDOW_MS = 5 * 60 * 1000;
export const DEFAULT_TIER1_LIMIT = 50;

export interface ThrottleCheckResult {
  allowed: boolean;
  count: number;
  limit: number;
}

// In-memory fallback tracking for unit test suites and offline local execution
export interface ThrottleCommandEntry {
  tenantId: string;
  tier: string;
  timestamp: number;
}

export const IN_MEMORY_THROTTLE_ENTRIES: ThrottleCommandEntry[] = [];

/**
 * Records a command execution/enqueue event in the in-memory throttle store.
 */
export function recordThrottleCommand(tenantId: string, tier: string = "Tier 1"): void {
  IN_MEMORY_THROTTLE_ENTRIES.push({
    tenantId,
    tier,
    timestamp: Date.now(),
  });
}

export const recordMockThrottleCommand = recordThrottleCommand;

/**
 * Resets the in-memory throttle store (used in test teardown/setup).
 */
export function resetThrottleStore(): void {
  IN_MEMORY_THROTTLE_ENTRIES.length = 0;
}

export const resetMockThrottle = resetThrottleStore;

/**
 * Checks whether a tenant has exceeded the Tier 1 blast-radius throttle.
 * Window: sliding 5 minutes.
 * Default Limit: 50 Tier 1 commands.
 */
export async function checkThrottle(
  tenantId: string,
  limit: number = DEFAULT_TIER1_LIMIT
): Promise<ThrottleCheckResult> {
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
    if (shouldFailClosed() && process.env.NODE_ENV !== "test") {
      return {
        allowed: false,
        count: limit,
        limit,
      };
    }

    // Fall back to in-memory tracking if database is offline or in unit tests
    const cutoff = Date.now() - THROTTLE_WINDOW_MS;
    const count = IN_MEMORY_THROTTLE_ENTRIES.filter(
      (entry) => entry.tenantId === tenantId && entry.tier === "Tier 1" && entry.timestamp >= cutoff
    ).length;

    return {
      allowed: count < limit,
      count,
      limit,
    };
  }
}

