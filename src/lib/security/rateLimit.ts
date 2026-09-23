/**
 * ShieldDesk Production API Rate Limiter
 *
 * Implements a sliding window rate-limiter to protect against:
 * 1. DoS / DDoS flooding on public API endpoints
 * 2. LLM token exhaustion & prompt spam
 * 3. Credential brute-forcing on approval and login endpoints
 */

interface RateLimitRecord {
  count: number;
  resetAt: number;
}

const IP_RATE_LIMITS = new Map<string, RateLimitRecord>();

// Clean up expired entries every 5 minutes
if (typeof setInterval !== "undefined") {
  setInterval(() => {
    const now = Date.now();
    for (const [key, value] of IP_RATE_LIMITS.entries()) {
      if (now > value.resetAt) {
        IP_RATE_LIMITS.delete(key);
      }
    }
  }, 300000);
}

export interface RateLimitOptions {
  limit?: number;        // Max requests allowed in window (default: 60)
  windowMs?: number;     // Window size in ms (default: 60,000ms = 1 minute)
}

export function checkRateLimit(
  identifier: string,
  options: RateLimitOptions = {}
): { allowed: boolean; remaining: number; resetAt: number } {
  const limit = options.limit ?? 120;
  const windowMs = options.windowMs ?? 60000;
  const now = Date.now();

  const record = IP_RATE_LIMITS.get(identifier);

  if (!record || now > record.resetAt) {
    const newRecord: RateLimitRecord = {
      count: 1,
      resetAt: now + windowMs,
    };
    IP_RATE_LIMITS.set(identifier, newRecord);
    return {
      allowed: true,
      remaining: limit - 1,
      resetAt: newRecord.resetAt,
    };
  }

  record.count++;
  if (record.count > limit) {
    return {
      allowed: false,
      remaining: 0,
      resetAt: record.resetAt,
    };
  }

  return {
    allowed: true,
    remaining: limit - record.count,
    resetAt: record.resetAt,
  };
}
