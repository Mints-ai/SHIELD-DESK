import Redis from "ioredis";

const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";

let redisClient: Redis | null = null;
const memoryCache = new Map<string, { val: string; expires: number }>();

try {
  redisClient = new Redis(REDIS_URL, {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
    retryStrategy: () => null, // Don't crash if local dev Redis is offline
  });
  redisClient.connect().catch(() => {
    console.warn("[IAM-Redis] Notice: Redis not reachable, falling back to safe in-memory cache.");
    redisClient = null;
  });
} catch {
  redisClient = null;
}

export async function setCache(key: string, val: string, ttlSeconds: number): Promise<void> {
  if (redisClient) {
    await redisClient.set(key, val, "EX", ttlSeconds);
  } else {
    memoryCache.set(key, { val, expires: Date.now() + ttlSeconds * 1000 });
  }
}

export async function getCache(key: string): Promise<string | null> {
  if (redisClient) {
    return await redisClient.get(key);
  }
  const item = memoryCache.get(key);
  if (!item) return null;
  if (Date.now() > item.expires) {
    memoryCache.delete(key);
    return null;
  }
  return item.val;
}

export async function delCache(key: string): Promise<void> {
  if (redisClient) {
    await redisClient.del(key);
  } else {
    memoryCache.delete(key);
  }
}

// Check and increment IP rate limit counter (TTL 60s)
export async function checkRateLimit(ip: string, maxRequests = 100): Promise<{ allowed: boolean; remaining: number }> {
  const key = `ratelimit:${ip}`;
  if (redisClient) {
    const count = await redisClient.incr(key);
    if (count === 1) {
      await redisClient.expire(key, 60);
    }
    return { allowed: count <= maxRequests, remaining: Math.max(0, maxRequests - count) };
  }

  // Memory fallback
  const now = Date.now();
  const entry = memoryCache.get(key);
  let count = 1;
  if (entry && now < entry.expires) {
    count = parseInt(entry.val, 10) + 1;
    memoryCache.set(key, { val: count.toString(), expires: entry.expires });
  } else {
    memoryCache.set(key, { val: "1", expires: now + 60000 });
  }
  return { allowed: count <= maxRequests, remaining: Math.max(0, maxRequests - count) };
}
