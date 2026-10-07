import fs from "fs";
import path from "path";

export interface ShodanApiInfo {
  configured: boolean;
  plan?: string;
  scanCredits?: number;
  queryCredits?: number;
  monitoredIps?: number;
  unlockedLeft?: number;
  error?: string;
}

export interface ShodanServiceBanner {
  port: number;
  transport?: string;
  product?: string;
  version?: string;
  banner?: string;
}

export interface ShodanHostInspection {
  found: boolean;
  ip: string;
  org?: string;
  isp?: string;
  asn?: string;
  hostnames?: string[];
  domains?: string[];
  country?: string;
  countryCode?: string;
  city?: string;
  region?: string;
  ports: number[];
  vulns: string[];
  lastUpdate?: string;
  services: ShodanServiceBanner[];
  message?: string;
}

// In-memory cache for API info and host lookups (TTL 3 minutes)
interface CacheEntry<T> {
  data: T;
  timestamp: number;
}
const cache = new Map<string, CacheEntry<any>>();
const CACHE_TTL_MS = 3 * 60 * 1000;

function getCached<T>(key: string): T | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    cache.delete(key);
    return null;
  }
  return entry.data as T;
}

function setCached<T>(key: string, data: T): void {
  cache.set(key, { data, timestamp: Date.now() });
}

/**
 * Retrieves the Shodan API key from process.env or falls back to reading .env.local on disk.
 */
export function getShodanApiKey(): string | undefined {
  if (process.env.SHODAN_API_KEY && process.env.SHODAN_API_KEY.trim() !== "") {
    return process.env.SHODAN_API_KEY.trim();
  }

  // Fallback: parse .env.local or .env directly from filesystem in dev
  try {
    const root = process.cwd();
    const envPaths = [path.join(root, ".env.local"), path.join(root, ".env")];
    for (const p of envPaths) {
      if (fs.existsSync(p)) {
        const content = fs.readFileSync(p, "utf-8");
        for (const line of content.split("\n")) {
          const trimmed = line.trim();
          if (trimmed.startsWith("#") || !trimmed.includes("=")) continue;
          const [key, ...vals] = trimmed.split("=");
          if (key.trim() === "SHODAN_API_KEY") {
            const val = vals.join("=").trim().replace(/^["']|["']$/g, "");
            if (val) {
              // Populate process.env so subsequent reads are fast
              process.env.SHODAN_API_KEY = val;
              return val;
            }
          }
        }
      }
    }
  } catch {
    // Ignore FS errors
  }

  return undefined;
}

/**
 * Queries Shodan API to verify API key validity and credit balance.
 */
export async function getShodanApiInfo(customKey?: string): Promise<ShodanApiInfo> {
  const key = customKey || getShodanApiKey();
  if (!key) {
    return {
      configured: false,
      error: "SHODAN_API_KEY not configured in environment.",
    };
  }

  const cacheKey = `api-info:${key.slice(0, 6)}`;
  const cached = getCached<ShodanApiInfo>(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetch(`https://api.shodan.io/api-info?key=${encodeURIComponent(key)}`, {
      signal: AbortSignal.timeout(6000),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      return {
        configured: false,
        error: `Shodan API error (${res.status}): ${errText || res.statusText}`,
      };
    }

    const data = await res.json();
    const result: ShodanApiInfo = {
      configured: true,
      plan: data.plan || "community",
      scanCredits: data.scan_credits ?? 0,
      queryCredits: data.query_credits ?? 0,
      monitoredIps: data.monitored_ips ?? 0,
      unlockedLeft: data.unlocked_left ?? 0,
    };

    setCached(cacheKey, result);
    return result;
  } catch (err: any) {
    return {
      configured: false,
      error: `Failed to connect to Shodan API: ${err.message || String(err)}`,
    };
  }
}

/**
 * Resolves the client's current external public IP using Shodan's tools/myip endpoint.
 */
export async function getMyPublicIp(customKey?: string): Promise<string | null> {
  const key = customKey || getShodanApiKey();
  if (!key) return null;

  const cacheKey = `my-ip:${key.slice(0, 6)}`;
  const cached = getCached<string>(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetch(`https://api.shodan.io/tools/myip?key=${encodeURIComponent(key)}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const raw = await res.text();
    // Raw output is either `"1.2.3.4"` or `1.2.3.4`
    const ip = raw.replace(/["\s]/g, "");
    if (ip) {
      setCached(cacheKey, ip);
      return ip;
    }
  } catch {
    // Ignore network error
  }
  return null;
}

/**
 * Inspects an IP address or hostname using Shodan's Host API.
 */
export async function inspectHost(
  targetIp: string,
  customKey?: string
): Promise<ShodanHostInspection> {
  const key = customKey || getShodanApiKey();
  if (!key) {
    return {
      found: false,
      ip: targetIp,
      ports: [],
      vulns: [],
      services: [],
      message: "SHODAN_API_KEY is not configured.",
    };
  }

  const cleanIp = targetIp.trim();
  const cacheKey = `host:${cleanIp}:${key.slice(0, 6)}`;
  const cached = getCached<ShodanHostInspection>(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetch(
      `https://api.shodan.io/shodan/host/${encodeURIComponent(cleanIp)}?key=${encodeURIComponent(key)}`,
      { signal: AbortSignal.timeout(10000) }
    );

    if (res.status === 404) {
      const notFoundResult: ShodanHostInspection = {
        found: false,
        ip: cleanIp,
        ports: [],
        vulns: [],
        services: [],
        message: "No open services or indexed vulnerabilities found for this IP on Shodan. The host may be firewalled, private, or has no active listening ports exposed to the public internet.",
      };
      setCached(cacheKey, notFoundResult);
      return notFoundResult;
    }

    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      return {
        found: false,
        ip: cleanIp,
        ports: [],
        vulns: [],
        services: [],
        message: `Shodan lookup failed (${res.status}): ${errText || res.statusText}`,
      };
    }

    const data = await res.json();

    const services: ShodanServiceBanner[] = Array.isArray(data.data)
      ? data.data.map((s: any) => ({
          port: s.port,
          transport: s.transport,
          product: s.product || (s._shodan?.module ? `Service (${s._shodan.module})` : "Active Service"),
          version: s.version,
          banner:
            typeof s.data === "string"
              ? s.data.trim().split("\n").slice(0, 4).join(" ").slice(0, 200)
              : undefined,
        }))
      : [];

    const result: ShodanHostInspection = {
      found: true,
      ip: data.ip_str || cleanIp,
      org: data.org,
      isp: data.isp,
      asn: data.asn,
      hostnames: Array.isArray(data.hostnames) ? data.hostnames : [],
      domains: Array.isArray(data.domains) ? data.domains : [],
      country: data.country_name,
      countryCode: data.country_code,
      city: data.city,
      region: data.region_code,
      ports: Array.isArray(data.ports) ? data.ports.sort((a: number, b: number) => a - b) : [],
      vulns: Array.isArray(data.vulns) ? data.vulns : [],
      lastUpdate: data.last_update,
      services,
    };

    setCached(cacheKey, result);
    return result;
  } catch (err: any) {
    return {
      found: false,
      ip: cleanIp,
      ports: [],
      vulns: [],
      services: [],
      message: `Error inspecting host via Shodan: ${err.message || String(err)}`,
    };
  }
}
