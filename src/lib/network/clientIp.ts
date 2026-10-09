import { NextRequest } from "next/server";
import os from "os";

// In-memory cache for resolved public IP
declare global {
  // eslint-disable-next-line no-var
  var __shieldDeskCachedPublicIp: { ip: string; timestamp: number } | undefined;
}

/**
 * Fetch the real external/public IP of this machine if running in local development
 * or loopback environment. Caches the result in memory for 10 minutes.
 */
export async function getRealPublicIp(): Promise<string> {
  const now = Date.now();
  if (
    global.__shieldDeskCachedPublicIp &&
    now - global.__shieldDeskCachedPublicIp.timestamp < 10 * 60 * 1000
  ) {
    return global.__shieldDeskCachedPublicIp.ip;
  }

  // Attempt to fetch actual public IP from lightweight IP lookup services
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);
    const res = await fetch("https://api.ipify.org?format=json", {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      if (data && typeof data.ip === "string" && data.ip.trim().length > 0) {
        const ip = data.ip.trim();
        global.__shieldDeskCachedPublicIp = { ip, timestamp: now };
        return ip;
      }
    }
  } catch {
    // Secondary fallback service if ipify is temporarily unreachable
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);
      const res = await fetch("https://api64.ipify.org?format=json", {
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (res.ok) {
        const data = await res.json();
        if (data && typeof data.ip === "string" && data.ip.trim().length > 0) {
          const ip = data.ip.trim();
          global.__shieldDeskCachedPublicIp = { ip, timestamp: now };
          return ip;
        }
      }
    } catch {
      // Fall through to local network interface detection
    }
  }

  // Fallback to local network adapter IPv4 (e.g. 192.168.x.x, 10.x.x.x)
  try {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      const netList = interfaces[name];
      if (netList) {
        for (const net of netList) {
          if (net.family === "IPv4" && !net.internal && net.address) {
            global.__shieldDeskCachedPublicIp = { ip: net.address, timestamp: now };
            return net.address;
          }
        }
      }
    }
  } catch {
    // Ignore error
  }

  return "127.0.0.1";
}

/**
 * Resolves the genuine client IP address for incoming HTTP requests.
 * Hierarchy:
 * 1. Explicit body clientIp (if supplied by client-side detector and not loopback)
 * 2. Header 'x-client-ip'
 * 3. Header 'cf-connecting-ip'
 * 4. Header 'x-real-ip'
 * 5. Header 'x-forwarded-for' (first IP in proxy chain)
 * 6. If IP is loopback ('127.0.0.1' or '::1') and not explicitly under test runner:
 *    Resolves actual external public IP so real source telemetry is captured and blocked.
 */
export async function resolveClientIp(
  req: NextRequest,
  bodyClientIp?: string | null
): Promise<string> {
  // 1. Client-supplied IP from payload
  if (bodyClientIp && typeof bodyClientIp === "string") {
    const clean = bodyClientIp.trim();
    if (clean && clean !== "127.0.0.1" && clean !== "::1") {
      return clean;
    }
  }

  // 2. Custom client-provided header
  const customClientIp = req.headers.get("x-client-ip");
  if (customClientIp && typeof customClientIp === "string") {
    const clean = customClientIp.trim();
    if (clean && clean !== "127.0.0.1" && clean !== "::1") {
      return clean;
    }
  }

  // 3. Cloudflare / Edge proxy headers
  const cfIp = req.headers.get("cf-connecting-ip");
  if (cfIp && typeof cfIp === "string" && cfIp.trim() !== "127.0.0.1" && cfIp.trim() !== "::1") {
    return cfIp.trim();
  }

  // 4. Nginx / reverse proxy headers
  const realIp = req.headers.get("x-real-ip");
  if (realIp && typeof realIp === "string" && realIp.trim() !== "127.0.0.1" && realIp.trim() !== "::1") {
    return realIp.trim();
  }

  // 5. Standard Forwarded header chain
  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) {
    const firstIp = forwarded.split(",")[0].trim();
    // If a non-loopback IP was forwarded (e.g. In unit tests or production edge), use it
    if (firstIp && firstIp !== "127.0.0.1" && firstIp !== "::1") {
      return firstIp;
    }
    // If it's a test environment where x-forwarded-for was explicitly provided (even 127.0.0.1)
    if (process.env.NODE_ENV === "test") {
      return firstIp || "127.0.0.1";
    }
  }

  // In test runners without network/mocked environment, stay on 127.0.0.1
  if (process.env.NODE_ENV === "test") {
    return "127.0.0.1";
  }

  // 6. In local development or standalone server, resolve the real public IP
  return await getRealPublicIp();
}
