import { NextRequest, NextResponse } from "next/server";
import { isIpBlocked } from "@/lib/alerts/threatAlertStore";

/**
 * ShieldDesk Edge Proxy (Next.js 16)
 *
 * Enforces production security gates:
 * 0. Edge IP Banning & Containment: Drop all inbound requests (Web & API) from blocked IPs.
 * 1. Enterprise Subdomain Routing: Maps subdomains (api., status., trust., portal.) to route boundaries.
 * 2. Header Spoofing Resistance: Strips untrusted identity headers (X-ShieldDesk-User, X-Tenant-ID)
 *    from unauthenticated external traffic in production.
 * 3. Unauthenticated Route Protection: Redirects public visitors to /login when attempting
 *    to access protected SOC dashboards without a valid session.
 * 4. Security Headers: Applies strict edge security headers to all responses.
 */

function resolveRequestIp(req: NextRequest): string {
  const headers = [
    "x-client-ip",
    "cf-connecting-ip",
    "x-real-ip",
    "true-client-ip",
    "x-cluster-client-ip",
  ];
  for (const h of headers) {
    const val = req.headers.get(h);
    if (val) {
      let clean = val.split(",")[0].trim();
      if (clean.startsWith("::ffff:")) clean = clean.replace("::ffff:", "");
      if (clean && clean !== "127.0.0.1" && clean !== "::1") return clean;
    }
  }

  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) {
    let firstIp = forwarded.split(",")[0].trim();
    if (firstIp.startsWith("::ffff:")) firstIp = firstIp.replace("::ffff:", "");
    if (firstIp && firstIp !== "127.0.0.1" && firstIp !== "::1") return firstIp;
    if (process.env.NODE_ENV === "test" && firstIp) return firstIp;
  }

  let directIp = (req as unknown as { ip?: string }).ip;
  if (directIp) {
    if (directIp.startsWith("::ffff:")) directIp = directIp.replace("::ffff:", "");
    if (directIp !== "127.0.0.1" && directIp !== "::1") return directIp;
  }

  return "127.0.0.1";
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function renderIpBanHtml(clientIp: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>403 Forbidden — IP Access Banned | ShieldDesk SOC</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: #070a0e;
      color: #e2e8f0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
      position: relative;
      overflow-x: hidden;
    }
    .background-grid {
      position: absolute;
      inset: 0;
      background-image: 
        linear-gradient(to right, rgba(239, 68, 68, 0.05) 1px, transparent 1px),
        linear-gradient(to bottom, rgba(239, 68, 68, 0.05) 1px, transparent 1px);
      background-size: 40px 40px;
      pointer-events: none;
    }
    .glow-radial {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      width: 600px;
      height: 600px;
      background: radial-gradient(circle, rgba(239, 68, 68, 0.12) 0%, transparent 70%);
      pointer-events: none;
    }
    .card {
      position: relative;
      width: 100%;
      max-width: 540px;
      background: #0d1219;
      border: 1px solid rgba(239, 68, 68, 0.35);
      border-radius: 20px;
      padding: 36px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 40px -10px rgba(239, 68, 68, 0.25);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 12px;
      border-radius: 9999px;
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.3);
      color: #f87171;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      margin-bottom: 20px;
    }
    .badge-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #ef4444;
      box-shadow: 0 0 8px #ef4444;
    }
    .icon-container {
      width: 56px;
      height: 56px;
      border-radius: 14px;
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.25);
      display: flex;
      align-items: center;
      justify-content: center;
      margin-bottom: 20px;
      color: #ef4444;
    }
    h1 {
      font-size: 22px;
      font-weight: 700;
      color: #ffffff;
      letter-spacing: -0.02em;
      margin-bottom: 10px;
    }
    p.lead {
      font-size: 14px;
      line-height: 1.6;
      color: #94a3b8;
      margin-bottom: 24px;
    }
    .metadata-box {
      background: #080c12;
      border: 1px solid #1e293b;
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 24px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
    }
    .metadata-row {
      display: flex;
      justify-content: space-between;
      padding: 6px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    }
    .metadata-row:last-child {
      border-bottom: none;
    }
    .metadata-label {
      color: #64748b;
    }
    .metadata-val {
      color: #f1f5f9;
      font-weight: 600;
    }
    .metadata-val.danger {
      color: #ef4444;
    }
    .guidance {
      font-size: 12px;
      color: #64748b;
      line-height: 1.5;
      padding-top: 8px;
      border-top: 1px solid #1e293b;
    }
    .guidance strong {
      color: #cbd5e1;
    }
  </style>
</head>
<body>
  <div class="background-grid"></div>
  <div class="glow-radial"></div>
  <div class="card">
    <div class="badge">
      <span class="badge-dot"></span>
      Security Quarantine Active
    </div>
    <div class="icon-container">
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <line x1="12" y1="8" x2="12" y2="12"/>
        <line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
    </div>
    <h1>IP Access Banned by SOC Policy</h1>
    <p class="lead">
      Inbound traffic from this IP address has been terminated by ShieldDesk autonomous threat containment. All web dashboard access, API operations, and endpoint communications from this origin are blocked.
    </p>
    <div class="metadata-box">
      <div class="metadata-row">
        <span class="metadata-label">Blocked IP Address</span>
        <span class="metadata-val danger">${escapeHtml(clientIp)}</span>
      </div>
      <div class="metadata-row">
        <span class="metadata-label">Enforcement Point</span>
        <span class="metadata-val">Edge Proxy / Zero-Trust Gateway</span>
      </div>
      <div class="metadata-row">
        <span class="metadata-label">Action</span>
        <span class="metadata-val danger">DROP (403 Forbidden)</span>
      </div>
      <div class="metadata-row">
        <span class="metadata-label">Status</span>
        <span class="metadata-val danger">TERMINATED</span>
      </div>
    </div>
    <div class="guidance">
      <strong>Next Steps:</strong> If you believe this host was contained in error, contact your SOC Security Operations Administrator to lift the containment rule via <code>unblock_ip</code> from an authorized administrative console.
    </div>
  </div>
</body>
</html>`;
}

const PUBLIC_EXACT_PATHS = new Set([
  "/login",
  "/signup",
  "/onboarding",
  "/pricing",
  "/status",
  "/docs",
  "/favicon.ico",
  "/logo.png",
  "/shielddesk-logo.png",
  "/shield-emblem.png",
  "/robots.txt",
  "/sitemap.xml",
  // Payment providers authenticate here through the handler's signature checks.
  "/api/billing/webhook",
]);

const PUBLIC_PATH_PREFIXES = [
  "/api/auth/",
  "/api/health",
  "/api/status",
  "/api/docs",
  "/docs/",
  "/dashboard/integrations",
  "/api/integrations",
  "/api/fleet/enrollment-tokens",
  "/api/ingest/",
  "/api/agent/",
  "/api/v1/plans",
  "/checkout/",
  "/_next/",
  "/favicon/",
  "/monitoring",
];

function isPublicRoute(pathname: string): boolean {
  if (PUBLIC_EXACT_PATHS.has(pathname)) return true;
  for (const prefix of PUBLIC_PATH_PREFIXES) {
    if (pathname.startsWith(prefix)) return true;
  }
  return false;
}

export function proxy(req: NextRequest) {
  const hostname = req.headers.get("host") || "";
  const url = req.nextUrl.clone();
  const { pathname } = req.nextUrl;

  // 0. Edge IP Containment & Ban Guard: Block all inbound traffic from quarantined IPs
  const clientIp = resolveRequestIp(req);
  if (clientIp && isIpBlocked(clientIp)) {
    // Allow authenticated system administrators to access unblock routes
    const isUnblockPath =
      (pathname === "/api/threats" ||
        pathname === "/api/fleet/execute" ||
        pathname === "/api/fleet/blocked-ips" ||
        pathname === "/api/fleet/logs" ||
        pathname === "/api/fleet") &&
      req.method === "POST";

    const devUserHeader = req.headers.get("x-shielddesk-user");
    const isDevAdmin = devUserHeader === "dev-admin" || devUserHeader === "dev-super";
    const hasAdminSession = isDevAdmin || Boolean(
      req.cookies.get("shielddesk_session")?.value || req.headers.get("authorization")
    );

    // If local loopback is blocked (dev testing), only allow SOC admin operators on /dashboard/fleet to manage containment
    const isLocalLoopback = clientIp === "127.0.0.1" || clientIp === "::1" || clientIp === "localhost";
    const isSocFleetConsole = isLocalLoopback && isDevAdmin && (pathname.startsWith("/dashboard/fleet") || pathname.startsWith("/api/fleet"));

    if (!(isUnblockPath && hasAdminSession) && !isSocFleetConsole) {
      const isApi =
        pathname.startsWith("/api/") ||
        req.headers.get("accept")?.includes("application/json");

      if (isApi) {
        return NextResponse.json(
          {
            error: "IP_BANNED",
            message: `Access Denied: Your IP address (${clientIp}) has been quarantined by ShieldDesk SOC Security Policy. All inbound traffic is terminated.`,
            blocked: true,
            clientIp,
          },
          {
            status: 403,
            headers: {
              "X-ShieldDesk-Blocked": "true",
              "X-Content-Type-Options": "nosniff",
              "Set-Cookie": "shielddesk_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
            },
          }
        );
      }

      return new NextResponse(renderIpBanHtml(clientIp), {
        status: 403,
        headers: {
          "content-type": "text/html; charset=utf-8",
          "X-ShieldDesk-Blocked": "true",
          "X-Content-Type-Options": "nosniff",
          "Set-Cookie": "shielddesk_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
        },
      });
    }
  }

  // 1. Enterprise Subdomain Routing
  if (hostname.startsWith("api.")) {
    if (!url.pathname.startsWith("/api")) {
      url.pathname = `/api${url.pathname}`;
      return NextResponse.rewrite(url);
    }
  } else if (hostname.startsWith("status.")) {
    if (url.pathname === "/") {
      url.pathname = "/status";
      return NextResponse.rewrite(url);
    }
  } else if (hostname.startsWith("trust.")) {
    if (url.pathname === "/") {
      url.pathname = "/compliance";
      return NextResponse.rewrite(url);
    }
  } else if (hostname.startsWith("portal.")) {
    if (url.pathname === "/") {
      url.pathname = "/settings/billing";
      return NextResponse.rewrite(url);
    }
  }

  const isProd =
    process.env.NODE_ENV === "production" || process.env.APP_ENV === "production";
  const isDemo = process.env.DEMO_MODE !== "false" && !isProd;

  // 2. Prepare sanitized request headers
  const requestHeaders = new Headers(req.headers);

  // In production (or when demo mode is inactive), strip external spoofed headers
  if (isProd || !isDemo) {
    requestHeaders.delete("x-shielddesk-user");
    requestHeaders.delete("x-tenant-id");
  }

  // 3. Check for active session (Cookie or Bearer token)
  const sessionCookie = req.cookies.get("shielddesk_session")?.value;
  const authHeader = req.headers.get("authorization");
  const hasSession = Boolean(sessionCookie || authHeader);

  // 4. Protected route verification (Redirect unauthenticated visitors to /login)
  if (!isPublicRoute(pathname) && !hasSession) {
    // If it's an API route, return 401 Unauthorized in production
    if (pathname.startsWith("/api/")) {
      if (isProd) {
        return NextResponse.json(
          { error: "Unauthorized: Active session required for this resource." },
          { status: 401 }
        );
      }
    } else {
      // For web dashboard / root pages, redirect unauthenticated users to login
      const loginUrl = new URL("/login", req.url);
      if (pathname !== "/") {
        loginUrl.searchParams.set("redirect", pathname);
      }
      return NextResponse.redirect(loginUrl);
    }
  }

  // 5. Create response with sanitized request headers
  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });

  // 6. Apply defense-in-depth security response headers
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set("X-XSS-Protection", "1; mode=block");
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), browsing-topics=()"
  );

  return response;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico, favicon/, logo.png, shielddesk-logo.png, shield-emblem.png (public images/icons)
     */
    "/((?!_next/static|_next/image|favicon.ico|favicon|logo.png|shielddesk-logo.png|shield-emblem.png).*)",
  ],
};

export default proxy;


