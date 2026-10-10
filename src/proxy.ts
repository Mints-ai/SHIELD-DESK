import { NextRequest, NextResponse } from "next/server";

/**
 * ShieldDesk Edge Proxy (Next.js 16)
 *
 * Enforces production security gates:
 * 1. Enterprise Subdomain Routing: Maps subdomains (api., status., trust., portal.) to route boundaries.
 * 2. Header Spoofing Resistance: Strips untrusted identity headers (X-ShieldDesk-User, X-Tenant-ID)
 *    from unauthenticated external traffic in production.
 * 3. Unauthenticated Route Protection: Redirects public visitors to /login when attempting
 *    to access protected SOC dashboards without a valid session.
 * 4. Security Headers: Applies strict edge security headers to all responses.
 */

const PUBLIC_EXACT_PATHS = new Set([
  "/login",
  "/onboarding",
  "/favicon.ico",
  "/logo.png",
  "/shielddesk-logo.png",
  "/robots.txt",
  "/sitemap.xml",
]);

const PUBLIC_PATH_PREFIXES = [
  "/api/auth/",
  "/api/health",
  "/api/ingest/",
  "/api/agent/",
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

  // 1. Enterprise Subdomain Routing
  if (hostname.startsWith("api.")) {
    if (!url.pathname.startsWith("/api")) {
      url.pathname = `/api${url.pathname}`;
      return NextResponse.rewrite(url);
    }
  } else if (hostname.startsWith("status.")) {
    if (url.pathname === "/") {
      url.pathname = "/api/health";
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

  // 4. Protected route verification in production
  if (isProd && !isPublicRoute(pathname) && !hasSession) {
    // If it's an API route, return 401 Unauthorized
    if (pathname.startsWith("/api/")) {
      return NextResponse.json(
        { error: "Unauthorized: Active session required for this resource." },
        { status: 401 }
      );
    }

    // For web dashboard / root pages, redirect to login
    const loginUrl = new URL("/login", req.url);
    if (pathname !== "/") {
      loginUrl.searchParams.set("redirect", pathname);
    }
    return NextResponse.redirect(loginUrl);
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
     * - favicon.ico, favicon/, logo.png, shielddesk-logo.png (public images/icons)
     */
    "/((?!_next/static|_next/image|favicon.ico|favicon|logo.png|shielddesk-logo.png).*)",
  ],
};

