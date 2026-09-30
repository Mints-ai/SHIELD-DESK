import { NextRequest, NextResponse } from "next/server";

export function middleware(request: NextRequest) {
  const hostname = request.headers.get("host") || "";
  const url = request.nextUrl.clone();

  // Phase 35: Enterprise Subdomain Routing
  // Maps shielddesk.com subdomains to their respective route boundaries
  if (hostname.startsWith("api.")) {
    // api.shielddesk.com: Direct to API namespace
    if (!url.pathname.startsWith("/api")) {
      url.pathname = `/api${url.pathname}`;
      return NextResponse.rewrite(url);
    }
  } else if (hostname.startsWith("status.")) {
    // status.shielddesk.com: Live health & availability probe
    if (url.pathname === "/") {
      url.pathname = "/api/health";
      return NextResponse.rewrite(url);
    }
  } else if (hostname.startsWith("trust.")) {
    // trust.shielddesk.com: Security & compliance trust center
    if (url.pathname === "/") {
      url.pathname = "/compliance";
      return NextResponse.rewrite(url);
    }
  } else if (hostname.startsWith("portal.")) {
    // portal.shielddesk.com: Customer account & billing portal
    if (url.pathname === "/") {
      url.pathname = "/settings/billing";
      return NextResponse.rewrite(url);
    }
  }

  // Security Headers for Production (Phase 45: Frontend Security)
  const response = NextResponse.next();
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), browsing-topics=()"
  );

  return response;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};
