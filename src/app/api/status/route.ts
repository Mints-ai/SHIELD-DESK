import { NextRequest, NextResponse } from "next/server";
import { getSystemStatusReport } from "@/lib/status/serviceStatus";

export const dynamic = "force-dynamic";

/**
 * GET /api/status
 *
 * Public Telemetry & Status API Endpoint.
 * - When requested from a web browser (Accept: text/html), seamlessly redirects to the /status UI.
 * - When requested via curl, monitoring agents, or with ?format=json, returns indented JSON telemetry.
 */
export async function GET(req?: NextRequest) {
  const acceptHeader = req?.headers?.get("accept") || "";
  const format = req?.nextUrl?.searchParams?.get("format");

  // Browser navigation -> redirect to full ShieldDesk Status UI
  if (acceptHeader.includes("text/html") && format !== "json" && req?.url) {
    return NextResponse.redirect(new URL("/status", req.url));
  }

  try {
    const report = await getSystemStatusReport();
    const httpStatus = report.status === "outage" ? 503 : 200;

    return new Response(JSON.stringify(report, null, 2), {
      status: httpStatus,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
        "X-ShieldDesk-Status": report.status,
      },
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Internal status probe error";
    return new Response(
      JSON.stringify(
        {
          status: "outage",
          version: "2.4.0",
          timestamp: new Date().toISOString(),
          error: errorMessage,
        },
        null,
        2
      ),
      {
        status: 503,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
          "X-ShieldDesk-Status": "outage",
        },
      }
    );
  }
}
