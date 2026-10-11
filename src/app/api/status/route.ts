import { NextResponse } from "next/server";
import { getSystemStatusReport } from "@/lib/status/serviceStatus";

export const dynamic = "force-dynamic";

/**
 * GET /api/status
 *
 * Public Machine-Readable API Status Endpoint.
 * Reports real-time operational health, round-trip latency,
 * and component state across all ShieldDesk platform subsystems.
 */
export async function GET() {
  try {
    const report = await getSystemStatusReport();
    const httpStatus = report.status === "outage" ? 503 : 200;

    return NextResponse.json(report, {
      status: httpStatus,
      headers: {
        "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
        "X-ShieldDesk-Status": report.status,
      },
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Internal status probe error";
    return NextResponse.json(
      {
        status: "outage",
        version: "2.4.0",
        timestamp: new Date().toISOString(),
        error: errorMessage,
      },
      {
        status: 503,
        headers: {
          "Cache-Control": "no-store",
          "X-ShieldDesk-Status": "outage",
        },
      }
    );
  }
}
