import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { runLiveComplianceScan } from "@/lib/compliance/scanner";
import { trackError } from "@/lib/observability/errorTracker";

export async function POST(req: NextRequest) {
  try {
    const caller = await getSessionUser(req);
    if (!caller) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const scan = await runLiveComplianceScan(caller);
    return NextResponse.json({
      success: true,
      scan,
      report: scan,
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/compliance/scan" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
