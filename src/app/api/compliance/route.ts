import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { getComplianceSummary, exportAuditEvidencePackage } from "@/lib/compliance/iso27001";
import { trackError } from "@/lib/observability/errorTracker";

export async function GET(req: NextRequest) {
  try {
    const caller = await getSessionUser(req);
    if (!caller) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const url = new URL(req.url);
    const isExport = url.searchParams.get("export") === "true";

    if (isExport) {
      const evidence = await exportAuditEvidencePackage(caller);
      return NextResponse.json(evidence);
    }

    const summary = await getComplianceSummary(caller);
    return NextResponse.json(summary);
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/compliance" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
