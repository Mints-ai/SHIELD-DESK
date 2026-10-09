import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { exportAuditEvidencePackage } from "@/lib/compliance/iso27001";
import {
  getFrameworkCompliance,
  FrameworkId,
} from "@/lib/compliance/frameworks";
import { AuditExportGenerator } from "@/lib/compliance/exportGenerator";
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
    const frameworkParam = url.searchParams.get("framework") as FrameworkId | null;

    if (isExport) {
      const format = url.searchParams.get("format") === "csv" ? "csv" : "json";
      const isLegacy = url.searchParams.get("legacy") === "true";

      if (isLegacy && format === "json") {
        const evidence = await exportAuditEvidencePackage(caller);
        return NextResponse.json(evidence);
      }

      const bundle = await AuditExportGenerator.generateBundle({
        tenantId: caller.tenant_id,
        exportedBy: caller.id,
        format,
        limit: url.searchParams.get("limit") ? parseInt(url.searchParams.get("limit")!, 10) : undefined,
        startDate: url.searchParams.get("startDate") || undefined,
        endDate: url.searchParams.get("endDate") || undefined,
      });

      return new NextResponse(bundle.data, {
        status: 200,
        headers: bundle.headers,
      });
    }

    const frameworkData = await getFrameworkCompliance(caller, frameworkParam || "iso27001");
    return NextResponse.json(frameworkData);
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/compliance" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
