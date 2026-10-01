import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { AuditExportGenerator } from "@/lib/compliance/exportGenerator";

export async function GET(request: NextRequest) {
  try {
    const session = await getSessionFromRequest(request);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    if (!canAccess(session.role, "incident.read") && !canAccess(session.role, "cve.read")) {
      return NextResponse.json({ error: "Forbidden: insufficient permissions" }, { status: 403 });
    }

    const { searchParams } = new URL(request.url);
    const format = searchParams.get("format") === "csv" ? "csv" : "json";
    const limit = searchParams.get("limit") ? parseInt(searchParams.get("limit")!, 10) : undefined;
    const startDate = searchParams.get("startDate") || undefined;
    const endDate = searchParams.get("endDate") || undefined;

    const bundle = await AuditExportGenerator.generateBundle({
      tenantId: session.tenantId,
      exportedBy: session.uid || session.email || "system",
      format,
      limit,
      startDate,
      endDate,
    });

    return new NextResponse(bundle.data, {
      status: 200,
      headers: bundle.headers,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
