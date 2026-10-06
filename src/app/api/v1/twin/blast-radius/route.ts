import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { BlastRadiusEngine } from "@/lib/blast-radius/engine";

export async function GET(request: NextRequest) {
  try {
    const session = await getSessionFromRequest(request);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    if (!canAccess(session.role, "incident.investigate")) {
      return NextResponse.json({ error: "Forbidden: insufficient permissions" }, { status: 403 });
    }

    const { searchParams } = new URL(request.url);
    const targetAssetId = searchParams.get("targetAssetId");
    if (!targetAssetId || typeof targetAssetId !== "string" || targetAssetId.trim().length === 0) {
      return NextResponse.json({ error: "targetAssetId query parameter is required" }, { status: 400 });
    }

    const action = searchParams.get("action") || "isolate_host";

    const report = await BlastRadiusEngine.calculateBlastRadiusAsync(session.tenantId, targetAssetId.trim(), action, {
      persistReport: true,
    });

    return NextResponse.json(report, { status: 200 });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const session = await getSessionFromRequest(request);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    if (!canAccess(session.role, "incident.investigate")) {
      return NextResponse.json({ error: "Forbidden: insufficient permissions" }, { status: 403 });
    }

    const body = await request.json().catch(() => ({}));
    const targetAssetId = body.targetAssetId;
    if (!targetAssetId || typeof targetAssetId !== "string" || targetAssetId.trim().length === 0) {
      return NextResponse.json({ error: "targetAssetId string field is required" }, { status: 400 });
    }

    const action = typeof body.action === "string" && body.action.trim().length > 0 ? body.action.trim() : "isolate_host";

    const report = await BlastRadiusEngine.calculateBlastRadiusAsync(session.tenantId, targetAssetId.trim(), action, {
      persistReport: true,
    });

    return NextResponse.json(report, { status: 200 });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
