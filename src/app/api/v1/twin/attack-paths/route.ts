import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { AttackPathEngine } from "@/lib/attack-path/engine";

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

    const maxDepthParam = searchParams.get("maxDepth");
    const maxDepth = maxDepthParam ? Math.min(10, Math.max(1, parseInt(maxDepthParam, 10))) : 6;

    const report = await AttackPathEngine.analyzeAttackPathsAsync(session.tenantId, targetAssetId.trim(), {
      maxDepth,
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

    const maxDepth = typeof body.maxDepth === "number" ? Math.min(10, Math.max(1, body.maxDepth)) : 6;

    const report = await AttackPathEngine.analyzeAttackPathsAsync(session.tenantId, targetAssetId.trim(), {
      maxDepth,
      persistReport: true,
    });

    return NextResponse.json(report, { status: 200 });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
