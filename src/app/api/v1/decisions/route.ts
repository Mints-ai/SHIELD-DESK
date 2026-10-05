import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { DecisionEngine } from "@/lib/decision-engine/engine";
import { DecisionInput } from "@/lib/decision-engine/types";

export async function GET(request: NextRequest) {
  try {
    const session = await getSessionFromRequest(request);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    if (!canAccess(session.role, "incident.investigate") && !canAccess(session.role, "incident.read")) {
      return NextResponse.json({ error: "Forbidden: insufficient permissions" }, { status: 403 });
    }

    const { searchParams } = new URL(request.url);
    const id = searchParams.get("id");
    const assetId = searchParams.get("assetId") || undefined;
    const decision = searchParams.get("decision") || undefined;
    const limit = searchParams.get("limit") ? parseInt(searchParams.get("limit")!, 10) : 50;

    if (id) {
      const record = await DecisionEngine.getDecisionRecord(session.tenantId, id);
      if (!record) {
        return NextResponse.json({ error: "Decision record not found" }, { status: 404 });
      }
      return NextResponse.json(record, { status: 200 });
    }

    const records = await DecisionEngine.listDecisionRecords(session.tenantId, {
      limit,
      assetId,
      decision,
    });

    return NextResponse.json({ tenantId: session.tenantId, recordsCount: records.length, records }, { status: 200 });
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
    if (!canAccess(session.role, "incident.investigate") && !canAccess(session.role, "incident.mitigate")) {
      return NextResponse.json({ error: "Forbidden: insufficient permissions" }, { status: 403 });
    }

    const body = await request.json().catch(() => ({}));
    if (!body.action || typeof body.action !== "string") {
      return NextResponse.json({ error: "action string field is required" }, { status: 400 });
    }

    const decisionInput: DecisionInput = {
      tenantId: session.tenantId, // Strictly scoped to session tenant
      incidentId: body.incidentId,
      assetId: body.assetId,
      assetType: body.assetType,
      hostname: body.hostname,
      assetCriticality: body.assetCriticality,
      action: body.action,
      evidence: Array.isArray(body.evidence) ? body.evidence : [],
      risk: body.risk,
      blastRadius: body.blastRadius,
      policy: body.policy,
      autonomyMode: body.autonomyMode,
      assetAutonomyMode: body.assetAutonomyMode,
      aiConfidence: typeof body.aiConfidence === "number" ? body.aiConfidence : undefined,
      actor: {
        id: session.uid || session.email || "usr-anonymous",
        role: session.role,
        tenantId: session.tenantId,
        mfaVerified: false,
      },
    };

    const decisionOutput = await DecisionEngine.evaluate(decisionInput);

    // Persist decision record to PostgreSQL
    await DecisionEngine.persistDecisionRecord(decisionOutput, {
      userId: decisionInput.actor.id,
      role: decisionInput.actor.role,
      tenantId: decisionInput.actor.tenantId,
    });

    return NextResponse.json(decisionOutput, { status: 200 });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
