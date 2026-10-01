import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { VerificationEngine } from "@/lib/verification-engine/engine";
import { VerificationPlan } from "@/lib/verification-engine/types";

export async function GET(request: NextRequest) {
  try {
    const session = await getSessionFromRequest(request);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    if (!canAccess(session.role, "incident.read") && !canAccess(session.role, "incident.investigate")) {
      return NextResponse.json({ error: "Forbidden: insufficient permissions" }, { status: 403 });
    }

    const { searchParams } = new URL(request.url);
    const agentId = searchParams.get("agentId") || undefined;
    const commandId = searchParams.get("commandId") || undefined;
    const status = searchParams.get("status") || undefined;
    const limit = searchParams.get("limit") ? parseInt(searchParams.get("limit")!, 10) : 50;

    const records = await VerificationEngine.getVerifications(session.tenantId, {
      agentId,
      commandId,
      status,
      limit,
    });

    return NextResponse.json(
      { tenantId: session.tenantId, verificationsCount: records.length, verifications: records },
      { status: 200 }
    );
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
    if (!canAccess(session.role, "incident.mitigate") && !canAccess(session.role, "incident.investigate")) {
      return NextResponse.json({ error: "Forbidden: insufficient permissions" }, { status: 403 });
    }

    const body = await request.json().catch(() => ({}));
    const evidence = body.evidence || body.actualHostEvidence || {};

    let plan: VerificationPlan;
    if (body.plan) {
      plan = {
        ...body.plan,
        tenantId: session.tenantId, // Guard strictly to session tenant
      };
    } else {
      if (!body.action || !body.agentId || !body.commandId) {
        return NextResponse.json(
          { error: "Missing required fields: action, agentId, and commandId (or plan object)" },
          { status: 400 }
        );
      }
      plan = VerificationEngine.createPlan({
        action: body.action,
        agentId: body.agentId,
        tenantId: session.tenantId,
        commandId: body.commandId,
        findingId: body.findingId,
        snapshotId: body.snapshotId,
        target: body.target,
        cveId: body.cveId,
        checks: body.checks,
      });
    }

    const verificationResult = await VerificationEngine.verify(plan, evidence);

    return NextResponse.json(verificationResult, { status: 200 });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
