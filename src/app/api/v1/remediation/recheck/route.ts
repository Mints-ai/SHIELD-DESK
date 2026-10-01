import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { ContinuousRecheckService } from "@/lib/verification-engine/continuousRecheck";

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
    const status = searchParams.get("status") || undefined;
    const findingId = searchParams.get("findingId") || undefined;

    const schedules = await ContinuousRecheckService.getSchedules(session.tenantId, {
      status,
      findingId,
    });

    return NextResponse.json(
      { tenantId: session.tenantId, schedulesCount: schedules.length, schedules },
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
    const actionType = body.actionType || body.operation || "register";

    if (actionType === "audit") {
      const schedule = body.schedule;
      if (!schedule || !schedule.id || !schedule.checkSpec) {
        return NextResponse.json(
          { error: "Schedule object with id and checkSpec is required for audit action" },
          { status: 400 }
        );
      }
      const evidence = body.evidence || body.liveEvidence || {};
      const auditResult = await ContinuousRecheckService.auditSchedule(schedule, evidence);
      return NextResponse.json(auditResult, { status: 200 });
    }

    // Default: Register schedule
    if (!body.findingId || !body.assetId || !body.checkSpec) {
      return NextResponse.json(
        { error: "Missing required fields: findingId, assetId, and checkSpec" },
        { status: 400 }
      );
    }

    const schedule = await ContinuousRecheckService.registerSchedule({
      tenantId: session.tenantId,
      findingId: body.findingId,
      assetId: body.assetId,
      action: body.action || "continuous_verification",
      checkSpec: body.checkSpec,
      frequencyHours: body.frequencyHours || 24,
    });

    return NextResponse.json(schedule, { status: 201 });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
