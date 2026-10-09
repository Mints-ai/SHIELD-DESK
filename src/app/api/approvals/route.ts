import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { listApprovalTokens, requestApprovalToken } from "@/lib/governance/approvalTokens";
import { trackError } from "@/lib/observability/errorTracker";

export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const { searchParams } = new URL(req.url);
    const status = searchParams.get("status") || undefined;
    const taskId = searchParams.get("taskId") || undefined;

    const result = await listApprovalTokens(session, { status, taskId });
    return NextResponse.json(result);
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/approvals", userId: session.uid, tenantId: session.tenantId });
    return NextResponse.json({ error: "Failed to list approval tokens" }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const body = await req.json();
    const result = await requestApprovalToken(session, {
      taskId: body.taskId,
      actionType: body.actionType,
      blastRadius: body.blastRadius,
      cveScore: body.cveScore,
      tier: body.tier,
    });

    if ("error" in result) {
      const status = result.error === "task_not_found" ? 404 : 400;
      return NextResponse.json(result, { status });
    }

    return NextResponse.json(result, { status: 201 });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/approvals", userId: session.uid, tenantId: session.tenantId });
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }
}
