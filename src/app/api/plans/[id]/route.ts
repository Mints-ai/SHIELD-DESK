import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { getMitigationPlan } from "@/lib/tools";
import { trackError } from "@/lib/observability/errorTracker";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;
  if (!id) {
    return NextResponse.json({ error: "missing_plan_id" }, { status: 400 });
  }

  try {
    const result = await getMitigationPlan(session, { planId: id });
    if ("error" in result) {
      const status = result.error === "not_found" ? 404 : 400;
      return NextResponse.json(result, { status });
    }

    return NextResponse.json(result);
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/plans/[id]", userId: session.uid, tenantId: session.tenantId });
    return NextResponse.json({ error: "Failed to retrieve mitigation plan" }, { status: 500 });
  }
}
