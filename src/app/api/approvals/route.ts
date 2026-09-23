import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { listApprovalTokens, requestApprovalToken } from "@/lib/governance/approvalTokens";

export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { searchParams } = new URL(req.url);
  const status = searchParams.get("status") || undefined;
  const taskId = searchParams.get("taskId") || undefined;

  const result = await listApprovalTokens(session, { status, taskId });
  return NextResponse.json(result);
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
    });

    if ("error" in result) {
      return NextResponse.json(result, { status: 400 });
    }

    return NextResponse.json(result, { status: 201 });
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }
}
