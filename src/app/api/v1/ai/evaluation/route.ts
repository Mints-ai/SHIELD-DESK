import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { AIEvaluationLab } from "@/lib/ai/evaluationLab";

export async function GET(request: NextRequest) {
  try {
    const session = await getSessionFromRequest(request);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const runs = await AIEvaluationLab.getEvaluationRuns(session.tenantId);
    const benchmarkDataset = await AIEvaluationLab.getBenchmarkDataset();

    return NextResponse.json(
      {
        tenantId: session.tenantId,
        benchmarkCasesCount: benchmarkDataset.length,
        evaluationRunsCount: runs.length,
        runs,
      },
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

    // High privilege check: only system_admin, super_admin, or analyst can trigger AI evaluation
    const privilegedRoles = ["system_admin", "super_admin", "analyst"];
    if (!privilegedRoles.includes(session.role)) {
      return NextResponse.json(
        { error: "Forbidden: AI Evaluation Lab runs require analyst or admin role" },
        { status: 403 }
      );
    }

    const body = await request.json().catch(() => ({}));
    const { provider, modelName, promptVersion } = body;

    const runResult = await AIEvaluationLab.runEvaluationSuite({
      tenantId: session.tenantId,
      runBy: session.uid,
      provider,
      modelName,
      promptVersion,
    });

    return NextResponse.json(runResult, { status: 200 });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
