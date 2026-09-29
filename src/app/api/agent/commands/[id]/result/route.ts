import { NextRequest, NextResponse } from "next/server";
import { recordCommandResult } from "@/lib/fleet/fleet";
import { trackError } from "@/lib/observability/errorTracker";

/**
 * POST /api/agent/commands/:id/result
 * Receives the command execution result, output, and optional safety snapshot ID from the endpoint agent.
 * Updates the command state to 'executed', 'failed', or 'rolled_back' and appends to the audit hash chain.
 */
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const body = await req.json();

    const { status, output = "", snapshotId, verified } = body;
    const agentId = body.agentId || req.headers.get("x-shielddesk-agent-id") || undefined;

    const validStatuses = ["executed", "succeeded", "failed", "rolled_back", "verified", "acknowledged", "executing"];
    if (!status || !validStatuses.includes(status)) {
      return NextResponse.json(
        { error: "Valid status ('executed', 'succeeded', 'failed', 'rolled_back', 'verified', 'acknowledged', 'executing') is required" },
        { status: 400 }
      );
    }
    const normalizedStatus = status === "succeeded" ? "executed" : status;

    const res = await recordCommandResult({
      commandId: id,
      status: normalizedStatus as "executed" | "failed" | "rolled_back" | "verified" | "acknowledged" | "executing",
      output: typeof output === "string" ? output : JSON.stringify(output),
      snapshotId: typeof snapshotId === "string" ? snapshotId : undefined,
      agentId,
      verified: Boolean(verified),
    });

    if (res.notFound) {
      return NextResponse.json({ error: "Command not found" }, { status: 404 });
    }

    if (res.unauthorized) {
      return NextResponse.json(
        { error: "Forbidden: Command does not belong to reporting agent" },
        { status: 403 }
      );
    }

    return NextResponse.json({ success: true, commandId: id, status });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/agent/commands/[id]/result" });
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
