import { NextRequest, NextResponse } from "next/server";
import { recordCommandResult } from "@/lib/fleet/fleet";

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

    const { status, output = "", snapshotId } = body;

    if (!status || !["executed", "failed", "rolled_back"].includes(status)) {
      return NextResponse.json(
        { error: "Valid status ('executed', 'failed', 'rolled_back') is required" },
        { status: 400 }
      );
    }

    await recordCommandResult({
      commandId: id,
      status,
      output: typeof output === "string" ? output : JSON.stringify(output),
      snapshotId: typeof snapshotId === "string" ? snapshotId : undefined,
    });

    return NextResponse.json({ success: true, commandId: id, status });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal server error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
