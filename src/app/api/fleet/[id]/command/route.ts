import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { executeAgentCommand } from "@/lib/fleet/fleet";

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const caller = await getSessionUser(req);
    const { id } = await params;
    const body = await req.json();

    const { command, tier = "Tier 1", tokenId } = body;

    if (!command || typeof command !== "string") {
      return NextResponse.json(
        { error: "command is required" },
        { status: 400 }
      );
    }

    const result = await executeAgentCommand({
      agentId: id,
      command,
      tier,
      tokenId,
      caller,
    });

    return NextResponse.json(result);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal error";
    if (msg.includes("AGENT_NOT_FOUND")) {
      return NextResponse.json({ error: "Endpoint agent not found" }, { status: 404 });
    }
    if (msg.includes("APPROVAL_TOKEN_REQUIRED") || msg.includes("APPROVAL_TOKEN_NOT_APPROVED") || msg.includes("APPROVAL_TOKEN_EXPIRED")) {
      return NextResponse.json({ error: msg }, { status: 403 });
    }
    if (msg.includes("KILL_SWITCH_ACTIVE")) {
      return NextResponse.json({ error: msg }, { status: 423 }); // Locked
    }
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
