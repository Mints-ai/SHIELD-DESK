import { NextRequest, NextResponse } from "next/server";
import { ExecutionBroker } from "@/lib/fleet/executionBroker";
import { SignedAgentResultPayload } from "@/lib/fleet/agentResultVerifier";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const {
      commandId,
      agentId,
      tenantId,
      exitCode,
      stdout,
      stderr,
      executionTimestamp,
      hostStateDigest,
      resultSignature,
    } = body;

    if (!commandId || !agentId || typeof exitCode !== "number" || !resultSignature) {
      return NextResponse.json(
        { error: "Missing required execution result parameters (commandId, agentId, exitCode, resultSignature)" },
        { status: 400 }
      );
    }

    const payload: SignedAgentResultPayload = {
      commandId,
      agentId,
      tenantId: tenantId || "acme-tenant",
      exitCode,
      stdout: stdout || "",
      stderr: stderr || "",
      executionTimestamp: executionTimestamp || new Date().toISOString(),
      hostStateDigest: hostStateDigest || "",
      resultSignature,
    };

    const result = await ExecutionBroker.processSignedAgentResult(payload, { allowTestKey: process.env.NODE_ENV === "test" });

    if (!result.success && result.reason) {
      return NextResponse.json({ error: result.reason, state: result.state }, { status: 401 });
    }

    return NextResponse.json(
      {
        success: result.success,
        state: result.state,
        commandId,
      },
      { status: 200 }
    );
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
