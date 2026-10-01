import { NextRequest, NextResponse } from "next/server";
import { AgentUpdater } from "@/lib/fleet/agentUpdater";
import { getSessionFromRequest } from "@/lib/auth/session";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const platform = (searchParams.get("platform") as "linux_amd64" | "windows_amd64") || "linux_amd64";

    // Publish or retrieve default active release manifest
    const manifest = AgentUpdater.publishUpdateManifest({
      version: "1.4.0",
      platform,
      binaryUrl: `https://downloads.shielddesk.io/agent/v1.4.0/shielddesk-agent-${platform}.tar.gz`,
      sha256Checksum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      minAgentVersion: "1.0.0",
    });

    return NextResponse.json(manifest, { status: 200 });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const {
      agentId,
      tenantId,
      fromVersion,
      targetVersion,
      canarySuccessful,
      canaryLatencyMs,
      failureReason,
    } = body;

    if (!agentId || !targetVersion || typeof canarySuccessful !== "boolean") {
      return NextResponse.json(
        { error: "Missing required parameters (agentId, targetVersion, canarySuccessful)" },
        { status: 400 }
      );
    }

    const event = await AgentUpdater.processCanaryEvaluation({
      agentId,
      tenantId: tenantId || "acme-tenant",
      fromVersion: fromVersion || "1.3.0",
      targetVersion,
      canarySuccessful,
      canaryLatencyMs,
      failureReason,
    });

    return NextResponse.json(event, { status: 200 });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal Server Error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
