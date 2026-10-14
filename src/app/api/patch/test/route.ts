import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { hasPermission } from "@/lib/permissions";
import { isDevPersonaAllowed } from "@/lib/config/environment";

const ORCHESTRATOR_URL = process.env.PATCH_ORCHESTRATOR_URL || "http://localhost:8006";

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization,X-ShieldDesk-User",
  };
}

/** POST /api/patch/test — pre-flight test SSH connection and public key authentication */
export async function POST(req: NextRequest) {
  let session = await getSessionFromRequest(req);
  if (!session && isDevPersonaAllowed()) {
    session = {
      uid: "dev-analyst",
      role: "analyst",
      tenantId: "acme-tenant",
      email: "analyst@acme.corp",
    };
  }
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!hasPermission(session.role, "cve.read")) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  try {
    const res = await fetch(`${ORCHESTRATOR_URL}/api/v1/ssh/test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15000),
    });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status, headers: corsHeaders() });
  } catch (err: any) {
    return NextResponse.json(
      {
        connected: false,
        error_class: "ORCHESTRATOR_OFFLINE",
        error: "SSH Patch Orchestrator daemon is unreachable on port 8006.",
        diagnostic_hint: "The local Go orchestrator microservice is not active on port 8006.",
        remediation_steps: [
          "Start the Go orchestrator: cd ssh-patch-orchestrator && go run cmd/orchestrator/*.go",
          "Verify the daemon is listening: Test-NetConnection -Port 8006 -ComputerName localhost",
        ],
      },
      { status: 503, headers: corsHeaders() }
    );
  }
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: corsHeaders() });
}
