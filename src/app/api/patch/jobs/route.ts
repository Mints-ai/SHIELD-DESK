import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { hasPermission } from "@/lib/permissions";

const ORCHESTRATOR_URL = process.env.PATCH_ORCHESTRATOR_URL || "http://localhost:8004";

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization,X-ShieldDesk-User",
  };
}

/** GET /api/patch/jobs — list all jobs */
export async function GET(req: NextRequest) {
  const session = await getSessionFromRequest(req);
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (!hasPermission(session.role, "cve.read")) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  try {
    const res = await fetch(`${ORCHESTRATOR_URL}/api/v1/jobs`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      return NextResponse.json({ error: "Orchestrator error", status: res.status }, { status: 502 });
    }
    const data = await res.json();
    return NextResponse.json(data, { headers: corsHeaders() });
  } catch (err: any) {
    return NextResponse.json(
      { error: "SSH Patch Orchestrator is offline. Start it with: orchestrator.exe server", offline: true },
      { status: 503, headers: corsHeaders() }
    );
  }
}

/** POST /api/patch/jobs — create a new patch job */
export async function POST(req: NextRequest) {
  const session = await getSessionFromRequest(req);
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
    const res = await fetch(`${ORCHESTRATOR_URL}/api/v1/jobs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status, headers: corsHeaders() });
  } catch (err: any) {
    return NextResponse.json(
      { error: "SSH Patch Orchestrator is offline. Make sure it is running on port 8004.", offline: true },
      { status: 503, headers: corsHeaders() }
    );
  }
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: corsHeaders() });
}
