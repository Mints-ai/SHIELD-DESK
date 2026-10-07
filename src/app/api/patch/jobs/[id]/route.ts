import { NextRequest, NextResponse } from "next/server";
import { getSessionFromRequest } from "@/lib/auth/session";
import { hasPermission } from "@/lib/permissions";
import { isDevPersonaAllowed } from "@/lib/config/environment";

const ORCHESTRATOR_URL = process.env.PATCH_ORCHESTRATOR_URL || "http://localhost:8004";

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization,X-ShieldDesk-User",
  };
}

/** GET /api/patch/jobs/[id] — get job status + logs */
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
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

  const { id } = await params;

  try {
    const res = await fetch(`${ORCHESTRATOR_URL}/api/v1/jobs/${id}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      return NextResponse.json({ error: "Job not found" }, { status: res.status });
    }
    const data = await res.json();
    return NextResponse.json(data, { headers: corsHeaders() });
  } catch {
    return NextResponse.json(
      { error: "SSH Patch Orchestrator is offline", offline: true },
      { status: 503, headers: corsHeaders() }
    );
  }
}

/** POST /api/patch/jobs/[id]/rollback — trigger manual rollback */
export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
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

  const { id } = await params;
  const url = new URL(req.url);
  const isRollback = url.pathname.endsWith("/rollback");

  const endpoint = isRollback
    ? `${ORCHESTRATOR_URL}/api/v1/jobs/${id}/rollback`
    : `${ORCHESTRATOR_URL}/api/v1/jobs/${id}`;

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(10000),
    });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status, headers: corsHeaders() });
  } catch {
    return NextResponse.json(
      { error: "SSH Patch Orchestrator is offline", offline: true },
      { status: 503, headers: corsHeaders() }
    );
  }
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: corsHeaders() });
}
