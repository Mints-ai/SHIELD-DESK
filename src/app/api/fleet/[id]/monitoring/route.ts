import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { getEndpointAgent } from "@/lib/fleet/fleet";
import {
  getEndpointCoreFunctionsData,
  updateEndpointMonitoringPolicy,
  CoreFunctionScope,
} from "@/lib/fleet/monitoringPolicy";
import { trackError } from "@/lib/observability/errorTracker";

export const dynamic = "force-dynamic";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const caller = await getSessionUser(req);
    if (!caller) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const { id } = await params;
    const agent = await getEndpointAgent(id, caller);
    if (!agent) {
      return NextResponse.json({ error: "Endpoint agent not found" }, { status: 404 });
    }

    const result = await getEndpointCoreFunctionsData(agent.id, agent.tenant_id, agent.hostname);
    return NextResponse.json({ success: true, agentStatus: agent.status, ...result });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/fleet/[id]/monitoring" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const caller = await getSessionUser(req);
    if (!caller) {
      return NextResponse.json(
        { error: "Unauthorized: Valid authentication session required" },
        { status: 401 }
      );
    }

    const { id } = await params;
    const agent = await getEndpointAgent(id, caller);
    if (!agent) {
      return NextResponse.json({ error: "Endpoint agent not found" }, { status: 404 });
    }

    const body = await req.json().catch(() => ({}));
    const { requestedScopes, approvalTokenId } = body;

    if (!Array.isArray(requestedScopes)) {
      return NextResponse.json(
        { error: "requestedScopes must be an array of core function scopes" },
        { status: 400 }
      );
    }

    const result = await updateEndpointMonitoringPolicy({
      agentId: agent.id,
      tenantId: agent.tenant_id,
      requestedScopes: requestedScopes as CoreFunctionScope[],
      caller,
      approvalTokenId,
    });

    return NextResponse.json(result);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Internal error";
    if (msg.includes("AUTHORITY_APPROVAL_REQUIRED") || msg.includes("APPROVAL_TOKEN_NOT_APPROVED")) {
      return NextResponse.json({ error: msg }, { status: 403 });
    }
    trackError(err, { endpoint: "/api/fleet/[id]/monitoring" });
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
