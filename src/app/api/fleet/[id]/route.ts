import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { getEndpointAgent } from "@/lib/fleet/fleet";
import { trackError } from "@/lib/observability/errorTracker";
import { query } from "@/lib/db";

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

    // Anti-enumeration: returns 404 whether agent doesn't exist or is cross-tenant
    if (!agent) {
      return NextResponse.json(
        { error: "Endpoint agent not found" },
        { status: 404 }
      );
    }

    return NextResponse.json({ agent });
  } catch (err: unknown) {
    trackError(err, { endpoint: "/api/fleet/[id]" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

export async function PATCH(
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
    const body = await req.json().catch(() => ({}));
    const action = body.action || "disconnect";

    if (action === "disconnect") {
      const isCrossTenant =
        caller.role === "system_admin" || caller.role === "super_admin";
      try {
        const sql = isCrossTenant
          ? `UPDATE endpoint_agents SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0 WHERE id = $1 RETURNING id;`
          : `UPDATE endpoint_agents SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0 WHERE id = $1 AND tenant_id = $2 RETURNING id;`;
        const sqlParams = isCrossTenant ? [id] : [id, caller.tenant_id];
        const { rows } = await query<{ id: string }>(sql, sqlParams);
        return NextResponse.json({ success: rows.length > 0, status: "disconnected" });
      } catch {
        const { MOCK_ENDPOINT_AGENTS } = await import("@/lib/fleet/fleet");
        const agent = MOCK_ENDPOINT_AGENTS.find((a) => a.id === id);
        if (agent) {
          agent.status = "disconnected";
          agent.cpu_usage = 0;
          agent.memory_usage = 0;
          agent.eps = 0;
          return NextResponse.json({ success: true, status: "disconnected" });
        }
        return NextResponse.json({ success: false, error: "Agent not found" }, { status: 404 });
      }
    }

    if (action === "reconnect" || action === "refresh") {
      const isCrossTenant =
        caller.role === "system_admin" || caller.role === "super_admin";
      try {
        const sql = isCrossTenant
          ? `UPDATE endpoint_agents
             SET status = 'connected',
                 cpu_usage = 0,
                 memory_usage = 0,
                 eps = 0
             WHERE id = $1 RETURNING id;`
          : `UPDATE endpoint_agents
             SET status = 'connected',
                 cpu_usage = 0,
                 memory_usage = 0,
                 eps = 0
             WHERE id = $1 AND tenant_id = $2 RETURNING id;`;
        const sqlParams = isCrossTenant ? [id] : [id, caller.tenant_id];
        const { rows } = await query<{ id: string }>(sql, sqlParams);
        return NextResponse.json({ success: rows.length > 0, status: "connected" });
      } catch {
        const { MOCK_ENDPOINT_AGENTS } = await import("@/lib/fleet/fleet");
        const agent = MOCK_ENDPOINT_AGENTS.find((a) => a.id === id);
        if (agent) {
          agent.status = "connected";
          agent.cpu_usage = 0;
          agent.memory_usage = 0;
          agent.eps = 0;
          return NextResponse.json({ success: true, status: "connected" });
        }
        return NextResponse.json({ success: false, error: "Agent not found" }, { status: 404 });
      }
    }

    return NextResponse.json({ error: "Unsupported action" }, { status: 400 });
  } catch (err: unknown) {
    trackError(err, { endpoint: "PATCH /api/fleet/[id]" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

export async function DELETE(
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
    const isCrossTenant =
      caller.role === "system_admin" || caller.role === "super_admin";
    try {
      await query(`DELETE FROM agent_command_logs WHERE agent_id = $1`, [id]);
    } catch {}
    const sql = isCrossTenant
      ? `DELETE FROM endpoint_agents WHERE id = $1 RETURNING id;`
      : `DELETE FROM endpoint_agents WHERE id = $1 AND tenant_id = $2 RETURNING id;`;
    const sqlParams = isCrossTenant ? [id] : [id, caller.tenant_id];
    const { rows } = await query<{ id: string }>(sql, sqlParams);

    return NextResponse.json({
      success: rows.length > 0,
      message: "Endpoint successfully removed from fleet",
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "DELETE /api/fleet/[id]" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
