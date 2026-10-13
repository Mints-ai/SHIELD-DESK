import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { getEndpointAgent, MOCK_ENDPOINT_AGENTS, removeMockEndpointAgent } from "@/lib/fleet/fleet";
import { getOrCreateTenantStore } from "@/lib/compliance/statefulTenantDb";
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
    const isCrossTenant =
      caller.role === "system_admin" || caller.role === "super_admin";

    if (action === "disconnect") {
      // Keep in-memory fallback stores synchronized
      const mockAgent = MOCK_ENDPOINT_AGENTS.find(
        (a) => (a.id === id || a.hostname === id) && (isCrossTenant || a.tenant_id === caller.tenant_id)
      );
      if (mockAgent) {
        mockAgent.status = "disconnected";
        mockAgent.cpu_usage = 0;
        mockAgent.memory_usage = 0;
        mockAgent.eps = 0;
      }
      const stateStore = getOrCreateTenantStore(caller.tenant_id);
      const stateAgent = stateStore.endpointAgents.find(
        (a) => a.id === id || a.hostname === id
      );
      if (stateAgent) {
        stateAgent.status = "disconnected";
        stateAgent.cpu_usage = 0;
        stateAgent.memory_usage = 0;
        stateAgent.eps = 0;
      }

      try {
        const sql = isCrossTenant
          ? `UPDATE endpoint_agents SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0 WHERE id = $1 RETURNING id;`
          : `UPDATE endpoint_agents SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0 WHERE id = $1 AND tenant_id = $2 RETURNING id;`;
        const sqlParams = isCrossTenant ? [id] : [id, caller.tenant_id];
        const { rows } = await query<{ id: string }>(sql, sqlParams);
        return NextResponse.json({
          success: rows.length > 0 || Boolean(mockAgent || stateAgent),
          status: "disconnected",
        });
      } catch {
        if (mockAgent || stateAgent) {
          return NextResponse.json({ success: true, status: "disconnected" });
        }
        return NextResponse.json({ success: false, error: "Agent not found" }, { status: 404 });
      }
    }

    if (action === "reconnect" || action === "refresh") {
      const nowIso = new Date().toISOString();
      const mockAgent = MOCK_ENDPOINT_AGENTS.find(
        (a) => (a.id === id || a.hostname === id) && (isCrossTenant || a.tenant_id === caller.tenant_id)
      );
      if (mockAgent) {
        mockAgent.status = "connected";
        mockAgent.last_heartbeat = nowIso;
        mockAgent.cpu_usage = 0;
        mockAgent.memory_usage = 0;
        mockAgent.eps = 0;
      }
      const stateStore = getOrCreateTenantStore(caller.tenant_id);
      const stateAgent = stateStore.endpointAgents.find(
        (a) => a.id === id || a.hostname === id
      );
      if (stateAgent) {
        stateAgent.status = "connected";
        stateAgent.last_heartbeat = nowIso;
        stateAgent.cpu_usage = 0;
        stateAgent.memory_usage = 0;
        stateAgent.eps = 0;
      }

      try {
        const sql = isCrossTenant
          ? `UPDATE endpoint_agents
             SET status = 'connected',
                 last_seen_at = now(),
                 cpu_usage = 0,
                 memory_usage = 0,
                 eps = 0
             WHERE id = $1 RETURNING id;`
          : `UPDATE endpoint_agents
             SET status = 'connected',
                 last_seen_at = now(),
                 cpu_usage = 0,
                 memory_usage = 0,
                 eps = 0
             WHERE id = $1 AND tenant_id = $2 RETURNING id;`;
        const sqlParams = isCrossTenant ? [id] : [id, caller.tenant_id];
        const { rows } = await query<{ id: string }>(sql, sqlParams);
        return NextResponse.json({
          success: rows.length > 0 || Boolean(mockAgent || stateAgent),
          status: "connected",
        });
      } catch {
        if (mockAgent || stateAgent) {
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

    // Remove from in-memory fallback stores so removed endpoints never reappear
    const removedMock = removeMockEndpointAgent(id, isCrossTenant ? undefined : caller.tenant_id);
    const stateStore = getOrCreateTenantStore(caller.tenant_id);
    const stateIdx = stateStore.endpointAgents.findIndex(
      (a) => a.id === id || a.hostname === id
    );
    const removedState = stateIdx !== -1;
    if (removedState) {
      stateStore.endpointAgents.splice(stateIdx, 1);
    }

    let removedDb = false;
    try {
      await query(`DELETE FROM agent_command_logs WHERE agent_id = $1`, [id]).catch(() => {});
      const sql = isCrossTenant
        ? `DELETE FROM endpoint_agents WHERE id = $1 RETURNING id;`
        : `DELETE FROM endpoint_agents WHERE id = $1 AND tenant_id = $2 RETURNING id;`;
      const sqlParams = isCrossTenant ? [id] : [id, caller.tenant_id];
      const { rows } = await query<{ id: string }>(sql, sqlParams);
      removedDb = rows.length > 0;
    } catch {
      // Database offline — rely on in-memory store removal above
    }

    return NextResponse.json({
      success: removedDb || removedMock || removedState,
      message: "Endpoint successfully removed from fleet",
    });
  } catch (err: unknown) {
    trackError(err, { endpoint: "DELETE /api/fleet/[id]" });
    const msg = err instanceof Error ? err.message : "Internal error";
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
