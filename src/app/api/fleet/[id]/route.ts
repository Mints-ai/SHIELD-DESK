import { NextRequest, NextResponse } from "next/server";
import { getSessionUser } from "@/lib/auth/session";
import { getEndpointAgent, MOCK_ENDPOINT_AGENTS, removeMockEndpointAgent } from "@/lib/fleet/fleet";
import { getOrCreateTenantStore } from "@/lib/compliance/statefulTenantDb";
import { trackError } from "@/lib/observability/errorTracker";
import { query } from "@/lib/db";
import { adminDisconnectedAgents } from "@/lib/fleet/liveTelemetry";

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
      adminDisconnectedAgents.add(id);
      // Keep in-memory fallback stores synchronized
      const mockAgent = MOCK_ENDPOINT_AGENTS.find(
        (a) => (a.id === id || a.hostname === id) && (isCrossTenant || a.tenant_id === caller.tenant_id)
      );
      if (mockAgent) {
        adminDisconnectedAgents.add(mockAgent.id);
        if (mockAgent.hostname) adminDisconnectedAgents.add(mockAgent.hostname);
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
          ? `UPDATE endpoint_agents SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0 WHERE (id = $1 OR hostname = $1) RETURNING id, hostname;`
          : `UPDATE endpoint_agents SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0 WHERE (id = $1 OR hostname = $1) AND tenant_id = $2 RETURNING id, hostname;`;
        const sqlParams = isCrossTenant ? [id] : [id, caller.tenant_id];
        const { rows } = await query<{ id: string; hostname: string }>(sql, sqlParams);
        for (const row of rows) {
          adminDisconnectedAgents.add(row.id);
          if (row.hostname) adminDisconnectedAgents.add(row.hostname);
        }
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
      adminDisconnectedAgents.delete(id);
      const reconnectMock = MOCK_ENDPOINT_AGENTS.find(
        (a) => (a.id === id || a.hostname === id) && (isCrossTenant || a.tenant_id === caller.tenant_id)
      );
      if (reconnectMock) {
        adminDisconnectedAgents.delete(reconnectMock.id);
        if (reconnectMock.hostname) adminDisconnectedAgents.delete(reconnectMock.hostname);
      }
      try {
        const tenantFilterSql = isCrossTenant ? "" : `AND tenant_id = '${caller.tenant_id}'`;
        const { rows: reconnRows } = await query<{ id: string; hostname: string }>(
          `SELECT id, hostname FROM endpoint_agents WHERE (id = $1 OR hostname = $1) ${tenantFilterSql};`,
          [id]
        );
        for (const row of reconnRows) {
          adminDisconnectedAgents.delete(row.id);
          if (row.hostname) adminDisconnectedAgents.delete(row.hostname);
        }
      } catch {}
      // Single-endpoint-per-IP: verify no other endpoint with this IP is currently connected
      try {
        const { rows: conflictRows } = await query<{ id: string; hostname: string; ip_address: string }>(
          `SELECT c.id, c.hostname, c.ip_address
           FROM endpoint_agents target
           JOIN endpoint_agents c 
             ON c.tenant_id = target.tenant_id 
            AND c.ip_address = target.ip_address 
            AND c.id != target.id
            AND c.status = 'connected'
            AND c.kill_switch_active = false
            AND (COALESCE(c.last_seen_at, c.created_at) > now() - INTERVAL '15 seconds')
           WHERE target.id = $1
           LIMIT 1;`,
          [id]
        );

        if (conflictRows.length > 0) {
          return NextResponse.json(
            {
              error: `Cannot reconnect endpoint: Another endpoint ('${conflictRows[0].hostname}') is already connected from IP ${conflictRows[0].ip_address}. Only one endpoint per IP is allowed at a time.`,
            },
            { status: 409 }
          );
        }
      } catch {}

      const targetMock = MOCK_ENDPOINT_AGENTS.find((a) => a.id === id || a.hostname === id);
      if (targetMock && targetMock.ip_address) {
        const conflict = MOCK_ENDPOINT_AGENTS.find(
          (a) =>
            a.tenant_id === targetMock.tenant_id &&
            a.id !== targetMock.id &&
            a.ip_address === targetMock.ip_address &&
            a.status === "connected" &&
            !a.kill_switch_active &&
            Date.now() - new Date(a.last_heartbeat).getTime() <= 15000
        );
        if (conflict) {
          return NextResponse.json(
            {
              error: `Cannot reconnect endpoint: Another endpoint ('${conflict.hostname}') is already connected from IP ${conflict.ip_address}. Only one endpoint per IP is allowed at a time.`,
            },
            { status: 409 }
          );
        }
      }

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
