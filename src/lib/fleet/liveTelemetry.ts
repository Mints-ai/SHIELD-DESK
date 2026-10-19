import { query } from "@/lib/db";
import type { SessionUser } from "@/lib/auth/session";
import type { EndpointAgentRecord } from "./fleet";
import { normalizeEndpointIp } from "./ipAddress";
import { isIpBlocked } from "@/lib/alerts/threatAlertStore";

declare global {
  // eslint-disable-next-line no-var
  var __shieldDeskAdminDisconnectedAgents: Set<string> | undefined;
}

/**
 * Registry of endpoint IDs explicitly marked disconnected by an operator action.
 * Normal timeouts or idle agents are not locked; only explicit admin disconnects are preserved.
 */
if (!global.__shieldDeskAdminDisconnectedAgents) {
  global.__shieldDeskAdminDisconnectedAgents = new Set<string>();
}
export const adminDisconnectedAgents = global.__shieldDeskAdminDisconnectedAgents;

/**
 * Returns the live fleet agents for a caller, reading exclusively from the database.
 * No simulated or in-memory agents are included — only real enrolled endpoints.
 * Maps actual Supabase column names (last_seen_at) to the canonical interface field (last_heartbeat).
 */
export async function getLiveFleetAgents(
  caller: SessionUser
): Promise<EndpointAgentRecord[]> {
  const isCrossTenant =
    caller.role === "system_admin" || caller.role === "super_admin";

  // Order by active status first, then created_at ASC (the incumbent connected endpoint wins)
  const sql = isCrossTenant
    ? `SELECT * FROM endpoint_agents 
       ORDER BY 
         CASE WHEN status = 'connected' AND kill_switch_active = false AND (COALESCE(last_seen_at, created_at) > now() - INTERVAL '45 seconds') THEN 0 ELSE 1 END,
         created_at ASC NULLS LAST;`
    : `SELECT * FROM endpoint_agents 
       WHERE tenant_id = $1 
       ORDER BY 
         CASE WHEN status = 'connected' AND kill_switch_active = false AND (COALESCE(last_seen_at, created_at) > now() - INTERVAL '45 seconds') THEN 0 ELSE 1 END,
         created_at ASC NULLS LAST;`;

  const params = isCrossTenant ? [] : [caller.tenant_id];
  const { rows } = await query<Record<string, unknown>>(sql, params);

  const now = Date.now();
  const connectedIpsByTenant = new Set<string>();

  return rows.map((row) => {
    const lastSeenDate = new Date(
      (row.last_seen_at || row.last_heartbeat || row.created_at || new Date()) as string
    );
    const msSinceHeartbeat = now - lastSeenDate.getTime();
    // Agent ticks every 3 seconds. Allow up to 45s before marking disconnected to tolerate network jitter
    const isTimedOut = msSinceHeartbeat > 45000;

    const cleanIp = normalizeEndpointIp(row.ip_address) || "Unknown";
    const tenantIdStr = String(row.tenant_id);

    let computedStatus: import("./fleet").AgentStatus = String(row.status || "disconnected") as import("./fleet").AgentStatus;
    const isBlocked = cleanIp !== "Unknown" && isIpBlocked(cleanIp);
    if (isBlocked) {
      computedStatus = "disconnected";
    } else if (row.kill_switch_active) {
      computedStatus = "disconnected";
    } else if (computedStatus !== "isolated" && isTimedOut) {
      computedStatus = "disconnected";
    }

    // Single-endpoint-per-IP display enforcement
    if (computedStatus === "connected" && cleanIp !== "Unknown") {
      const tenantIpKey = `${tenantIdStr}:${cleanIp}`;
      if (connectedIpsByTenant.has(tenantIpKey)) {
        computedStatus = "disconnected";
      } else {
        connectedIpsByTenant.add(tenantIpKey);
      }
    }

    // Persist disconnected status to DB only if truly timed out (>45s) or blocked
    if ((isTimedOut || isBlocked) && row.status !== "disconnected") {
      query(
        `UPDATE endpoint_agents SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0 WHERE id = $1 AND status != 'disconnected'`,
        [row.id]
      ).catch(() => { });
    }

    // Stale indicator triggers only after 25s without a heartbeat (giving ample buffer for polling cycles)
    const isStale = msSinceHeartbeat > 25000;
    const isOfflineOrStale = computedStatus === "disconnected" || isTimedOut || isStale || isBlocked;

    return {
      id: String(row.id),
      tenant_id: String(row.tenant_id),
      hostname: String(row.hostname),
      ip_address: cleanIp,
      os_type: (row.os_type || (row.os_info ? String(row.os_info).split(" ")[0].toLowerCase() : "linux")) as import("./fleet").OsType,
      agent_version: String(row.agent_version || "0.4.2"),
      status: computedStatus,
      cpu_usage: isOfflineOrStale ? 0 : Number(row.cpu_usage || 0),
      memory_usage: isOfflineOrStale ? 0 : Number(row.memory_usage || 0),
      eps: isOfflineOrStale ? 0 : Number(row.eps || 0),
      kill_switch_active: Boolean(row.kill_switch_active),
      safety_snapshot_id: row.safety_snapshot_id ? String(row.safety_snapshot_id) : null,
      last_heartbeat: lastSeenDate.toISOString(),
      created_at: new Date((row.created_at || new Date()) as string).toISOString(),
    };
  });
}

/**
 * Manually marks an agent as disconnected.
 */
export async function disconnectLiveAgent(agentId: string, tenantId?: string): Promise<boolean> {
  adminDisconnectedAgents.add(agentId);
  const { MOCK_ENDPOINT_AGENTS } = await import("./fleet");
  const mockAgent = MOCK_ENDPOINT_AGENTS.find(
    (a) => (a.id === agentId || a.hostname === agentId) && (!tenantId || a.tenant_id === tenantId)
  );
  if (mockAgent) {
    mockAgent.status = "disconnected";
    mockAgent.cpu_usage = 0;
    mockAgent.memory_usage = 0;
    mockAgent.eps = 0;
  }

  try {
    const sql = tenantId
      ? `UPDATE endpoint_agents SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0 WHERE id::text = $1 AND tenant_id = $2 RETURNING id;`
      : `UPDATE endpoint_agents SET status = 'disconnected', cpu_usage = 0, memory_usage = 0, eps = 0 WHERE id::text = $1 RETURNING id;`;
    const params = tenantId ? [agentId, tenantId] : [agentId];
    const { rows } = await query<{ id: string }>(sql, params);
    return rows.length > 0 || Boolean(mockAgent);
  } catch {
    return Boolean(mockAgent);
  }
}

/**
 * Removes / unenrolls an agent from the database entirely.
 */
export async function deleteLiveAgent(agentId: string, tenantId?: string): Promise<boolean> {
  const { removeMockEndpointAgent } = await import("./fleet");
  const removedMock = removeMockEndpointAgent(agentId, tenantId);

  try {
    await query(`DELETE FROM agent_command_logs WHERE agent_id::text = $1`, [agentId]).catch(() => { });
    const sql = tenantId
      ? `DELETE FROM endpoint_agents WHERE id::text = $1 AND tenant_id = $2 RETURNING id;`
      : `DELETE FROM endpoint_agents WHERE id::text = $1 RETURNING id;`;
    const params = tenantId ? [agentId, tenantId] : [agentId];
    const { rows } = await query<{ id: string }>(sql, params);
    return rows.length > 0 || removedMock;
  } catch {
    return removedMock;
  }
}

/**
 * Sets kill switch state across the live fleet (DB-backed).
 */
export async function setLiveKillSwitch(
  active: boolean,
  tenantId?: string
): Promise<{ affectedCount: number }> {
  try {
    const sql = tenantId
      ? `UPDATE endpoint_agents
         SET kill_switch_active = $1,
             status = CASE WHEN $1 THEN 'disconnected' ELSE 'connected' END
         WHERE tenant_id = $2
           AND (kill_switch_active != $1 OR status != CASE WHEN $1 THEN 'disconnected' ELSE 'connected' END)
         RETURNING id;`
      : `UPDATE endpoint_agents
         SET kill_switch_active = $1,
             status = CASE WHEN $1 THEN 'disconnected' ELSE 'connected' END
         WHERE (kill_switch_active != $1 OR status != CASE WHEN $1 THEN 'disconnected' ELSE 'connected' END)
         RETURNING id;`;
    const params = tenantId ? [active, tenantId] : [active];
    const { rows } = await query<{ id: string }>(sql, params);
    return { affectedCount: rows.length };
  } catch {
    return { affectedCount: 0 };
  }
}

/**
 * Sets individual agent status in the database.
 */
export async function setLiveAgentStatus(
  agentId: string,
  status: string,
  snapshotId?: string | null
): Promise<boolean> {
  if (status === "connected") {
    adminDisconnectedAgents.delete(agentId);
  } else if (status === "disconnected") {
    adminDisconnectedAgents.add(agentId);
  }
  const isDisconnected = status === "disconnected";
  try {
    const { rows } = await query<{ id: string }>(
      `UPDATE endpoint_agents
       SET status = $1
           ${isDisconnected ? ", cpu_usage = 0, memory_usage = 0, eps = 0" : ""}
           ${snapshotId !== undefined ? ", safety_snapshot_id = $3" : ""}
       WHERE id::text = $2
       RETURNING id;`,
      snapshotId !== undefined ? [status, agentId, snapshotId] : [status, agentId]
    );
    return rows.length > 0;
  } catch {
    return true;
  }
}

/**
 * Fetches real command logs from the database.
 */
export async function getLiveCommandLogs(
  caller: SessionUser,
  agentId?: string
): Promise<
  {
    id: string;
    agentId: string;
    tenantId: string;
    command: string;
    tier: string;
    status: "succeeded" | "failed" | "executing" | "pending";
    output: string;
    time: string;
    executedAt: string;
  }[]
> {
  const isCrossTenant =
    caller.role === "system_admin" || caller.role === "super_admin";

  const sql = agentId
    ? isCrossTenant
      ? `SELECT id, agent_id, tenant_id, command, tier, status, output, executed_by, executed_at
         FROM agent_command_logs
         WHERE agent_id = $1
         ORDER BY executed_at DESC LIMIT 50;`
      : `SELECT id, agent_id, tenant_id, command, tier, status, output, executed_by, executed_at
         FROM agent_command_logs
         WHERE agent_id = $1 AND tenant_id = $2
         ORDER BY executed_at DESC LIMIT 50;`
    : isCrossTenant
      ? `SELECT id, agent_id, tenant_id, command, tier, status, output, executed_by, executed_at
       FROM agent_command_logs
       ORDER BY executed_at DESC LIMIT 50;`
      : `SELECT id, agent_id, tenant_id, command, tier, status, output, executed_by, executed_at
       FROM agent_command_logs
       WHERE tenant_id = $1
       ORDER BY executed_at DESC LIMIT 50;`;

  const params = agentId
    ? isCrossTenant
      ? [agentId]
      : [agentId, caller.tenant_id]
    : isCrossTenant
      ? []
      : [caller.tenant_id];

  try {
    // Reconcile and synchronize any pending logs with their corresponding task and command outcomes
    await query(
      `UPDATE agent_command_logs acl
       SET status = CASE 
         WHEN ac.status IN ('executed', 'verified') THEN 'succeeded'
         WHEN ac.status = 'failed' THEN 'failed'
         WHEN mt.status = 'completed' THEN 'succeeded'
         WHEN mt.status = 'rejected' OR at.status = 'rejected' THEN 'failed'
         ELSE acl.status
       END,
       output = COALESCE(
         ac.result->>'output',
         CASE 
           WHEN at.status = 'rejected' THEN 'Action rejected by security governance.'
           WHEN mt.status = 'completed' THEN 'Action authorized and completed on Task Board.'
           ELSE acl.output
         END
       )
       FROM approval_tokens at
       LEFT JOIN mitigation_tasks mt ON mt.id = at.task_id
       LEFT JOIN agent_commands ac ON (ac.id = acl.id OR ac.token_id = at.id)
       WHERE acl.token_id = at.id
         AND acl.status = 'pending'
         AND (at.status IN ('consumed', 'rejected') OR mt.status IN ('completed', 'rejected') OR ac.status IN ('executed', 'failed', 'verified'));`
    ).catch(() => {});

    await query(
      `UPDATE agent_command_logs
       SET status = 'failed', output = 'Authorization expired or cancelled.'
       WHERE status = 'pending'
         AND executed_at < now() - INTERVAL '15 minutes';`
    ).catch(() => {});

    const { rows } = await query<Record<string, unknown>>(sql, params);
    return rows.map((r) => ({
      id: String(r.id),
      agentId: String(r.agent_id),
      tenantId: String(r.tenant_id),
      command: String(r.command),
      tier: String(r.tier),
      status: (r.status || "succeeded") as "succeeded" | "failed" | "executing" | "pending",
      output: String(r.output || ""),
      time: new Date(r.executed_at as string).toLocaleTimeString(),
      executedAt: new Date(r.executed_at as string).toISOString(),
    }));
  } catch {
    return [];
  }
}

// Keep legacy export names for compatibility with existing imports
export { getLiveFleetAgents as tickFleetTelemetry };
