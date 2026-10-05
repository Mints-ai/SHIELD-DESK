import { query } from "@/lib/db";
import type { SessionUser } from "@/lib/auth/session";
import type { EndpointAgentRecord } from "./fleet";

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

  // Use SELECT * and map dynamically so this is resilient to column name variants
  const sql = isCrossTenant
    ? `SELECT * FROM endpoint_agents ORDER BY COALESCE(last_seen_at, created_at) DESC NULLS LAST;`
    : `SELECT * FROM endpoint_agents WHERE tenant_id = $1 ORDER BY COALESCE(last_seen_at, created_at) DESC NULLS LAST;`;

  const params = isCrossTenant ? [] : [caller.tenant_id];
  const { rows } = await query<Record<string, unknown>>(sql, params);

  return rows.map((row) => ({
    id: String(row.id),
    tenant_id: String(row.tenant_id),
    hostname: String(row.hostname),
    ip_address: String(row.ip_address),
    os_type: (row.os_type || (row.os_info ? String(row.os_info).split(" ")[0].toLowerCase() : "linux")) as import("./fleet").OsType,
    agent_version: String(row.agent_version || "0.4.2"),
    status: String(row.status || "disconnected") as import("./fleet").AgentStatus,
    cpu_usage: Number(row.cpu_usage || 0),
    memory_usage: Number(row.memory_usage || 0),
    eps: Number(row.eps || 0),
    kill_switch_active: Boolean(row.kill_switch_active),
    safety_snapshot_id: row.safety_snapshot_id ? String(row.safety_snapshot_id) : null,
    // Normalise to last_heartbeat regardless of whether DB has last_seen_at or last_heartbeat
    last_heartbeat: new Date(
      (row.last_seen_at || row.last_heartbeat || row.created_at || new Date()) as string
    ).toISOString(),
    created_at: new Date((row.created_at || new Date()) as string).toISOString(),
  }));
}

/**
 * Sets kill switch state across the live fleet (DB-backed).
 */
export async function setLiveKillSwitch(
  active: boolean,
  tenantId: string
): Promise<{ affectedCount: number }> {
  const { rows } = await query<{ id: string }>(
    `UPDATE endpoint_agents
     SET kill_switch_active = $1,
         status = CASE WHEN $1 THEN 'disconnected' ELSE 'connected' END
     WHERE tenant_id = $2
       AND (kill_switch_active != $1 OR status != CASE WHEN $1 THEN 'disconnected' ELSE 'connected' END)
     RETURNING id;`,
    [active, tenantId]
  );
  return { affectedCount: rows.length };
}

/**
 * Sets individual agent status in the database.
 */
export async function setLiveAgentStatus(
  agentId: string,
  status: string,
  snapshotId?: string | null
): Promise<boolean> {
  const { rows } = await query<{ id: string }>(
    `UPDATE endpoint_agents
     SET status = $1
         ${snapshotId !== undefined ? ", safety_snapshot_id = $3" : ""}
     WHERE id = $2
     RETURNING id;`,
    snapshotId !== undefined ? [status, agentId, snapshotId] : [status, agentId]
  );
  return rows.length > 0;
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
    status: "succeeded" | "failed" | "executing";
    output: string;
    time: string;
    executedAt: string;
  }[]
> {
  const isCrossTenant =
    caller.role === "system_admin" || caller.role === "super_admin";

  const sql = agentId
    ? `SELECT id, agent_id, tenant_id, command, tier, status, output, executed_by, executed_at
       FROM agent_command_logs
       WHERE agent_id = $1
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
    ? [agentId]
    : isCrossTenant
    ? []
    : [caller.tenant_id];

  const { rows } = await query<Record<string, unknown>>(sql, params);
  return rows.map((r) => ({
    id: String(r.id),
    agentId: String(r.agent_id),
    tenantId: String(r.tenant_id),
    command: String(r.command),
    tier: String(r.tier),
    status: (r.status || "succeeded") as "succeeded" | "failed" | "executing",
    output: String(r.output || ""),
    time: new Date(r.executed_at as string).toLocaleTimeString(),
    executedAt: new Date(r.executed_at as string).toISOString(),
  }));
}

// Keep legacy export names for compatibility with existing imports
export { getLiveFleetAgents as tickFleetTelemetry };
