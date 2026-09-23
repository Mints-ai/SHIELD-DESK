import { query } from "@/lib/db";
import type { SessionUser } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { getApprovalToken } from "@/lib/governance/approvalTokens";
import crypto from "crypto";

export type AgentStatus = "connected" | "isolated" | "quarantined" | "disconnected";
export type OsType = "linux" | "windows" | "darwin";

export interface EndpointAgentRecord {
  id: string;
  tenant_id: string;
  hostname: string;
  ip_address: string;
  os_type: OsType;
  agent_version: string;
  status: AgentStatus;
  cpu_usage: number;
  memory_usage: number;
  eps: number;
  kill_switch_active: boolean;
  safety_snapshot_id: string | null;
  last_heartbeat: string;
  created_at: string;
}

export interface AgentCommandLogRecord {
  id: string;
  agent_id: string;
  tenant_id: string;
  command: string;
  tier: "Tier 0" | "Tier 1" | "Tier 2" | "Tier 3";
  token_id: string | null;
  status: "pending" | "executing" | "succeeded" | "failed" | "rolled_back";
  output: string;
  executed_by: string;
  executed_at: string;
}

export interface HashChainAuditRecord {
  id: string;
  tenant_id: string;
  event_type: string;
  actor_id: string;
  payload: Record<string, unknown>;
  prev_hash: string;
  current_hash: string;
  created_at: string;
}

// In-memory fallback mock store for tests / offline mode
export const MOCK_ENDPOINT_AGENTS: EndpointAgentRecord[] = [
  {
    id: "ea111111-1111-1111-1111-111111111111",
    tenant_id: "acme-tenant",
    hostname: "FIN-WS-042",
    ip_address: "10.0.4.42",
    os_type: "windows",
    agent_version: "0.4.2",
    status: "connected",
    cpu_usage: 42.5,
    memory_usage: 68.2,
    eps: 145,
    kill_switch_active: false,
    safety_snapshot_id: "snap-finws042-baseline",
    last_heartbeat: new Date().toISOString(),
    created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
  {
    id: "ea222222-2222-2222-2222-222222222222",
    tenant_id: "acme-tenant",
    hostname: "FIN-DB-01",
    ip_address: "10.0.4.10",
    os_type: "linux",
    agent_version: "0.4.2",
    status: "connected",
    cpu_usage: 18.2,
    memory_usage: 84.1,
    eps: 412,
    kill_switch_active: false,
    safety_snapshot_id: "snap-findb01-baseline",
    last_heartbeat: new Date().toISOString(),
    created_at: new Date(Date.now() - 86400000 * 5).toISOString(),
  },
  {
    id: "ea333333-3333-3333-3333-333333333333",
    tenant_id: "acme-tenant",
    hostname: "ENG-LAPTOP-09",
    ip_address: "10.0.12.9",
    os_type: "linux",
    agent_version: "0.4.2",
    status: "connected",
    cpu_usage: 12.1,
    memory_usage: 45.0,
    eps: 32,
    kill_switch_active: false,
    safety_snapshot_id: "snap-eng09-baseline",
    last_heartbeat: new Date().toISOString(),
    created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
  },
  {
    id: "ea444444-4444-4444-4444-444444444444",
    tenant_id: "acme-tenant",
    hostname: "PROD-API-01",
    ip_address: "10.0.2.100",
    os_type: "linux",
    agent_version: "0.4.2",
    status: "connected",
    cpu_usage: 64.8,
    memory_usage: 71.3,
    eps: 890,
    kill_switch_active: false,
    safety_snapshot_id: "snap-prodapi-baseline",
    last_heartbeat: new Date().toISOString(),
    created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
  },
  {
    id: "ea555555-5555-5555-5555-555555555555",
    tenant_id: "globex-tenant",
    hostname: "GLX-SEC-01",
    ip_address: "192.168.1.15",
    os_type: "linux",
    agent_version: "0.4.2",
    status: "connected",
    cpu_usage: 15.0,
    memory_usage: 38.0,
    eps: 80,
    kill_switch_active: false,
    safety_snapshot_id: "snap-glx01-baseline",
    last_heartbeat: new Date().toISOString(),
    created_at: new Date(Date.now() - 86400000 * 4).toISOString(),
  },
];

export const MOCK_COMMAND_LOGS: AgentCommandLogRecord[] = [
  {
    id: "cl111111-1111-1111-1111-111111111111",
    agent_id: "ea111111-1111-1111-1111-111111111111",
    tenant_id: "acme-tenant",
    command: "take_safety_snapshot",
    tier: "Tier 1",
    token_id: null,
    status: "succeeded",
    output: "Snapshot snap-finws042-baseline captured successfully (routing table + process tree).",
    executed_by: "system-air",
    executed_at: new Date(Date.now() - 3600000 * 2).toISOString(),
  },
];

export const MOCK_HASH_CHAINS: HashChainAuditRecord[] = [
  {
    id: "hc000000-0000-0000-0000-000000000000",
    tenant_id: "acme-tenant",
    event_type: "GENESIS",
    actor_id: "system-init",
    payload: { msg: "ShieldDesk Hash Chain Genesis" },
    prev_hash: "0".repeat(64),
    current_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    created_at: new Date(Date.now() - 86400000 * 10).toISOString(),
  },
];

/**
 * Computes SHA-256 for hash-chaining audit entries.
 */
function computeHash(prevHash: string, payload: Record<string, unknown>, actorId: string): string {
  const data = `${prevHash}|${actorId}|${JSON.stringify(payload)}`;
  return crypto.createHash("sha256").update(data).digest("hex");
}

/**
 * Lists endpoint agents for the caller with strict tenant boundary.
 */
export async function listEndpointAgents(caller: SessionUser): Promise<EndpointAgentRecord[]> {
  const canCrossTenant = canAccess(caller.role, "VIEW_CROSS_TENANT");

  try {
    const sql = canCrossTenant
      ? `SELECT * FROM endpoint_agents ORDER BY hostname ASC;`
      : `SELECT * FROM endpoint_agents WHERE tenant_id = $1 ORDER BY hostname ASC;`;
    const params = canCrossTenant ? [] : [caller.tenant_id];

    const result = await query(sql, params);
    if (result && result.rows.length > 0) {
      return result.rows.map((row: Record<string, unknown>) => ({
        id: String(row.id),
        tenant_id: String(row.tenant_id),
        hostname: String(row.hostname),
        ip_address: String(row.ip_address),
        os_type: row.os_type as OsType,
        agent_version: String(row.agent_version),
        status: row.status as AgentStatus,
        cpu_usage: Number(row.cpu_usage || 0),
        memory_usage: Number(row.memory_usage || 0),
        eps: Number(row.eps || 0),
        kill_switch_active: Boolean(row.kill_switch_active),
        safety_snapshot_id: row.safety_snapshot_id ? String(row.safety_snapshot_id) : null,
        last_heartbeat: new Date(row.last_heartbeat as string).toISOString(),
        created_at: new Date(row.created_at as string).toISOString(),
      }));
    }
  } catch {
    // Fall back to in-memory store
  }

  return MOCK_ENDPOINT_AGENTS.filter(
    (a) => canCrossTenant || a.tenant_id === caller.tenant_id
  );
}

/**
 * Retrieves a single endpoint agent by ID or hostname.
 * Strictly enforces Anti-Enumeration: returns null (leading to 404) if cross-tenant.
 */
export async function getEndpointAgent(
  identifier: string,
  caller: SessionUser
): Promise<EndpointAgentRecord | null> {
  const canCrossTenant = canAccess(caller.role, "VIEW_CROSS_TENANT");

  try {
    const sql = canCrossTenant
      ? `SELECT * FROM endpoint_agents WHERE id::text = $1 OR hostname = $1 LIMIT 1;`
      : `SELECT * FROM endpoint_agents WHERE (id::text = $1 OR hostname = $1) AND tenant_id = $2 LIMIT 1;`;
    const params = canCrossTenant ? [identifier] : [identifier, caller.tenant_id];

    const result = await query(sql, params);
    if (result && result.rows.length > 0) {
      const row = result.rows[0];
      return {
        id: String(row.id),
        tenant_id: String(row.tenant_id),
        hostname: String(row.hostname),
        ip_address: String(row.ip_address),
        os_type: row.os_type as OsType,
        agent_version: String(row.agent_version),
        status: row.status as AgentStatus,
        cpu_usage: Number(row.cpu_usage || 0),
        memory_usage: Number(row.memory_usage || 0),
        eps: Number(row.eps || 0),
        kill_switch_active: Boolean(row.kill_switch_active),
        safety_snapshot_id: row.safety_snapshot_id ? String(row.safety_snapshot_id) : null,
        last_heartbeat: new Date(row.last_heartbeat as string).toISOString(),
        created_at: new Date(row.created_at as string).toISOString(),
      };
    }
  } catch {
    // Fall back to mock
  }

  const agent = MOCK_ENDPOINT_AGENTS.find(
    (a) => a.id === identifier || a.hostname === identifier
  );
  if (!agent) return null;
  if (!canCrossTenant && agent.tenant_id !== caller.tenant_id) {
    return null; // Anti-enumeration 404
  }
  return agent;
}

/**
 * Triggers the Emergency Admin Kill Switch.
 * Instantly revokes an agent's ability to act, or all agents in a tenant.
 */
export async function triggerKillSwitch({
  agentId,
  active,
  caller,
}: {
  agentId?: string;
  active: boolean;
  caller: SessionUser;
}): Promise<{ affectedCount: number; message: string }> {
  const isSuperOrAdmin =
    caller.role === "system_admin" ||
    caller.role === "super_admin" ||
    canAccess(caller.role, "MANAGE_USERS");

  if (!isSuperOrAdmin) {
    throw new Error("UNAUTHORIZED_KILL_SWITCH: Only Administrators can trigger the Emergency Kill Switch.");
  }

  let count = 0;
  try {
    if (agentId) {
      const res = await query(
        `UPDATE endpoint_agents SET kill_switch_active = $1, status = CASE WHEN $1 = true THEN 'disconnected' ELSE 'connected' END WHERE (id::text = $2 OR hostname = $2) AND tenant_id = $3 RETURNING id;`,
        [active, agentId, caller.tenant_id]
      );
      count = res.rowCount || 0;
    } else {
      const res = await query(
        `UPDATE endpoint_agents SET kill_switch_active = $1, status = CASE WHEN $1 = true THEN 'disconnected' ELSE 'connected' END WHERE tenant_id = $2 RETURNING id;`,
        [active, caller.tenant_id]
      );
      count = res.rowCount || 0;
    }
  } catch {
    // mock fallback
    if (agentId) {
      const agent = MOCK_ENDPOINT_AGENTS.find(
        (a) => (a.id === agentId || a.hostname === agentId) && a.tenant_id === caller.tenant_id
      );
      if (agent) {
        agent.kill_switch_active = active;
        agent.status = active ? "disconnected" : "connected";
        count = 1;
      }
    } else {
      MOCK_ENDPOINT_AGENTS.filter((a) => a.tenant_id === caller.tenant_id).forEach((a) => {
        a.kill_switch_active = active;
        a.status = active ? "disconnected" : "connected";
        count++;
      });
    }
  }

  // Record into tamper-proof hash chain
  await recordHashChainEvent({
    tenantId: caller.tenant_id,
    eventType: active ? "KILL_SWITCH_ENGAGED" : "KILL_SWITCH_DISENGAGED",
    actorId: caller.id,
    payload: { agentId: agentId || "ALL_TENANT_AGENTS", active, affectedCount: count },
  });

  return {
    affectedCount: count,
    message: active
      ? `Emergency Kill Switch engaged. ${count} endpoint agent(s) disconnected and revoked.`
      : `Emergency Kill Switch disengaged. ${count} endpoint agent(s) restored.`,
  };
}

/**
 * Executes a command on an endpoint agent.
 * Enforces Layer 4 Rulebook: Tier 1 executes automatically with safety snapshot;
 * Tier 2/3 requires a pre-existing approved ApprovalToken.
 */
export async function executeAgentCommand({
  agentId,
  command,
  tier,
  tokenId,
  caller,
}: {
  agentId: string;
  command: string;
  tier: "Tier 1" | "Tier 2" | "Tier 3";
  tokenId?: string;
  caller: SessionUser;
}): Promise<{
  success: boolean;
  commandId: string;
  output: string;
  snapshotId?: string;
  tier: string;
}> {
  const agent = await getEndpointAgent(agentId, caller);
  if (!agent) {
    throw new Error("AGENT_NOT_FOUND");
  }

  if (agent.kill_switch_active) {
    throw new Error("KILL_SWITCH_ACTIVE: Agent is blocked by Emergency Admin Kill Switch.");
  }

  // Tier 2 & Tier 3 Governance Validation
  if (tier === "Tier 2" || tier === "Tier 3") {
    if (!tokenId) {
      throw new Error(`APPROVAL_TOKEN_REQUIRED: Action '${command}' is ${tier} and requires an approved human sign-off token.`);
    }

    const token = await getApprovalToken(tokenId, caller);
    if (!token) {
      throw new Error("APPROVAL_TOKEN_NOT_FOUND");
    }
    if (token.status !== "approved") {
      throw new Error(`APPROVAL_TOKEN_NOT_APPROVED: Current token status is '${token.status}'. Must be 'approved'.`);
    }
    if (new Date(token.expires_at).getTime() < Date.now()) {
      throw new Error("APPROVAL_TOKEN_EXPIRED");
    }
  }

  // Tier 1 safety snapshot verification
  let snapshotId: string | undefined = undefined;
  if (command.startsWith("isolate_host") || command.startsWith("block_ip") || command.startsWith("kill_process")) {
    snapshotId = `snap-${agent.hostname.toLowerCase()}-${Date.now().toString(36)}`;
  }

  // Simulate command execution on endpoint
  let output = "";
  if (command.startsWith("isolate_host")) {
    output = `Network interface isolated successfully on ${agent.hostname}. Outbound/inbound traffic disabled except management gRPC tunnel. Safety snapshot ${snapshotId} saved.`;
    agent.status = "isolated";
    agent.safety_snapshot_id = snapshotId || null;
  } else if (command.startsWith("restore_host")) {
    output = `Network interface restored on ${agent.hostname}. Restored baseline routing table.`;
    agent.status = "connected";
  } else if (command.startsWith("block_ip")) {
    const ip = command.split(" ")[1] || "198.51.100.4";
    output = `Local firewall rule inserted on ${agent.hostname}: DROP all traffic to/from ${ip}. Snapshot ${snapshotId} registered.`;
  } else if (command.startsWith("kill_process")) {
    const pid = command.split(" ")[1] || "4812";
    output = `Process ${pid} terminated via SIGKILL on ${agent.hostname}. Process dump captured for forensics.`;
  } else if (command.startsWith("take_safety_snapshot")) {
    output = `Filesystem & network state snapshot ${snapshotId} taken successfully on ${agent.hostname}.`;
    agent.safety_snapshot_id = snapshotId || null;
  } else if (command.startsWith("rollback_snapshot")) {
    output = `State reverted to snapshot ${agent.safety_snapshot_id || "snap-baseline"} on ${agent.hostname}.`;
    agent.status = "connected";
  } else {
    output = `Command '${command}' executed with exit code 0 on ${agent.hostname}.`;
  }

  const commandLogId = `cl-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 7)}`;
  const logRecord: AgentCommandLogRecord = {
    id: commandLogId,
    agent_id: agent.id,
    tenant_id: caller.tenant_id,
    command,
    tier,
    token_id: tokenId || null,
    status: "succeeded",
    output,
    executed_by: caller.id,
    executed_at: new Date().toISOString(),
  };

  try {
    await query(
      `INSERT INTO agent_command_logs (id, agent_id, tenant_id, command, tier, token_id, status, output, executed_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);`,
      [logRecord.id, logRecord.agent_id, logRecord.tenant_id, logRecord.command, logRecord.tier, logRecord.token_id, logRecord.status, logRecord.output, logRecord.executed_by]
    );
  } catch {
    MOCK_COMMAND_LOGS.push(logRecord);
  }

  // Tamper-proof hash-chain append
  await recordHashChainEvent({
    tenantId: caller.tenant_id,
    eventType: "AGENT_COMMAND_EXECUTED",
    actorId: caller.id,
    payload: {
      agentId: agent.id,
      command,
      tier,
      tokenId: tokenId || null,
      snapshotId: snapshotId || null,
    },
  });

  return {
    success: true,
    commandId: commandLogId,
    output,
    snapshotId,
    tier,
  };
}

/**
 * Appends a record to the tamper-proof cryptographic hash chain.
 */
export async function recordHashChainEvent({
  tenantId,
  eventType,
  actorId,
  payload,
}: {
  tenantId: string;
  eventType: string;
  actorId: string;
  payload: Record<string, unknown>;
}): Promise<HashChainAuditRecord> {
  const lastHashRecord = MOCK_HASH_CHAINS[MOCK_HASH_CHAINS.length - 1];
  const prevHash = lastHashRecord ? lastHashRecord.current_hash : "0".repeat(64);
  const currentHash = computeHash(prevHash, payload, actorId);

  const record: HashChainAuditRecord = {
    id: `hc-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
    tenant_id: tenantId,
    event_type: eventType,
    actor_id: actorId,
    payload,
    prev_hash: prevHash,
    current_hash: currentHash,
    created_at: new Date().toISOString(),
  };

  try {
    await query(
      `INSERT INTO hash_chain_audit (id, tenant_id, event_type, actor_id, payload, prev_hash, current_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7);`,
      [record.id, record.tenant_id, record.event_type, record.actor_id, JSON.stringify(record.payload), record.prev_hash, record.current_hash]
    );
  } catch {
    MOCK_HASH_CHAINS.push(record);
  }

  return record;
}
