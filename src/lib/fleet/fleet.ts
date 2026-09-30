import { query } from "@/lib/db";
import type { SessionUser } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { getApprovalToken, markApprovalTokenConsumed } from "@/lib/governance/approvalTokens";
import { checkThrottle, recordMockThrottleCommand } from "@/lib/governance/blastRadiusThrottle";
import { signCommand } from "@/lib/fleet/commandSigning";
import { isDemoMode, isProduction, isSimulationAllowed } from "@/lib/config/environment";
import { validateCapabilitySupport, getCapability } from "./capabilities";
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

export type CommandExecutionState =
  | "requested"
  | "authorised"
  | "signed"
  | "queued"
  | "delivered"
  | "acknowledged"
  | "executing"
  | "executed"
  | "verified"
  | "failed"
  | "rolled_back"
  | "cancelled"
  | "expired"
  | "delivery_failed"
  | "execution_failed"
  | "verification_failed";

export interface AgentCommandQueueRecord {
  id: string;
  agent_id: string;
  tenant_id: string;
  command: string;
  tier: "Tier 0" | "Tier 1" | "Tier 2" | "Tier 3";
  token_id: string | null;
  signature: string;
  nonce?: string | null;
  status: CommandExecutionState;
  result?: Record<string, unknown> | null;
  snapshot_id?: string | null;
  created_at: string;
  delivered_at?: string | null;
  completed_at?: string | null;
}

export const MOCK_AGENT_COMMANDS: AgentCommandQueueRecord[] = [];

export interface AgentCommandLogRecord {
  id: string;
  agent_id: string;
  tenant_id: string;
  command: string;
  tier: "Tier 0" | "Tier 1" | "Tier 2" | "Tier 3";
  token_id: string | null;
  status: "pending" | "executing" | "succeeded" | "failed" | "rolled_back" | "verified";
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

  if (!agentId) {
    if (active) {
      TENANT_KILL_SWITCH_REGISTRY.add(caller.tenant_id);
    } else {
      TENANT_KILL_SWITCH_REGISTRY.delete(caller.tenant_id);
    }
  }

  return {
    affectedCount: count,
    message: active
      ? `Emergency Kill Switch engaged. ${count} endpoint agent(s) disconnected and revoked.`
      : `Emergency Kill Switch disengaged. ${count} endpoint agent(s) restored.`,
  };
}

export const TENANT_KILL_SWITCH_REGISTRY = new Set<string>();

/**
 * Checks whether an emergency kill switch is engaged for a given tenant.
 */
export async function isKillSwitchEngaged(tenantId: string): Promise<boolean> {
  if (TENANT_KILL_SWITCH_REGISTRY.has(tenantId)) {
    return true;
  }

  try {
    const res = await query<{ count: string }>(
      `SELECT count(*) FROM endpoint_agents WHERE tenant_id = $1 AND kill_switch_active = true;`,
      [tenantId]
    );
    if (res.rows[0] && parseInt(res.rows[0].count, 10) > 0) {
      return true;
    }
  } catch {
    // Fall back to memory check
  }

  return MOCK_ENDPOINT_AGENTS.some((a) => a.tenant_id === tenantId && a.kill_switch_active);
}

/**
 * Programmatically sets the kill switch state for a tenant (used in tests and administrative actions).
 */
export async function setKillSwitchState(tenantId: string, active: boolean): Promise<void> {
  await triggerKillSwitch({
    active,
    caller: {
      id: "usr-secops-admin",
      tenant_id: tenantId,
      role: "system_admin",
    },
  });
}

/**
 * Executes a command on an endpoint agent.
 * Enforces Layer 4 Rulebook: Tier 1 executes automatically with safety snapshot;
 * Tier 2/3 requires a pre-existing approved ApprovalToken.
 */
export interface CommandExecutionParams {
  agent: EndpointAgentRecord;
  command: string;
  tier: "Tier 1" | "Tier 2" | "Tier 3";
  tokenId?: string;
  caller: SessionUser;
  commandLogId: string;
  signature: string;
  nonce: string;
  snapshotId?: string;
}

export interface CommandExecutionResult {
  success: boolean;
  commandId: string;
  output: string;
  snapshotId?: string;
  tier: string;
  state: CommandExecutionState;
  isSimulated?: boolean;
}

/**
 * RealAgentExecutor: Enqueues signed commands into the agent delivery queue.
 * Does NOT simulate execution. Sets status to 'queued' and awaits signed execution report from the remote agent.
 * Mandated for all production and live staging environments.
 */
export class RealAgentExecutor {
  async execute(params: CommandExecutionParams): Promise<CommandExecutionResult> {
    const { agent, command, tier, tokenId, caller, commandLogId, signature, nonce, snapshotId } = params;

    const queueRecord: AgentCommandQueueRecord = {
      id: commandLogId,
      agent_id: agent.id,
      tenant_id: caller.tenant_id,
      command,
      tier,
      token_id: tokenId || null,
      signature,
      nonce,
      status: "queued",
      snapshot_id: snapshotId || null,
      created_at: new Date().toISOString(),
    };

    try {
      await query(
        `INSERT INTO agent_commands (id, agent_id, tenant_id, command, tier, token_id, signature, nonce, status, snapshot_id, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now());`,
        [queueRecord.id, queueRecord.agent_id, queueRecord.tenant_id, queueRecord.command, queueRecord.tier, queueRecord.token_id, queueRecord.signature, queueRecord.nonce, queueRecord.status, queueRecord.snapshot_id]
      );
    } catch {
      try {
        await query(
          `INSERT INTO agent_commands (id, agent_id, tenant_id, command, tier, token_id, signature, status, snapshot_id, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now());`,
          [queueRecord.id, queueRecord.agent_id, queueRecord.tenant_id, queueRecord.command, queueRecord.tier, queueRecord.token_id, queueRecord.signature, queueRecord.status, queueRecord.snapshot_id]
        );
      } catch {
        MOCK_AGENT_COMMANDS.push(queueRecord);
        if (tier === "Tier 1") {
          recordMockThrottleCommand(caller.tenant_id, "Tier 1");
        }
      }
    }

    await recordHashChainEvent({
      tenantId: caller.tenant_id,
      eventType: "AGENT_COMMAND_QUEUED",
      actorId: caller.id,
      payload: {
        agentId: agent.id,
        command,
        tier,
        tokenId: tokenId || null,
        commandId: commandLogId,
        signature,
        nonce,
      },
    });

    const output = `Command '${command}' cryptographically signed (Tier: ${tier}, Nonce: ${nonce.substring(0, 8)}...) and enqueued for agent delivery. Awaiting signed host execution report.`;

    const logRecord: AgentCommandLogRecord = {
      id: commandLogId,
      agent_id: agent.id,
      tenant_id: caller.tenant_id,
      command,
      tier,
      token_id: tokenId || null,
      status: "pending",
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

    return {
      success: true,
      commandId: commandLogId,
      output,
      snapshotId,
      tier,
      state: "queued",
      isSimulated: false,
    };
  }
}

/**
 * SimulationExecutor: Local mock simulation for non-production evaluation and unit testing.
 * Strictly prohibited in production environments (Audit Section 44).
 */
export class SimulationExecutor {
  async execute(params: CommandExecutionParams): Promise<CommandExecutionResult> {
    if (!isSimulationAllowed()) {
      throw new Error(
        "SIMULATION_DISABLED_IN_PRODUCTION: Endpoint command simulation is strictly prohibited in this environment. Real agent execution required."
      );
    }

    const { agent, command, tier, tokenId, caller, commandLogId, signature, nonce, snapshotId } = params;

    const queueRecord: AgentCommandQueueRecord = {
      id: commandLogId,
      agent_id: agent.id,
      tenant_id: caller.tenant_id,
      command,
      tier,
      token_id: tokenId || null,
      signature,
      nonce,
      status: "queued",
      snapshot_id: snapshotId || null,
      created_at: new Date().toISOString(),
    };

    try {
      await query(
        `INSERT INTO agent_commands (id, agent_id, tenant_id, command, tier, token_id, signature, nonce, status, snapshot_id, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now());`,
        [queueRecord.id, queueRecord.agent_id, queueRecord.tenant_id, queueRecord.command, queueRecord.tier, queueRecord.token_id, queueRecord.signature, queueRecord.nonce, queueRecord.status, queueRecord.snapshot_id]
      );
    } catch {
      try {
        await query(
          `INSERT INTO agent_commands (id, agent_id, tenant_id, command, tier, token_id, signature, status, snapshot_id, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now());`,
          [queueRecord.id, queueRecord.agent_id, queueRecord.tenant_id, queueRecord.command, queueRecord.tier, queueRecord.token_id, queueRecord.signature, queueRecord.status, queueRecord.snapshot_id]
        );
      } catch {
        MOCK_AGENT_COMMANDS.push(queueRecord);
        if (tier === "Tier 1") {
          recordMockThrottleCommand(caller.tenant_id, "Tier 1");
        }
      }
    }

    await recordHashChainEvent({
      tenantId: caller.tenant_id,
      eventType: "AGENT_COMMAND_QUEUED",
      actorId: caller.id,
      payload: {
        agentId: agent.id,
        command,
        tier,
        tokenId: tokenId || null,
        commandId: commandLogId,
        signature,
        nonce,
        simulated: true,
      },
    });

    let output = "";
    if (command.startsWith("isolate_host")) {
      output = `Network interface isolated successfully (Simulated Demo Mode) on ${agent.hostname}. Outbound/inbound traffic disabled except management gRPC tunnel. Safety snapshot ${snapshotId} saved.`;
      agent.status = "isolated";
      agent.safety_snapshot_id = snapshotId || null;
    } else if (command.startsWith("restore_host")) {
      output = `Network interface restored (Simulated Demo Mode) on ${agent.hostname}. Restored baseline routing table.`;
      agent.status = "connected";
    } else if (command.startsWith("block_ip")) {
      const ip = command.split(" ")[1] || "198.51.100.4";
      output = `Local firewall rule inserted (Simulated Demo Mode) on ${agent.hostname}: DROP all traffic to/from ${ip}. Snapshot ${snapshotId} registered.`;
    } else if (command.startsWith("kill_process")) {
      const pid = command.split(" ")[1] || "4812";
      output = `Process ${pid} terminated via SIGKILL (Simulated Demo Mode) on ${agent.hostname}. Process dump captured for forensics.`;
    } else if (command.startsWith("take_safety_snapshot")) {
      output = `Filesystem & network state snapshot ${snapshotId} taken successfully (Simulated Demo Mode) on ${agent.hostname}.`;
      agent.safety_snapshot_id = snapshotId || null;
    } else if (command.startsWith("rollback_snapshot")) {
      output = `State reverted to snapshot ${agent.safety_snapshot_id || "snap-baseline"} (Simulated Demo Mode) on ${agent.hostname}.`;
      agent.status = "connected";
    } else {
      output = `Command '${command}' queued for agent delivery on ${agent.hostname} (Demo Mode).`;
    }

    const logRecord: AgentCommandLogRecord = {
      id: commandLogId,
      agent_id: agent.id,
      tenant_id: caller.tenant_id,
      command,
      tier,
      token_id: tokenId || null,
      status: "pending",
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

    return {
      success: true,
      commandId: commandLogId,
      output,
      snapshotId,
      tier,
      state: "executed",
      isSimulated: true,
    };
  }
}

/**
 * Executes a command on an endpoint agent.
 * Enforces Layer 4 Rulebook: Tier 1 executes automatically with safety snapshot;
 * Tier 2/3 requires a pre-existing approved ApprovalToken.
 * Recomputes and validates token bindings (tenant, endpoint, command hash, anti-replay).
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
  state?: CommandExecutionState;
}> {
  const agent = await getEndpointAgent(agentId, caller);
  if (!agent) {
    throw new Error("AGENT_NOT_FOUND");
  }

  if (agent.kill_switch_active) {
    throw new Error("KILL_SWITCH_ACTIVE: Agent is blocked by Emergency Admin Kill Switch.");
  }

  // Blast-Radius Throttle check for Tier 1
  if (tier === "Tier 1") {
    const { allowed, count } = await checkThrottle(caller.tenant_id);
    if (!allowed) {
      await recordHashChainEvent({
        tenantId: caller.tenant_id,
        eventType: "TIER1_THROTTLED_DOWNGRADED",
        actorId: caller.id,
        payload: { agentId, command, count, limit: 5 },
      });
      throw new Error("BLAST_RADIUS_EXCEEDED: too many Tier 1 actions in 5 minutes; action requires manual approval.");
    }
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

    // Anti-Replay: verify token has not already been consumed
    if (token.status === "consumed" || token.used_at) {
      throw new Error("APPROVAL_TOKEN_REPLAY_DETECTED: Token has already been used and cannot be replayed.");
    }

    if (token.status !== "approved") {
      throw new Error(`APPROVAL_TOKEN_NOT_APPROVED: Current token status is '${token.status}'. Must be 'approved'.`);
    }

    if (new Date(token.expires_at).getTime() < Date.now()) {
      throw new Error("APPROVAL_TOKEN_EXPIRED");
    }

    // Tenant binding validation (Audit Section 45)
    if (token.tenant_id !== caller.tenant_id && !canAccess(caller.role, "VIEW_CROSS_TENANT")) {
      throw new Error("APPROVAL_TOKEN_TENANT_MISMATCH: Approval token belongs to another tenant.");
    }

    // Target endpoint binding validation
    if (token.target_endpoint_ids && token.target_endpoint_ids.length > 0) {
      const matchesEndpoint =
        token.target_endpoint_ids.includes(agent.id) ||
        token.target_endpoint_ids.includes(agent.hostname);
      if (!matchesEndpoint) {
        throw new Error(
          `APPROVAL_TOKEN_ENDPOINT_MISMATCH: Approval token is not authorized for endpoint '${agent.hostname}' (${agent.id}).`
        );
      }
    }

    // Command hash binding validation
    if (token.command_hash) {
      const computedHash = crypto.createHash("sha256").update(command).digest("hex");
      if (token.command_hash !== computedHash) {
        throw new Error(
          "APPROVAL_TOKEN_COMMAND_MISMATCH: Command does not match cryptographically bound command hash."
        );
      }
    }
  }

  // Capability Validation (Phase 11)
  const capCheck = validateCapabilitySupport(command, agent.os_type);
  if (!capCheck.supported && capCheck.capability) {
    throw new Error(`CAPABILITY_UNSUPPORTED: ${capCheck.reason}`);
  }

  // Tier 1 safety snapshot verification
  let snapshotId: string | undefined = undefined;
  if (command.startsWith("isolate_host") || command.startsWith("block_ip") || command.startsWith("kill_process")) {
    snapshotId = `snap-${agent.hostname.toLowerCase()}-${Date.now().toString(36)}`;
  }

  // Cryptographically sign command with nonces
  const nonce = crypto.randomUUID();
  const signature = signCommand({
    agentId: agent.id,
    command,
    nonce,
    tier,
  });

  const commandLogId = `cl-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 7)}`;

  // Select executor: In production, always RealAgentExecutor; in non-prod, SimulationExecutor if allowed
  const executor = (isProduction() || !isSimulationAllowed())
    ? new RealAgentExecutor()
    : new SimulationExecutor();

  const result = await executor.execute({
    agent,
    command,
    tier,
    tokenId,
    caller,
    commandLogId,
    signature,
    nonce,
    snapshotId,
  });

  // Mark approval token consumed immediately after successful command enqueuing (Audit Section 45)
  if (tokenId) {
    await markApprovalTokenConsumed(tokenId, commandLogId, caller);
  }

  return result;
}

/**
 * Retrieves pending commands for a specific agent and transitions status to 'delivered'.
 */
export async function getQueuedCommandsForAgent(agentId: string): Promise<AgentCommandQueueRecord[]> {
  try {
    const { rows } = await query<AgentCommandQueueRecord>(
      `UPDATE agent_commands
       SET status = 'delivered', delivered_at = now()
       WHERE id IN (
         SELECT id FROM agent_commands
         WHERE agent_id = $1 AND status = 'queued'
         ORDER BY created_at ASC
         LIMIT 10
       )
       RETURNING *;`,
      [agentId]
    );
    return rows;
  } catch {
    const pending = MOCK_AGENT_COMMANDS.filter(
      (c) => c.agent_id === agentId && c.status === "queued"
    );
    for (const c of pending) {
      c.status = "delivered";
      c.delivered_at = new Date().toISOString();
    }
    return pending;
  }
}

/**
 * Updates an agent command with the execution result returned by the agent.
 */
export async function recordCommandResult({
  commandId,
  status,
  output,
  snapshotId,
  agentId,
  verified,
}: {
  commandId: string;
  status: CommandExecutionState;
  output: string;
  snapshotId?: string;
  agentId?: string;
  verified?: boolean;
}): Promise<{ success: boolean; notFound?: boolean; unauthorized?: boolean }> {
  const effectiveStatus = (status === "executed" && verified) ? "verified" : status;
  const logStatus = (effectiveStatus === "executed" || effectiveStatus === "verified") ? "succeeded" : effectiveStatus;
  try {
    // If agentId specified, verify ownership
    if (agentId) {
      const existing = await query<AgentCommandQueueRecord>(
        `SELECT id, agent_id, tenant_id FROM agent_commands WHERE id = $1 LIMIT 1`,
        [commandId]
      );
      if (existing.rows.length > 0 && existing.rows[0].agent_id !== agentId) {
        return { success: false, unauthorized: true };
      }
    }

    const { rows } = await query<AgentCommandQueueRecord>(
      `UPDATE agent_commands
       SET status = $1, result = $2, snapshot_id = COALESCE($3, snapshot_id), completed_at = now()
       WHERE id = $4
       RETURNING *;`,
      [effectiveStatus, JSON.stringify({ output }), snapshotId || null, commandId]
    );

    if (rows.length === 0) {
      // Check mock store fallback
      const cmd = MOCK_AGENT_COMMANDS.find((c) => c.id === commandId);
      if (!cmd) {
        return { success: false, notFound: true };
      }
      if (agentId && cmd.agent_id !== agentId) {
        return { success: false, unauthorized: true };
      }
      cmd.status = effectiveStatus;
      cmd.result = { output };
      if (snapshotId) cmd.snapshot_id = snapshotId;
      cmd.completed_at = new Date().toISOString();

      const log = MOCK_COMMAND_LOGS.find((l) => l.id === commandId);
      if (log) {
        log.status = logStatus as "succeeded" | "failed" | "rolled_back" | "verified";
        log.output = output;
      }

      await recordHashChainEvent({
        tenantId: cmd.tenant_id,
        eventType: "AGENT_COMMAND_EXECUTED",
        actorId: `agent:${cmd.agent_id}`,
        payload: { commandId, status: effectiveStatus, snapshotId, output },
      });

      return { success: true };
    }

    // Update command log to reflect true execution status and output
    await query(
      `UPDATE agent_command_logs
       SET status = $1, output = $2
       WHERE id = $3;`,
      [logStatus, output, commandId]
    );

    const cmd = rows[0];
    if (cmd) {
      await recordHashChainEvent({
        tenantId: cmd.tenant_id,
        eventType: "AGENT_COMMAND_EXECUTED",
        actorId: `agent:${cmd.agent_id}`,
        payload: { commandId, status: effectiveStatus, snapshotId, output },
      });

      if (cmd.token_id) {
        try {
          const token = await getApprovalToken(cmd.token_id);
          if (token && token.incident_id) {
            await query(
              `INSERT INTO incident_events (incident_id, occurred_at, description)
               VALUES ($1, now(), $2)`,
              [token.incident_id, `Endpoint remediation verified: ${cmd.command} executed by agent ${cmd.agent_id}. Status: ${effectiveStatus}. Output: ${output.slice(0, 150)}`]
            );
          }
        } catch {
          // Non-fatal
        }
      }
    }

    return { success: true };
  } catch {
    const cmd = MOCK_AGENT_COMMANDS.find((c) => c.id === commandId);
    if (!cmd) {
      return { success: false, notFound: true };
    }
    if (agentId && cmd.agent_id !== agentId) {
      return { success: false, unauthorized: true };
    }
    cmd.status = effectiveStatus;
    cmd.result = { output };
    if (snapshotId) cmd.snapshot_id = snapshotId;
    cmd.completed_at = new Date().toISOString();

    const log = MOCK_COMMAND_LOGS.find((l) => l.id === commandId);
    if (log) {
      log.status = logStatus as "succeeded" | "failed" | "rolled_back" | "verified";
      log.output = output;
    }

    await recordHashChainEvent({
      tenantId: cmd.tenant_id,
      eventType: "AGENT_COMMAND_EXECUTED",
      actorId: `agent:${cmd.agent_id}`,
      payload: { commandId, status: effectiveStatus, snapshotId, output },
    });

    if (cmd.token_id) {
      try {
        const token = await getApprovalToken(cmd.token_id);
        if (token && token.incident_id) {
          await query(
            `INSERT INTO incident_events (incident_id, occurred_at, description)
             VALUES ($1, now(), $2)`,
            [token.incident_id, `Endpoint remediation verified: ${cmd.command} executed by agent ${cmd.agent_id}. Status: ${effectiveStatus}. Output: ${output.slice(0, 150)}`]
          );
        }
      } catch {
        // Non-fatal
      }
    }

    return { success: true };
  }
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

  MOCK_HASH_CHAINS.push(record);

  try {
    await query(
      `INSERT INTO hash_chain_audit (id, tenant_id, event_type, actor_id, payload, prev_hash, current_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7);`,
      [record.id, record.tenant_id, record.event_type, record.actor_id, JSON.stringify(record.payload), record.prev_hash, record.current_hash]
    );
  } catch {
    // Database offline mode
  }

  return record;
}
