import { query } from "@/lib/db";
import type { SessionUser } from "@/lib/auth/session";
import { canAccess } from "@/lib/permissions";
import { getApprovalToken, markApprovalTokenConsumed } from "@/lib/governance/approvalTokens";
import { checkThrottle, recordMockThrottleCommand } from "@/lib/governance/blastRadiusThrottle";
import { signCommand } from "@/lib/fleet/commandSigning";
import { isDemoMode, isProduction, isSimulationAllowed } from "@/lib/config/environment";
import { validateCapabilitySupport, getCapability } from "./capabilities";
import { validateIpAddress } from "@/lib/utils/ipValidation";
import crypto from "crypto";
import os from "os";

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

// In-memory store for dynamically enrolled agents in development / production runtime.
// Test fixtures are isolated strictly to automated test runner environments.
export const MOCK_ENDPOINT_AGENTS: EndpointAgentRecord[] =
  process.env.NODE_ENV === "test"
    ? [

    ]
    : [];

export const MOCK_COMMAND_LOGS: AgentCommandLogRecord[] = [];

export const MOCK_HASH_CHAINS: HashChainAuditRecord[] = [];

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
export function removeMockEndpointAgent(agentId: string, tenantId?: string): boolean {
  const idx = MOCK_ENDPOINT_AGENTS.findIndex(
    (a) => (a.id === agentId || a.hostname === agentId) && (!tenantId || a.tenant_id === tenantId)
  );
  if (idx !== -1) {
    MOCK_ENDPOINT_AGENTS.splice(idx, 1);
    return true;
  }
  return false;
}

export async function listEndpointAgents(caller: SessionUser): Promise<EndpointAgentRecord[]> {
  const canCrossTenant =
    canAccess(caller.role, "VIEW_CROSS_TENANT") ||
    caller.role === "system_admin" ||
    caller.role === "super_admin";

  try {
    const { getLiveFleetAgents } = await import("./liveTelemetry");
    // When PostgreSQL is reachable, return the exact live fleet (even if 0 rows remain after user removal)
    // and enforce the 15-second heartbeat timeout so offline/stopped endpoints are marked 'disconnected'.
    return await getLiveFleetAgents(caller);
  } catch {
    // Database offline or test mode — fall back to in-memory store
  }

  const connectedIps = new Set<string>();
  return MOCK_ENDPOINT_AGENTS.filter(
    (a) => canCrossTenant || a.tenant_id === caller.tenant_id
  ).map((a) => {
    if (a.status === "connected" && a.ip_address) {
      const key = `${a.tenant_id}:${a.ip_address}`;
      if (connectedIps.has(key)) {
        return { ...a, status: "disconnected" as const, cpu_usage: 0, memory_usage: 0, eps: 0 };
      }
      connectedIps.add(key);
    }
    return a;
  });
}

/**
 * Retrieves a single endpoint agent by ID or hostname.
 * Strictly enforces Anti-Enumeration: returns null (leading to 404) if cross-tenant.
 */
export async function getEndpointAgent(
  identifier: string,
  caller: SessionUser
): Promise<EndpointAgentRecord | null> {
  const canCrossTenant =
    canAccess(caller.role, "VIEW_CROSS_TENANT") ||
    caller.role === "system_admin" ||
    caller.role === "super_admin";

  try {
    const sql = canCrossTenant
      ? `SELECT * FROM endpoint_agents WHERE id::text = $1 OR hostname = $1 LIMIT 1;`
      : `SELECT * FROM endpoint_agents WHERE (id::text = $1 OR hostname = $1) AND tenant_id = $2 LIMIT 1;`;
    const params = canCrossTenant ? [identifier] : [identifier, caller.tenant_id];

    const result = await query(sql, params);
    if (result && result.rows.length > 0) {
      const row = result.rows[0];
      const lastSeenRaw = row.last_seen_at || row.last_heartbeat || row.created_at || new Date();
      const lastSeenDate = new Date(lastSeenRaw as string | number | Date);
      const createdRaw = row.created_at || new Date();
      const createdDate = new Date(createdRaw as string | number | Date);
      return {
        id: String(row.id),
        tenant_id: String(row.tenant_id),
        hostname: String(row.hostname),
        ip_address: String(row.ip_address || "Unknown"),
        os_type: (row.os_type || "linux") as OsType,
        agent_version: String(row.agent_version || "0.4.2"),
        status: (row.status || "connected") as AgentStatus,
        cpu_usage: Number(row.cpu_usage || 0),
        memory_usage: Number(row.memory_usage || 0),
        eps: Number(row.eps || 0),
        kill_switch_active: Boolean(row.kill_switch_active),
        safety_snapshot_id: row.safety_snapshot_id ? String(row.safety_snapshot_id) : null,
        last_heartbeat: isNaN(lastSeenDate.getTime()) ? new Date().toISOString() : lastSeenDate.toISOString(),
        created_at: isNaN(createdDate.getTime()) ? new Date().toISOString() : createdDate.toISOString(),
      };
    }
  } catch (dbErr) {
    if (process.env.DATABASE_URL) {
      console.error("[getEndpointAgent] DB lookup failed, checking fallback:", dbErr);
    }
  }

  // Also check live telemetry store
  try {
    const { getLiveFleetAgents } = await import("./liveTelemetry");
    const liveAgents = await getLiveFleetAgents(caller);
    const liveMatch = liveAgents.find(
      (a) => a.id === identifier || a.hostname === identifier
    );
    if (liveMatch) return liveMatch;
  } catch { }

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
  const isCrossTenant =
    caller.role === "system_admin" || caller.role === "super_admin";

  try {
    if (agentId) {
      const sql = isCrossTenant
        ? `UPDATE endpoint_agents SET kill_switch_active = $1, status = CASE WHEN $1 = true THEN 'disconnected' ELSE 'connected' END WHERE (id::text = $2 OR hostname = $2) RETURNING id;`
        : `UPDATE endpoint_agents SET kill_switch_active = $1, status = CASE WHEN $1 = true THEN 'disconnected' ELSE 'connected' END WHERE (id::text = $2 OR hostname = $2) AND tenant_id = $3 RETURNING id;`;
      const params = isCrossTenant ? [active, agentId] : [active, agentId, caller.tenant_id];
      const res = await query(sql, params);
      count = res.rowCount || 0;
    } else {
      const sql = isCrossTenant
        ? `UPDATE endpoint_agents SET kill_switch_active = $1, status = CASE WHEN $1 = true THEN 'disconnected' ELSE 'connected' END RETURNING id;`
        : `UPDATE endpoint_agents SET kill_switch_active = $1, status = CASE WHEN $1 = true THEN 'disconnected' ELSE 'connected' END WHERE tenant_id = $2 RETURNING id;`;
      const params = isCrossTenant ? [active] : [active, caller.tenant_id];
      const res = await query(sql, params);
      count = res.rowCount || 0;
    }
  } catch {
    // mock fallback
    if (agentId) {
      const agent = MOCK_ENDPOINT_AGENTS.find(
        (a) => (a.id === agentId || a.hostname === agentId) && (isCrossTenant || a.tenant_id === caller.tenant_id)
      );
      if (agent) {
        agent.kill_switch_active = active;
        agent.status = active ? "disconnected" : "connected";
        count = 1;
      }
    } else {
      MOCK_ENDPOINT_AGENTS.filter((a) => isCrossTenant || a.tenant_id === caller.tenant_id).forEach((a) => {
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

    let output = `Command '${command}' cryptographically signed (Tier: ${tier}, Nonce: ${nonce.substring(0, 8)}...) and enqueued for agent delivery. Awaiting signed host execution report.`;

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
        `INSERT INTO agent_command_logs (id, agent_id, tenant_id, command, tier, token_id, status, output, executed_by, executed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now());`,
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
      output = `Network interface isolated successfully on ${agent.hostname}. Outbound/inbound traffic quarantined except management gRPC tunnel. Safety snapshot ${snapshotId} saved.`;
      agent.status = "isolated";
      agent.safety_snapshot_id = snapshotId || null;
    } else if (command.startsWith("restore_host")) {
      output = `Network interface restored on ${agent.hostname}. Restored baseline routing table.`;
      agent.status = "connected";
    } else if (command.startsWith("block_ip") || command.startsWith("block ip")) {
      const ip = (command.startsWith("block ip") ? command.replace(/^block ip\s+/i, "") : command.replace(/^block_ip\s+/i, "")).trim();
      output = `Local firewall rule inserted on ${agent.hostname}: DROP all traffic to/from ${ip}. Safety snapshot ${snapshotId} registered. Endpoint is DISCONNECTED from the fleet.`;
      agent.status = "disconnected";
      agent.cpu_usage = 0;
      agent.memory_usage = 0;
      agent.eps = 0;
    } else if (command.startsWith("unblock_ip") || command.startsWith("unblock ip")) {
      const ip = (command.startsWith("unblock ip") ? command.replace(/^unblock ip\s+/i, "") : command.replace(/^unblock_ip\s+/i, "")).trim();
      output = `Firewall block rule removed on ${agent.hostname} for IP ${ip}. Host connectivity restored.`;
    } else if (command.startsWith("kill_process")) {
      const pid = command.trim().split(/\s+/)[1] || "";
      output = `Process ${pid} terminated via SIGKILL on ${agent.hostname}. Process dump captured for forensics.`;
    } else if (command.startsWith("take_safety_snapshot")) {
      output = `Filesystem & network state snapshot ${snapshotId} taken successfully on ${agent.hostname}.`;
      agent.safety_snapshot_id = snapshotId || null;
    } else if (command.startsWith("rollback_snapshot")) {
      output = `State reverted to snapshot ${agent.safety_snapshot_id || "snap-baseline"} on ${agent.hostname}.`;
      agent.status = "connected";
    } else if (command.startsWith("defender_scan")) {
      const type = command.includes("full") ? "Full" : "Quick";
      output = `Microsoft Defender ${type} Scan initiated successfully on ${agent.hostname}. Scan task ID: mpscan-${Date.now().toString(36)}.`;
    } else if (command.startsWith("defender_update")) {
      output = `Microsoft Defender antivirus definition signatures updated successfully on ${agent.hostname}. Latest security intelligence applied.`;
    } else if (command.startsWith("defender_set_realtime")) {
      const state = command.includes("off") ? "DISABLED" : "ENABLED";
      output = `Microsoft Defender Real-Time Protection set to ${state} on ${agent.hostname}.`;
    } else if (command.startsWith("defender_remediate")) {
      output = `Active threat purged and neutralized via Microsoft Defender engine on ${agent.hostname}.`;
    } else if (command.startsWith("defender_add_exclusion")) {
      output = `Exclusion rule appended to Microsoft Defender inspection engine on ${agent.hostname}.`;
    } else if (command.startsWith("defender_remove_exclusion")) {
      output = `Exclusion rule removed from Microsoft Defender inspection engine on ${agent.hostname}.`;
    } else {
      output = `Command '${command}' queued for agent delivery on ${agent.hostname}.`;
    }

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
        `INSERT INTO agent_command_logs (id, agent_id, tenant_id, command, tier, token_id, status, output, executed_by, executed_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now());`,
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
  isSimulated?: boolean;
}> {
  const agent = await getEndpointAgent(agentId, caller);
  if (!agent) {
    throw new Error("AGENT_NOT_FOUND");
  }

  if (agent.kill_switch_active) {
    throw new Error("KILL_SWITCH_ACTIVE: Agent is blocked by Emergency Admin Kill Switch.");
  }

  // Parameter validation for targeted actions
  if (
    command.startsWith("block_ip") ||
    command.startsWith("block ip") ||
    command.startsWith("unblock_ip") ||
    command.startsWith("unblock ip")
  ) {
    const rawIp = (
      command.startsWith("block ip")
        ? command.replace(/^block ip\s+/i, "")
        : command.startsWith("block_ip")
          ? command.replace(/^block_ip\s+/i, "")
          : command.startsWith("unblock ip")
            ? command.replace(/^unblock ip\s+/i, "")
            : command.replace(/^unblock_ip\s+/i, "")
    ).trim();
    const val = validateIpAddress(rawIp);
    if (!val.valid) {
      throw new Error(`INVALID_IP_ADDRESS: ${val.error}`);
    }
  } else if (command.startsWith("kill_process")) {
    const rawPid = command.replace(/^kill_process\s+/i, "").trim();
    const numPid = parseInt(rawPid, 10);
    if (!rawPid || isNaN(numPid) || numPid <= 1) {
      throw new Error("INVALID_PID: Process ID must be a positive integer greater than 1.");
    }
  }

  if (isProduction()) {
    const { LicenseActivationService } = await import("@/lib/licensing/licenseActivation");
    if (!(await LicenseActivationService.isDeviceActive(agent.tenant_id, agent.id))) {
      throw new Error("LICENSE_ACTIVATION_REQUIRED: Active tenant-bound agent license is required before command execution.");
    }
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
    const isAuthorityRole =
      caller.role === "system_admin" ||
      caller.role === "super_admin" ||
      (caller.role === "responder" && command.startsWith("kill_process"));

    if (!tokenId) {
      if (!isAuthorityRole) {
        throw new Error(`APPROVAL_TOKEN_REQUIRED: Action '${command}' is ${tier} and requires an approved human sign-off token.`);
      }
    } else {
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
  }

  // Capability Validation (Phase 11)
  const capCheck = validateCapabilitySupport(command, agent.os_type);
  if (!capCheck.supported && capCheck.capability) {
    throw new Error(`CAPABILITY_UNSUPPORTED: ${capCheck.reason}`);
  }

  // Tier 1 safety snapshot verification
  let snapshotId: string | undefined = undefined;
  if (
    command.startsWith("isolate_host") ||
    command.startsWith("block_ip") ||
    command.startsWith("unblock_ip") ||
    command.startsWith("kill_process") ||
    command.startsWith("take_safety_snapshot") ||
    command.startsWith("firewall_")
  ) {
    const cleanHost = agent.hostname.toLowerCase().replace(/[^a-z0-9]/g, "-").slice(0, 16);
    snapshotId = `snap-${cleanHost}-${Date.now().toString(36)}`;
  }

  // Cryptographically sign command with nonces
  const nonce = crypto.randomUUID();
  const signature = signCommand({
    agentId: agent.id,
    command,
    nonce,
    tier,
  });

  const commandLogId = crypto.randomUUID();

  // In automated test runner, use SimulationExecutor for simulated unit test fixtures.
  // In dev and production runtimes, real agents always use RealAgentExecutor so commands reach the agent daemon.
  const isTestRunner = process.env.NODE_ENV === "test";
  const executor = (!isTestRunner || isProduction() || !isSimulationAllowed())
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
  let targetAgentUuid = agentId;
  try {
    const { rows: aRows } = await query<{ id: string }>(
      `SELECT id FROM endpoint_agents WHERE id::text = $1 OR hostname = $1 LIMIT 1;`,
      [agentId]
    );
    if (aRows.length > 0) {
      targetAgentUuid = aRows[0].id;
    }
  } catch {}

  try {
    const { rows } = await query<AgentCommandQueueRecord>(
      `UPDATE agent_commands
       SET status = 'delivered', delivered_at = now()
       WHERE id IN (
         SELECT id FROM agent_commands
         WHERE (agent_id = $1::uuid OR agent_id = $2::uuid) AND status = 'queued'
         ORDER BY created_at ASC
         LIMIT 10
       )
       RETURNING *;`,
      [targetAgentUuid, agentId]
    );
    if (rows && rows.length > 0) return rows;
  } catch (err) {
    console.warn("[Fleet] Error polling queued commands from database:", err);
  }

  const pending = MOCK_AGENT_COMMANDS.filter(
    (c) => (c.agent_id === agentId || c.agent_id === targetAgentUuid) && c.status === "queued"
  );
  for (const c of pending) {
    c.status = "delivered";
    c.delivered_at = new Date().toISOString();
  }
  return pending;
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
      let resolvedCallerUuid = agentId;
      try {
        const { rows: aRows } = await query<{ id: string }>(
          `SELECT id FROM endpoint_agents WHERE id::text = $1 OR hostname = $1 LIMIT 1;`,
          [agentId]
        );
        if (aRows.length > 0) {
          resolvedCallerUuid = aRows[0].id;
        }
      } catch {}

      const existing = await query<AgentCommandQueueRecord>(
        `SELECT id, agent_id, tenant_id FROM agent_commands WHERE id::text = $1 LIMIT 1`,
        [commandId]
      );
      if (
        existing.rows.length > 0 &&
        existing.rows[0].agent_id !== resolvedCallerUuid &&
        existing.rows[0].agent_id !== agentId
      ) {
        return { success: false, unauthorized: true };
      }
    }

    const { rows } = await query<AgentCommandQueueRecord>(
      `UPDATE agent_commands
       SET status = $1, result = $2, snapshot_id = COALESCE($3, snapshot_id), completed_at = now()
       WHERE id::text = $4
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
