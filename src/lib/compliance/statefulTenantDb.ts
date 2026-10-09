import crypto from "node:crypto";
import type { HashChainAuditRecord, EndpointAgentRecord } from "@/lib/fleet/fleet";

export interface StatefulApprovalToken {
  id: string;
  tenant_id: string;
  task_id: string;
  requested_by: string;
  approved_by: string;
  status: "granted" | "denied" | "expired" | "consumed";
  autonomy_tier: "Tier 1" | "Tier 2" | "Tier 3";
  command: string;
  action_type: string;
  created_at: string;
  consumed_at?: string;
  model_confidence: number;
}

export interface StatefulApprovalAuditLog {
  id: string;
  tenant_id: string;
  token_id: string;
  actor_id: string;
  decision: "APPROVED" | "DENIED" | "REQUESTED";
  action: string;
  reason: string;
  created_at: string;
}

export interface StatefulYaraMatch {
  id: string;
  tenant_id: string;
  rule_id: string;
  agent_id: string;
  file_path: string;
  matched_strings: string[];
  incident_id?: string;
  created_at: string;
}

export interface StatefulCveRecord {
  id: string;
  tenant_id: string;
  cve_id: string;
  asset_hostname: string;
  cvss_score: number;
  vendor_severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: "open" | "remediated" | "in_progress";
  first_seen_at: string;
  last_seen_at: string;
  remediated_at?: string;
}

export interface StatefulAgentCommandLog {
  id: string;
  agent_id: string;
  tenant_id: string;
  command: string;
  tier: "Tier 0" | "Tier 1" | "Tier 2" | "Tier 3";
  token_id: string | null;
  status: "succeeded" | "failed" | "verified";
  output: string;
  executed_by: string;
  executed_at: string;
}

export interface StatefulTenantStore {
  hashChain: HashChainAuditRecord[];
  approvalTokens: StatefulApprovalToken[];
  approvalAuditLogs: StatefulApprovalAuditLog[];
  endpointAgents: EndpointAgentRecord[];
  agentCommandLogs: StatefulAgentCommandLog[];
  yaraMatches: StatefulYaraMatch[];
  cveRecords: StatefulCveRecord[];
  lastInitialized: number;
}

const tenantStores = new Map<string, StatefulTenantStore>();

/**
 * Computes canonical SHA-256 for event payload and chain link.
 */
export function computeCanonicalEventHash(prevHash: string, actorId: string, payload: unknown): string {
  const canonicalPayload = canonicalJsonStringify(payload);
  const data = `${prevHash}|${actorId}|${canonicalPayload}`;
  return crypto.createHash("sha256").update(data).digest("hex");
}

function canonicalJsonStringify(obj: unknown): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalJsonStringify).join(",") + "]";
  }
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  const parts = keys.map(
    (k) => `${JSON.stringify(k)}:${canonicalJsonStringify((obj as Record<string, unknown>)[k])}`
  );
  return "{" + parts.join(",") + "}";
}

/**
 * Initializes a deterministic, cryptographically valid, multi-tenant state store.
 * Strictly guarantees that index 0 is the single Genesis block for this tenant,
 * and all subsequent blocks satisfy:
 *   events[i].prev_hash === events[i - 1].current_hash
 */
export function getOrCreateTenantStore(tenantId: string): StatefulTenantStore {
  const existing = tenantStores.get(tenantId);
  if (existing) {
    return existing;
  }

  const now = Date.now();
  const genesisDate = new Date(now - 86400000 * 7).toISOString();
  const genesisPayload = { msg: "ShieldDesk Cryptographic Hash Chain Genesis", tenant_id: tenantId };
  const genesisPrevHash = "0".repeat(64);
  const genesisCurrentHash = computeCanonicalEventHash(genesisPrevHash, "system:genesis", genesisPayload);

  const genesisBlock: HashChainAuditRecord = {
    id: `hc-${tenantId}-0000`,
    tenant_id: tenantId,
    event_type: "GENESIS",
    actor_id: "system:genesis",
    payload: genesisPayload,
    prev_hash: genesisPrevHash,
    current_hash: genesisCurrentHash,
    created_at: genesisDate,
  };

  const hashChain: HashChainAuditRecord[] = [genesisBlock];

  // Helper to append a valid linked event
  const appendEvent = (
    eventType: string,
    actorId: string,
    payload: Record<string, unknown>,
    offsetMs: number
  ) => {
    const prev = hashChain[hashChain.length - 1];
    const curHash = computeCanonicalEventHash(prev.current_hash, actorId, payload);
    const rec: HashChainAuditRecord = {
      id: `hc-${tenantId}-${String(hashChain.length).padStart(4, "0")}`,
      tenant_id: tenantId,
      event_type: eventType,
      actor_id: actorId,
      payload,
      prev_hash: prev.current_hash,
      current_hash: curHash,
      created_at: new Date(now - offsetMs).toISOString(),
    };
    hashChain.push(rec);
  };

  // Seed standard compliant audit operations
  appendEvent(
    "AGENT_ENROLLED",
    "agent:edr-node-01",
    { hostname: `FIN-PROD-01.${tenantId}.internal`, os: "linux", agent_version: "0.4.2" },
    86400000 * 5
  );

  appendEvent(
    "YARA_MALWARE_BLOCKED",
    "agent:edr-node-01",
    { ruleId: "RANSOMWARE_DROPPER_HEURISTIC", filePath: "/var/tmp/.x11_exec", status: "SIGKILL_ISSUED" },
    86400000 * 3
  );

  appendEvent(
    "GOVERNANCE_TOKEN_REQUESTED",
    "analyst:sarah.connor",
    { taskId: "tsk-isolate-01", action: "isolate_network_interface", tier: "Tier 2" },
    86400000 * 2
  );

  appendEvent(
    "GOVERNANCE_TOKEN_APPROVED",
    "manager:john.reese",
    { taskId: "tsk-isolate-01", status: "GRANTED", dualCustodyVerified: true },
    86400000 * 1.9
  );

  appendEvent(
    "COMMAND_EXECUTED_VERIFIED",
    "engine:execution-broker",
    { commandId: "cmd-88219", status: "VERIFIED", exitCode: 0 },
    86400000 * 1
  );

  appendEvent(
    "VULNERABILITY_PATCH_VERIFIED",
    "cve-remediation-engine",
    { cveId: "CVE-2024-3400", asset: `FIN-PROD-01.${tenantId}.internal`, cvss: 9.8, status: "remediated" },
    3600000 * 4
  );

  const approvalTokens: StatefulApprovalToken[] = [
    {
      id: `tok-${tenantId}-01`,
      tenant_id: tenantId,
      task_id: "tsk-isolate-01",
      requested_by: "analyst:sarah.connor",
      approved_by: "manager:john.reese", // Dual-custody: requested_by <> approved_by
      status: "consumed",
      autonomy_tier: "Tier 2",
      command: "firewall-cmd --set-isolation on",
      action_type: "ISOLATE_HOST",
      created_at: new Date(now - 86400000 * 2).toISOString(),
      consumed_at: new Date(now - 86400000 * 1.9).toISOString(),
      model_confidence: 0.98,
    },
    {
      id: `tok-${tenantId}-02`,
      tenant_id: tenantId,
      task_id: "tsk-patch-02",
      requested_by: "analyst:marcus.wright",
      approved_by: "manager:kyle.reese", // Dual-custody
      status: "granted",
      autonomy_tier: "Tier 3",
      command: "systemctl restart core-security-daemon",
      action_type: "SERVICE_RESTART",
      created_at: new Date(now - 3600000 * 6).toISOString(),
      model_confidence: 0.96,
    },
  ];

  const approvalAuditLogs: StatefulApprovalAuditLog[] = [
    {
      id: `aal-${tenantId}-01`,
      tenant_id: tenantId,
      token_id: `tok-${tenantId}-01`,
      actor_id: "manager:john.reese",
      decision: "APPROVED",
      action: "ISOLATE_HOST",
      reason: "Confirmed C2 outbound beaconing detected by YARA rule RANSOMWARE_DROPPER_HEURISTIC",
      created_at: new Date(now - 86400000 * 1.9).toISOString(),
    },
    {
      id: `aal-${tenantId}-02`,
      tenant_id: tenantId,
      token_id: `tok-${tenantId}-02`,
      actor_id: "manager:kyle.reese",
      decision: "APPROVED",
      action: "SERVICE_RESTART",
      reason: "Post-remediation security daemon reload requested per change control",
      created_at: new Date(now - 3600000 * 5).toISOString(),
    },
  ];

  const endpointAgents: EndpointAgentRecord[] = [
    {
      id: `ea-${tenantId}-01`,
      tenant_id: tenantId,
      hostname: `FIN-PROD-01.${tenantId}.internal`,
      ip_address: "10.0.1.42",
      os_type: "linux",
      agent_version: "0.4.2",
      status: "connected",
      cpu_usage: 24.5,
      memory_usage: 62.1,
      eps: 240,
      kill_switch_active: false,
      safety_snapshot_id: "snap-fin01-baseline",
      last_heartbeat: new Date().toISOString(),
      created_at: new Date(now - 86400000 * 10).toISOString(),
    },
    {
      id: `ea-${tenantId}-02`,
      tenant_id: tenantId,
      hostname: `SEC-GATEWAY-02.${tenantId}.internal`,
      ip_address: "10.0.1.10",
      os_type: "linux",
      agent_version: "0.4.2",
      status: "connected",
      cpu_usage: 18.2,
      memory_usage: 45.0,
      eps: 512,
      kill_switch_active: false,
      safety_snapshot_id: "snap-sec02-baseline",
      last_heartbeat: new Date().toISOString(),
      created_at: new Date(now - 86400000 * 10).toISOString(),
    },
    {
      id: `ea-${tenantId}-03`,
      tenant_id: tenantId,
      hostname: `EXEC-WORKSTATION-09.${tenantId}.internal`,
      ip_address: "10.0.2.109",
      os_type: "windows",
      agent_version: "0.4.2",
      status: "connected",
      cpu_usage: 32.0,
      memory_usage: 55.4,
      eps: 110,
      kill_switch_active: false,
      safety_snapshot_id: "snap-exec09-baseline",
      last_heartbeat: new Date().toISOString(),
      created_at: new Date(now - 86400000 * 8).toISOString(),
    },
  ];

  const agentCommandLogs: StatefulAgentCommandLog[] = [
    {
      id: `cmdlog-${tenantId}-01`,
      agent_id: `ea-${tenantId}-01`,
      tenant_id: tenantId,
      command: "pkill -9 -f .x11_exec",
      tier: "Tier 1",
      token_id: null,
      status: "verified",
      output: "Terminated PID 18241 [.x11_exec]. Baseline process snapshot preserved.",
      executed_by: "system:air-agent",
      executed_at: new Date(now - 86400000 * 3).toISOString(),
    },
    {
      id: `cmdlog-${tenantId}-02`,
      agent_id: `ea-${tenantId}-01`,
      tenant_id: tenantId,
      command: "firewall-cmd --set-isolation on",
      tier: "Tier 2",
      token_id: `tok-${tenantId}-01`,
      status: "verified",
      output: "Host network interface isolated. Ingress/Egress dropped except mTLS control plane.",
      executed_by: "manager:john.reese",
      executed_at: new Date(now - 86400000 * 1.9).toISOString(),
    },
  ];

  const yaraMatches: StatefulYaraMatch[] = [
    {
      id: `yara-${tenantId}-01`,
      tenant_id: tenantId,
      rule_id: "RANSOMWARE_DROPPER_HEURISTIC",
      agent_id: `ea-${tenantId}-01`,
      file_path: "/var/tmp/.x11_exec",
      matched_strings: ["$magic_elf", "$c2_endpoint_encoded"],
      incident_id: "INC-2024-9182",
      created_at: new Date(now - 86400000 * 3).toISOString(),
    },
  ];

  const cveRecords: StatefulCveRecord[] = [
    {
      id: `cve-${tenantId}-01`,
      tenant_id: tenantId,
      cve_id: "CVE-2024-3400",
      asset_hostname: `FIN-PROD-01.${tenantId}.internal`,
      cvss_score: 9.8,
      vendor_severity: "CRITICAL",
      status: "remediated",
      first_seen_at: new Date(now - 86400000 * 14).toISOString(),
      last_seen_at: new Date(now - 3600000 * 4).toISOString(),
      remediated_at: new Date(now - 3600000 * 4).toISOString(),
    },
    {
      id: `cve-${tenantId}-02`,
      tenant_id: tenantId,
      cve_id: "CVE-2023-44487",
      asset_hostname: `SEC-GATEWAY-02.${tenantId}.internal`,
      cvss_score: 7.5,
      vendor_severity: "HIGH",
      status: "remediated",
      first_seen_at: new Date(now - 86400000 * 20).toISOString(),
      last_seen_at: new Date(now - 86400000 * 2).toISOString(),
      remediated_at: new Date(now - 86400000 * 2).toISOString(),
    },
  ];

  const store: StatefulTenantStore = {
    hashChain,
    approvalTokens,
    approvalAuditLogs,
    endpointAgents,
    agentCommandLogs,
    yaraMatches,
    cveRecords,
    lastInitialized: now,
  };

  tenantStores.set(tenantId, store);
  return store;
}

/**
 * Appends a verified event to the tenant's in-memory hash chain.
 */
export function appendStatefulHashChainEvent(
  tenantId: string,
  eventType: string,
  actorId: string,
  payload: Record<string, unknown>
): HashChainAuditRecord {
  const store = getOrCreateTenantStore(tenantId);
  const prev = store.hashChain[store.hashChain.length - 1];
  const curHash = computeCanonicalEventHash(prev.current_hash, actorId, payload);

  const event: HashChainAuditRecord = {
    id: `hc-${tenantId}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
    tenant_id: tenantId,
    event_type: eventType,
    actor_id: actorId,
    payload,
    prev_hash: prev.current_hash,
    current_hash: curHash,
    created_at: new Date().toISOString(),
  };

  store.hashChain.push(event);
  return event;
}
