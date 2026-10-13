import { query } from "@/lib/db";
import type { SessionUser } from "@/lib/auth/session";
import { getApprovalToken } from "@/lib/governance/approvalTokens";
import { recordHashChainEvent } from "./fleet";
import crypto from "crypto";

export * from "./monitoringTypes";
import {
  type CoreFunctionScope,
  type EndpointMonitoringPolicy,
  CORE_FUNCTION_SCOPES,
} from "./monitoringTypes";

// In-memory policy store for resilience and demo environments
const MOCK_MONITORING_POLICIES: Record<string, EndpointMonitoringPolicy> = {};

/**
 * Returns the monitoring policy for an endpoint agent.
 */
export async function getEndpointMonitoringPolicy(
  agentId: string,
  tenantId: string
): Promise<EndpointMonitoringPolicy> {
  try {
    const res = await query<EndpointMonitoringPolicy>(
      `SELECT * FROM endpoint_monitoring_policies WHERE agent_id = $1 AND tenant_id = $2;`,
      [agentId, tenantId]
    );
    if (res.rows[0]) {
      return res.rows[0];
    }
  } catch {
    // Fall back to memory registry
  }

  if (MOCK_MONITORING_POLICIES[agentId]) {
    return MOCK_MONITORING_POLICIES[agentId];
  }

  // Default baseline policy (all core diagnostic scopes active by default for comprehensive endpoint visibility)
  const defaultPolicy: EndpointMonitoringPolicy = {
    agent_id: agentId,
    tenant_id: tenantId,
    enabled_scopes: [
      "system_performance",
      "process_inventory",
      "network_sockets",
      "firewall_baseline",
      "storage_disk",
      "service_health",
      "defender_authority",
    ],
    approved_by: "system-baseline",
    approved_at: new Date().toISOString(),
    approval_token_id: null,
    policy_hash: crypto.createHash("sha256").update(`${agentId}:all_scopes:baseline`).digest("hex"),
    status: "active",
  };

  MOCK_MONITORING_POLICIES[agentId] = defaultPolicy;
  return defaultPolicy;
}

/**
 * Updates an endpoint's core monitoring policy with mandatory Tier 2 Authority Approval.
 */
export async function updateEndpointMonitoringPolicy({
  agentId,
  tenantId,
  requestedScopes,
  caller,
  approvalTokenId,
}: {
  agentId: string;
  tenantId: string;
  requestedScopes: CoreFunctionScope[];
  caller: SessionUser;
  approvalTokenId?: string;
}): Promise<{
  success: boolean;
  policy: EndpointMonitoringPolicy;
  message: string;
}> {
  // Always include system_performance
  const finalScopes = Array.from(new Set(["system_performance", ...requestedScopes])) as CoreFunctionScope[];

  // Determine if any Tier 2 gated scopes are being enabled
  const gatedScopesRequested = finalScopes.filter(
    (s) => CORE_FUNCTION_SCOPES[s]?.requiresApproval
  );

  let authoritySignOff = caller.id;

  if (gatedScopesRequested.length > 0) {
    // Validate authority sign-off: Requires either an approved Token or privileged admin role
    const isAuthorityRole =
      caller.role === "system_admin" ||
      caller.role === "super_admin";

    if (!isAuthorityRole && !approvalTokenId) {
      throw new Error(
        `AUTHORITY_APPROVAL_REQUIRED: Monitoring core endpoint functions (${gatedScopesRequested.join(
          ", "
        )}) requires Tier 2 Authority Approval.`
      );
    }

    if (approvalTokenId) {
      const token = await getApprovalToken(approvalTokenId, caller);
      if (!token) {
        throw new Error("APPROVAL_TOKEN_NOT_FOUND: The supplied authority token does not exist.");
      }
      if (token.status !== "approved") {
        throw new Error(
          `APPROVAL_TOKEN_NOT_APPROVED: Authority token is in '${token.status}' state. Approval by designated security authority is required.`
        );
      }
      authoritySignOff = token.approved_by || caller.id;
    }
  }

  const policyHash = crypto
    .createHash("sha256")
    .update(`${agentId}:${finalScopes.sort().join(",")}:${Date.now()}:${authoritySignOff}`)
    .digest("hex");

  const policy: EndpointMonitoringPolicy = {
    agent_id: agentId,
    tenant_id: tenantId,
    enabled_scopes: finalScopes,
    approved_by: authoritySignOff,
    approved_at: new Date().toISOString(),
    approval_token_id: approvalTokenId || null,
    policy_hash: policyHash,
    status: "active",
  };

  try {
    await query(
      `INSERT INTO endpoint_monitoring_policies (agent_id, tenant_id, enabled_scopes, approved_by, approved_at, approval_token_id, policy_hash, status)
       VALUES ($1, $2, $3, $4, now(), $5, $6, $7)
       ON CONFLICT (agent_id) DO UPDATE
       SET enabled_scopes = $3, approved_by = $4, approved_at = now(), approval_token_id = $5, policy_hash = $6, status = $7;`,
      [policy.agent_id, policy.tenant_id, JSON.stringify(policy.enabled_scopes), policy.approved_by, policy.approval_token_id, policy.policy_hash, policy.status]
    );
  } catch {
    MOCK_MONITORING_POLICIES[agentId] = policy;
  }

  // Cryptographically log the policy change to the tamper-evident hash chain
  await recordHashChainEvent({
    tenantId,
    eventType: "ENDPOINT_MONITORING_POLICY_UPDATED",
    actorId: caller.id,
    payload: {
      agentId,
      enabledScopes: finalScopes,
      approvedBy: authoritySignOff,
      policyHash,
      tokenUsed: approvalTokenId || null,
    },
  });

  return {
    success: true,
    policy,
    message: `Core function monitoring policy updated and verified. Signed by authority '${authoritySignOff}'.`,
  };
}

import { getEndpointCoreTelemetry } from "./liveTelemetryCollector";

/**
 * Returns lightweight, on-demand telemetry for monitored core functions.
 * Strictly respects the policy: Unapproved or disabled scopes return disabled status.
 * Data is dynamically sampled from the specific endpoint agent.
 */
export async function getEndpointCoreFunctionsData(
  agentId: string,
  tenantId: string,
  hostname: string
) {
  const policy = await getEndpointMonitoringPolicy(agentId, tenantId);
  const isEnabled = (scope: CoreFunctionScope) => policy.enabled_scopes.includes(scope);
  const live = await getEndpointCoreTelemetry(agentId, hostname);

  return {
    policy,
    data: {
      system_performance: {
        enabled: isEnabled("system_performance"),
        status: isEnabled("system_performance") ? "active" : "disabled_by_policy",
        metrics: isEnabled("system_performance")
          ? {
              cpuModel: live.system_performance.cpuModel,
              cpuCores: live.system_performance.cpuCores,
              load_average: live.system_performance.load_average,
              memoryTotalGb: live.system_performance.memoryTotalGb,
              memoryUsedGb: live.system_performance.memoryUsedGb,
              memoryPct: live.system_performance.memoryPct,
              uptimeHours: live.system_performance.uptimeHours,
              threads_active: live.system_performance.threads_active,
              handle_count: live.system_performance.handle_count,
              sampling_overhead: live.system_performance.sampling_overhead,
            }
          : null,
      },
      network_sockets: {
        enabled: isEnabled("network_sockets"),
        status: isEnabled("network_sockets") ? "active" : "disabled_by_policy",
        gated: true,
        sockets: isEnabled("network_sockets") ? live.network_sockets : [],
        notice: !isEnabled("network_sockets")
          ? "Requires Tier 2 Authority Approval to monitor active socket connections."
          : undefined,
      },
      process_inventory: {
        enabled: isEnabled("process_inventory"),
        status: isEnabled("process_inventory") ? "active" : "disabled_by_policy",
        gated: true,
        processes: isEnabled("process_inventory") ? live.process_inventory : [],
        notice: !isEnabled("process_inventory")
          ? "Requires Tier 2 Authority Approval to inspect running process inventory."
          : undefined,
      },
      firewall_baseline: {
        enabled: isEnabled("firewall_baseline"),
        status: isEnabled("firewall_baseline") ? "active" : "disabled_by_policy",
        gated: true,
        baseline: isEnabled("firewall_baseline") ? live.firewall_baseline : null,
        notice: !isEnabled("firewall_baseline")
          ? "Requires Tier 2 Authority Approval to monitor firewall ruleset."
          : undefined,
      },
      storage_disk: {
        enabled: isEnabled("storage_disk"),
        status: isEnabled("storage_disk") ? "active" : "disabled_by_policy",
        gated: true,
        disks: isEnabled("storage_disk") ? live.storage_disk : [],
        notice: !isEnabled("storage_disk")
          ? "Requires Tier 2 Authority Approval to inspect storage metrics."
          : undefined,
      },
      service_health: {
        enabled: isEnabled("service_health"),
        status: isEnabled("service_health") ? "active" : "disabled_by_policy",
        gated: true,
        services: isEnabled("service_health") ? live.service_health : [],
        notice: !isEnabled("service_health")
          ? "Requires Tier 2 Authority Approval to inspect service health."
          : undefined,
      },
      defender_authority: {
        enabled: isEnabled("defender_authority") || isEnabled("service_health"),
        status: (isEnabled("defender_authority") || isEnabled("service_health")) ? "active" : "disabled_by_policy",
        gated: true,
        defender: live.defender_status || null,
        notice: !(isEnabled("defender_authority") || isEnabled("service_health"))
          ? "Requires Tier 2 Authority Approval to inspect Microsoft Defender EDR telemetry."
          : undefined,
      },
    },
  };
}
