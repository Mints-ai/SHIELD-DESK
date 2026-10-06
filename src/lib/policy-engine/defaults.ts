import { ActionPolicy, TenantSecurityPolicy } from "./types";

export const DEFAULT_ACTION_POLICIES: Record<string, ActionPolicy> = {
  gather_telemetry: {
    action: "gather_telemetry",
    description: "Read-only inspection and gathering of endpoint telemetry",
    conditions: { minRisk: "low" },
    modeBehaviors: { observe: "ALLOW", assist: "ALLOW", autopilot: "ALLOW" },
    maxBlastRadiusScore: 0,
    requireMfa: false,
  },

  revoke_user_sessions: {
    action: "revoke_user_sessions",
    description: "Invalidate active session tokens for exposed or compromised user",
    conditions: { minRisk: "low" },
    modeBehaviors: { observe: "DENY", assist: "ALLOW", autopilot: "ALLOW" },
    maxBlastRadiusScore: 20,
    requireMfa: false,
  },

  block_ip: {
    action: "block_ip",
    description: "Append inbound/outbound firewall drop rule for malicious external IP",
    conditions: { minRisk: "low" },
    modeBehaviors: { observe: "DENY", assist: "ALLOW", autopilot: "ALLOW" },
    maxBlastRadiusScore: 20,
    requireMfa: false,
  },

  isolate_host: {
    action: "isolate_host",
    description: "Sever host network interfaces to contain active lateral movement",
    conditions: { minRisk: "medium", assetCriticality: "medium" },
    modeBehaviors: { observe: "DENY", assist: "REQUIRE_APPROVAL", autopilot: "ALLOW" },
    maxBlastRadiusScore: 60,
    requireMfa: true,
    exceptions: [
      { assetType: "production_database", decisionOverride: "REQUIRE_DUAL_APPROVAL", requireDualApproval: true },
      { assetType: "domain_controller", decisionOverride: "REQUIRE_DUAL_APPROVAL", requireDualApproval: true },
    ],
  },

  restore_host: {
    action: "restore_host",
    description: "Restore network connectivity after host remediation and verification",
    conditions: { minRisk: "low" },
    modeBehaviors: { observe: "DENY", assist: "REQUIRE_APPROVAL", autopilot: "REQUIRE_APPROVAL" },
    maxBlastRadiusScore: 80,
    requireMfa: false,
  },

  terminate_process: {
    action: "terminate_process",
    description: "Terminate suspicious or malicious process on endpoint",
    conditions: { minRisk: "low" },
    modeBehaviors: { observe: "DENY", assist: "REQUIRE_APPROVAL", autopilot: "ALLOW" },
    maxBlastRadiusScore: 30,
    requireMfa: false,
    exceptions: [
      { assetType: "core_system_service", decisionOverride: "REQUIRE_DUAL_APPROVAL" },
    ],
  },

  apply_patch: {
    action: "apply_patch",
    description: "Deploy package or kernel security update to remediate identified CVE",
    conditions: { minRisk: "medium" },
    modeBehaviors: { observe: "DENY", assist: "REQUIRE_APPROVAL", autopilot: "REQUIRE_APPROVAL" },
    maxBlastRadiusScore: 50,
    requireMfa: false,
    exceptions: [
      { assetType: "production_database", decisionOverride: "REQUIRE_DUAL_APPROVAL" },
    ],
  },

  emergency_reboot_database: {
    action: "emergency_reboot_database",
    description: "Restart database engine to recover from severe deadlock or corrupt memory",
    conditions: { minRisk: "critical", assetCriticality: "critical" },
    modeBehaviors: { observe: "DENY", assist: "REQUIRE_DUAL_APPROVAL", autopilot: "REQUIRE_DUAL_APPROVAL" },
    maxBlastRadiusScore: 90,
    requireMfa: true,
  },
};

export function getDefaultTenantPolicy(tenantId: string): TenantSecurityPolicy {
  return {
    tenantId,
    autonomyMode: "assist",
    defaultActionDecision: "REQUIRE_APPROVAL",
    policies: { ...DEFAULT_ACTION_POLICIES },
    updatedAt: new Date().toISOString(),
  };
}
