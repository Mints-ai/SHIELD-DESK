import { VerificationMethodType } from "../verification-engine/types";

export type SupportedOS = "windows" | "linux" | "darwin";

export interface AgentCapability {
  name: string;
  riskLevel: "low" | "medium" | "high" | "critical";
  supportedOS: SupportedOS[];
  requiredPermission: string;
  approvalLevel: 0 | 1 | 2 | 3;
  rollbackSupport: boolean;
  verificationMethod: VerificationMethodType;
  description: string;
}

export const CAPABILITY_REGISTRY: Record<string, AgentCapability> = {
  "network.isolate": {
    name: "network.isolate",
    riskLevel: "high",
    supportedOS: ["windows", "linux"],
    requiredPermission: "fleet.isolate",
    approvalLevel: 2,
    rollbackSupport: true,
    verificationMethod: "firewall_rule_check",
    description: "Isolate endpoint from local network and internet, preserving control plane management tunnel.",
  },

  "network.restore": {
    name: "network.restore",
    riskLevel: "low",
    supportedOS: ["windows", "linux"],
    requiredPermission: "fleet.restore",
    approvalLevel: 2,
    rollbackSupport: false,
    verificationMethod: "firewall_rule_check",
    description: "Restore standard network connectivity and clear defensive firewall isolation rules.",
  },

  "process.terminate": {
    name: "process.terminate",
    riskLevel: "medium",
    supportedOS: ["windows", "linux", "darwin"],
    requiredPermission: "fleet.remediate",
    approvalLevel: 2,
    rollbackSupport: true,
    verificationMethod: "process_table_check",
    description: "Terminate target malicious or unauthorized process by PID or image name.",
  },

  "process.inspect": {
    name: "process.inspect",
    riskLevel: "low",
    supportedOS: ["windows", "linux", "darwin"],
    requiredPermission: "fleet.read",
    approvalLevel: 0,
    rollbackSupport: false,
    verificationMethod: "process_table_check",
    description: "Inspect running processes, memory footprints, and command line arguments.",
  },

  "snapshot.create": {
    name: "snapshot.create",
    riskLevel: "low",
    supportedOS: ["windows", "linux"],
    requiredPermission: "fleet.remediate",
    approvalLevel: 1,
    rollbackSupport: false,
    verificationMethod: "service_health_check",
    description: "Capture pre-flight safety snapshot of host state, processes, and network routing.",
  },

  "snapshot.restore": {
    name: "snapshot.restore",
    riskLevel: "medium",
    supportedOS: ["windows", "linux"],
    requiredPermission: "fleet.remediate",
    approvalLevel: 2,
    rollbackSupport: false,
    verificationMethod: "service_health_check",
    description: "Revert host state and firewall configurations to a previously captured snapshot ID.",
  },

  "patch.apply": {
    name: "patch.apply",
    riskLevel: "medium",
    supportedOS: ["windows", "linux"],
    requiredPermission: "cve.remediate",
    approvalLevel: 2,
    rollbackSupport: true,
    verificationMethod: "package_version_check",
    description: "Apply designated OS package security update or patch to resolve an identified CVE.",
  },

  "service.restart": {
    name: "service.restart",
    riskLevel: "medium",
    supportedOS: ["windows", "linux"],
    requiredPermission: "fleet.remediate",
    approvalLevel: 2,
    rollbackSupport: true,
    verificationMethod: "service_health_check",
    description: "Restart a system service daemon to reload patched binaries or recover from hang.",
  },

  "file.quarantine": {
    name: "file.quarantine",
    riskLevel: "medium",
    supportedOS: ["windows", "linux", "darwin"],
    requiredPermission: "fleet.remediate",
    approvalLevel: 2,
    rollbackSupport: true,
    verificationMethod: "service_health_check",
    description: "Move suspicious or malicious artifact into encrypted, restricted quarantine vault.",
  },

  "firewall.block": {
    name: "firewall.block",
    riskLevel: "low",
    supportedOS: ["windows", "linux"],
    requiredPermission: "fleet.remediate",
    approvalLevel: 1,
    rollbackSupport: true,
    verificationMethod: "firewall_rule_check",
    description: "Append firewall block rule for specified remote IP address or CIDR subnet.",
  },

};

/**
 * Microsoft Defender EDR and inspection capabilities (Windows-specific extensions).
 */
export const DEFENDER_CAPABILITY_REGISTRY: Record<string, AgentCapability> = {
  "defender.scan": {
    name: "defender.scan",
    riskLevel: "low",
    supportedOS: ["windows"],
    requiredPermission: "fleet.remediate",
    approvalLevel: 1,
    rollbackSupport: false,
    verificationMethod: "service_health_check",
    description: "Execute on-demand Microsoft Defender Antivirus scan (Quick or Full Scan).",
  },

  "defender.update": {
    name: "defender.update",
    riskLevel: "low",
    supportedOS: ["windows"],
    requiredPermission: "fleet.remediate",
    approvalLevel: 1,
    rollbackSupport: false,
    verificationMethod: "service_health_check",
    description: "Trigger Microsoft Defender security intelligence definition update.",
  },

  "defender.realtime": {
    name: "defender.realtime",
    riskLevel: "medium",
    supportedOS: ["windows"],
    requiredPermission: "fleet.remediate",
    approvalLevel: 2,
    rollbackSupport: true,
    verificationMethod: "service_health_check",
    description: "Enable or toggle Microsoft Defender real-time scanning protection.",
  },

  "defender.remediate": {
    name: "defender.remediate",
    riskLevel: "medium",
    supportedOS: ["windows"],
    requiredPermission: "fleet.remediate",
    approvalLevel: 2,
    rollbackSupport: true,
    verificationMethod: "service_health_check",
    description: "Remediate and remove identified threat from endpoint host.",
  },

  "defender.exclusion": {
    name: "defender.exclusion",
    riskLevel: "medium",
    supportedOS: ["windows"],
    requiredPermission: "fleet.remediate",
    approvalLevel: 2,
    rollbackSupport: true,
    verificationMethod: "service_health_check",
    description: "Configure directory, process, or file type inspection exclusions in Defender.",
  },
};

/**
 * Unified capabilities dictionary including core and platform extension capabilities.
 */
export const ALL_CAPABILITIES_REGISTRY: Record<string, AgentCapability> = {
  ...CAPABILITY_REGISTRY,
  ...DEFENDER_CAPABILITY_REGISTRY,
};

/**
 * Resolves capability specification by name or legacy command string.
 */
export function getCapability(nameOrCommand: string): AgentCapability | undefined {
  const normalized = nameOrCommand.trim().toLowerCase();

  // Direct capability key match (e.g. "network.isolate", "defender.scan")
  if (ALL_CAPABILITIES_REGISTRY[normalized]) {
    return ALL_CAPABILITIES_REGISTRY[normalized];
  }

  // Legacy command prefix match (e.g. "isolate_host" -> "network.isolate")
  if (normalized.startsWith("isolate_host") || normalized.startsWith("network_isolate")) {
    return ALL_CAPABILITIES_REGISTRY["network.isolate"];
  }
  if (normalized.startsWith("restore_host") || normalized.startsWith("network_restore")) {
    return ALL_CAPABILITIES_REGISTRY["network.restore"];
  }
  if (normalized.startsWith("kill_process") || normalized.startsWith("terminate_process")) {
    return ALL_CAPABILITIES_REGISTRY["process.terminate"];
  }
  if (normalized.startsWith("block_ip") || normalized.startsWith("firewall_block") || normalized.startsWith("firewall_")) {
    return ALL_CAPABILITIES_REGISTRY["firewall.block"];
  }
  if (normalized.startsWith("take_safety_snapshot") || normalized.startsWith("snapshot_create")) {
    return ALL_CAPABILITIES_REGISTRY["snapshot.create"];
  }
  if (normalized.startsWith("rollback_snapshot") || normalized.startsWith("snapshot_restore")) {
    return ALL_CAPABILITIES_REGISTRY["snapshot.restore"];
  }
  if (normalized.startsWith("apply_patch") || normalized.startsWith("patch_cve")) {
    return ALL_CAPABILITIES_REGISTRY["patch.apply"];
  }
  if (normalized.startsWith("defender_scan") || normalized.startsWith("defender.scan")) {
    return ALL_CAPABILITIES_REGISTRY["defender.scan"];
  }
  if (normalized.startsWith("defender_update") || normalized.startsWith("defender.update")) {
    return ALL_CAPABILITIES_REGISTRY["defender.update"];
  }
  if (normalized.startsWith("defender_set_realtime") || normalized.startsWith("defender.realtime")) {
    return ALL_CAPABILITIES_REGISTRY["defender.realtime"];
  }
  if (normalized.startsWith("defender_remediate") || normalized.startsWith("defender.remediate")) {
    return ALL_CAPABILITIES_REGISTRY["defender.remediate"];
  }
  if (normalized.startsWith("defender_add_exclusion") || normalized.startsWith("defender_remove_exclusion") || normalized.startsWith("defender.exclusion")) {
    return ALL_CAPABILITIES_REGISTRY["defender.exclusion"];
  }

  return undefined;
}

/**
 * Validates whether an action capability is supported on a given target OS.
 */
export function validateCapabilitySupport(
  action: string,
  osType: string
): { supported: boolean; capability?: AgentCapability; reason?: string } {
  const capability = getCapability(action);
  if (!capability) {
    return {
      supported: false,
      reason: `Unknown capability or unregistered action '${action}'.`,
    };
  }

  const normalizedOS = osType.toLowerCase() as SupportedOS;
  const isSupported = capability.supportedOS.includes(normalizedOS);

  if (!isSupported) {
    return {
      supported: false,
      capability,
      reason: `Capability '${capability.name}' is not supported on target OS '${osType}'. Supported OS: ${capability.supportedOS.join(", ")}.`,
    };
  }

  return {
    supported: true,
    capability,
  };
}

/**
 * Lists all registered agent capabilities.
 */
export function listCapabilities(): AgentCapability[] {
  return Object.values(CAPABILITY_REGISTRY);
}

/**
 * Lists all registered agent capabilities including platform extensions.
 */
export function listAllCapabilities(): AgentCapability[] {
  return Object.values(ALL_CAPABILITIES_REGISTRY);
}
