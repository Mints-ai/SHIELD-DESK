/**
 * Universal Core Function Monitoring Types & Scope Definitions
 * Isomorphic: Safe for both Client Components and Server code (zero Node/DB dependencies).
 */

export type CoreFunctionScope =
  | "system_performance"
  | "network_sockets"
  | "process_inventory"
  | "firewall_baseline"
  | "storage_disk"
  | "service_health";

export interface CoreFunctionScopeDefinition {
  id: CoreFunctionScope;
  label: string;
  description: string;
  tier: "Tier 1" | "Tier 2";
  requiresApproval: boolean;
  resourceCost: "negligible" | "low";
}

export const CORE_FUNCTION_SCOPES: Record<CoreFunctionScope, CoreFunctionScopeDefinition> = {
  system_performance: {
    id: "system_performance",
    label: "System Resources & CPU/RAM",
    description: "Real-time CPU percentage, memory usage, load average, and EPS metrics.",
    tier: "Tier 1",
    requiresApproval: false,
    resourceCost: "negligible",
  },
  network_sockets: {
    id: "network_sockets",
    label: "Active Network Sockets & Connections",
    description: "Sampled TCP/UDP open listening ports, established remote IPs, and socket states.",
    tier: "Tier 2",
    requiresApproval: true,
    resourceCost: "low",
  },
  process_inventory: {
    id: "process_inventory",
    label: "Running Process Inventory",
    description: "Active process list (PID, process name, memory footprint) with kernel PID protections.",
    tier: "Tier 2",
    requiresApproval: true,
    resourceCost: "low",
  },
  firewall_baseline: {
    id: "firewall_baseline",
    label: "Firewall & Security Packet Rules",
    description: "Local packet filter rules, active drop policies, and routing table integrity.",
    tier: "Tier 2",
    requiresApproval: true,
    resourceCost: "negligible",
  },
  storage_disk: {
    id: "storage_disk",
    label: "Disk & Storage Metrics",
    description: "Drive utilization, mounted volumes, and storage headroom.",
    tier: "Tier 2",
    requiresApproval: true,
    resourceCost: "negligible",
  },
  service_health: {
    id: "service_health",
    label: "Security Service & Daemon Health",
    description: "Monitoring of ShieldDesk agent daemon, Windows Defender / security services status.",
    tier: "Tier 2",
    requiresApproval: true,
    resourceCost: "negligible",
  },
};

export interface EndpointMonitoringPolicy {
  agent_id: string;
  tenant_id: string;
  enabled_scopes: CoreFunctionScope[];
  approved_by: string;
  approved_at: string;
  approval_token_id?: string | null;
  policy_hash: string;
  status: "active" | "pending_approval";
}
