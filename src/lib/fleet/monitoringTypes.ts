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
  | "service_health"
  | "defender_authority";

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
  defender_authority: {
    id: "defender_authority",
    label: "Microsoft Defender & EDR Authority",
    description: "Real-time Defender EDR control, signature intelligence, scan execution, and threat remediation.",
    tier: "Tier 2",
    requiresApproval: true,
    resourceCost: "low",
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

export interface FirewallProfileItem {
  name: "Domain" | "Private" | "Public" | string;
  state: "ON" | "OFF";
}

export interface FirewallRuleItem {
  name: string;
  direction: "in" | "out";
  action: "allow" | "block";
  protocol: string;
  localPort?: string;
  remotePort?: string;
  remoteIp?: string;
  program?: string;
  enabled: boolean;
  isShieldDeskRule: boolean;
}

export interface FirewallBaselineData {
  firewallState: string;
  defaultInbound: string;
  defaultOutbound: string;
  activeShieldDeskRules: number;
  lastSnapshotAudit: string;
  profiles?: FirewallProfileItem[];
  rules?: FirewallRuleItem[];
}

export interface DefenderThreatItem {
  threatId: string | number;
  threatName: string;
  severity: "Low" | "Medium" | "High" | "Severe" | string;
  didExecute: boolean;
  isActive?: boolean;
  category?: string;
  rollupStatus?: number;
  resources?: string[] | null;
  detectedAt?: string;
}

export interface DefenderDetectionItem {
  detectionId: string;
  threatId: number;
  threatName?: string;
  initialDetectionTime: string;
  remediationTime?: string;
  actionSuccess?: boolean;
  cleaningAction?: string;
  resources: string[];
  domainUser?: string;
  processName?: string;
}

export interface DefenderStatusData {
  antivirusEnabled: boolean;
  realTimeProtectionEnabled: boolean;
  ioavProtectionEnabled: boolean;
  antispywareEnabled: boolean;
  behaviorMonitorEnabled: boolean;
  nisProtectionEnabled?: boolean;
  onAccessProtectionEnabled: boolean;
  tamperProtectionSource?: string;
  isTamperProtected?: boolean;
  productVersion?: string;
  serviceVersion?: string;
  runningMode?: string;
  serviceEnabled?: boolean;
  signatureVersion: string;
  signatureLastUpdated: string;
  engineVersion: string;
  nisSignatureVersion?: string;
  nisEngineVersion?: string;
  quickScanAgeDays: number | null;
  quickScanStartTime?: string | null;
  quickScanEndTime: string | null;
  quickScanOverdue?: boolean;
  fullScanAgeDays: number | null;
  fullScanStartTime?: string | null;
  fullScanEndTime: string | null;
  signaturesOutOfDate?: boolean;
  rebootRequired?: boolean;
  computerId?: string;
  activeThreatsCount: number;
  threats: DefenderThreatItem[];
  detections?: DefenderDetectionItem[];
  exclusions?: {
    paths?: string[];
    extensions?: string[];
    processes?: string[];
  };
  cloudProtection?: {
    mapsReporting?: string;
    submitSamplesConsent?: string;
  };
  puaProtection?: string;
  networkProtection?: string;
  controlledFolderAccess?: string;
  scriptScanning?: boolean;
  smartAppControl?: string;
  deviceControl?: string;
  antivirusSignatureAge?: number;
  productStatus?: number;
  lastAudit: string;
}


