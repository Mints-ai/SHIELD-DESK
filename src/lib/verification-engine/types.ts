export type VerificationMethodType =
  | "process_table_check"
  | "port_reachability_check"
  | "package_version_check"
  | "vulnerability_rescan"
  | "service_health_check"
  | "firewall_rule_check"
  | "config_state_check"
  | "snapshot_state_check"
  | "file_quarantine_check"
  | "custom_script_check";

export type RemediationVerificationStatus =
  | "VERIFIED"
  | "FAILED"
  | "INCONCLUSIVE"
  | "ROLLBACK_TRIGGERED";

export interface VerificationCheckSpec {
  method: VerificationMethodType;
  target: string;
  expectedState: Record<string, unknown>;
  timeoutMs?: number;
}

export interface VerificationMethodResult {
  method: VerificationMethodType;
  target: string;
  success: boolean;
  actualState: Record<string, unknown>;
  expectedState: Record<string, unknown>;
  details: string;
  timestamp: string;
}

export interface VerificationPlan {
  action: string;
  agentId: string;
  tenantId: string;
  commandId: string;
  findingId?: string;
  expected: Record<string, unknown>;
  checks: VerificationCheckSpec[];
  rollbackOnFailure: boolean;
  snapshotId?: string;
}

export interface VerificationResult {
  verified: boolean;
  status: RemediationVerificationStatus;
  commandId: string;
  agentId: string;
  tenantId: string;
  findingId?: string;
  checks: VerificationMethodResult[];
  proofOfState: Record<string, unknown>;
  failureReason?: string;
  rollbackActionRequired: boolean;
  rollbackExecuted?: boolean;
  rollbackResult?: Record<string, unknown>;
  findingReopened?: boolean;
  verifiedAt: string;
  verificationHash: string;
}

export interface FindingInput {
  id?: string;
  cveId?: string;
  packageName?: string;
  installedVersion?: string;
  fixedVersion?: string;
  assetId: string;
  assetHostname?: string;
  cvssScore?: number;
  epssScore?: number;
  kevListed?: boolean;
  severity?: string;
  configKey?: string;
  serviceName?: string;
  title?: string;
}

export interface RootCauseGroup {
  rootCauseId: string;
  groupType: "package" | "cve" | "service" | "config" | "generic";
  title: string;
  packageName?: string;
  fixedVersion?: string;
  cveIds: string[];
  affectedAssets: Array<{ assetId: string; assetHostname?: string }>;
  totalFindings: number;
  maxCvss: number;
  hasKev: boolean;
  recommendedAction: string;
  projectedBlastRadius: {
    blastRadiusScore: number;
    affectedServicesCount: number;
    estimatedDowntimeMinutes: number;
    requiresReboot: boolean;
  };
  projectedRiskReductionPercent: number;
  maintenanceWindow: "immediate_emergency" | "scheduled_off_peak" | "standard_maintenance";
  rollbackReadiness: {
    snapshotSupported: boolean;
    recommendedRollbackType: "snapshot_restore" | "package_downgrade" | "service_restart" | "network_rollback";
    estimatedRollbackTimeSeconds: number;
  };
  verificationChecklist: VerificationCheckSpec[];
}

export interface RemediationSimulationPlan {
  id: string;
  tenantId: string;
  rootCauseId: string;
  title: string;
  findingsCount: number;
  affectedAssets: Array<{ assetId: string; assetHostname?: string }>;
  simulationResults: {
    groupType: string;
    maxCvss: number;
    hasKev: boolean;
    cveIds: string[];
    projectedBlastRadius: RootCauseGroup["projectedBlastRadius"];
    projectedRiskReductionPercent: number;
    rollbackReadiness: RootCauseGroup["rollbackReadiness"];
    verificationChecklist: VerificationCheckSpec[];
  };
  recommendedAction: string;
  maintenanceWindow: string;
  status: "simulated" | "approved" | "executing" | "completed" | "cancelled";
  createdAt: string;
}

export interface ContinuousRecheckSchedule {
  id: string;
  tenantId: string;
  findingId: string;
  assetId: string;
  action: string;
  checkSpec: VerificationCheckSpec;
  frequencyHours: number;
  lastRecheckAt?: string;
  nextRecheckAt: string;
  consecutivePasses: number;
  status: "active" | "drift_detected" | "completed";
  createdAt: string;
}

export interface DriftAuditResult {
  scheduleId: string;
  tenantId: string;
  findingId: string;
  assetId: string;
  driftDetected: boolean;
  checkResult: VerificationMethodResult;
  reopened: boolean;
  auditedAt: string;
}
