export type VerificationMethodType =
  | "process_table_check"
  | "port_reachability_check"
  | "package_version_check"
  | "vulnerability_rescan"
  | "service_health_check"
  | "firewall_rule_check"
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
  checks: VerificationMethodResult[];
  proofOfState: Record<string, unknown>;
  failureReason?: string;
  rollbackActionRequired: boolean;
  verifiedAt: string;
  verificationHash: string;
}
