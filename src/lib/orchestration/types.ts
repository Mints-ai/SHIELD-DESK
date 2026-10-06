import type { SessionUser } from "@/lib/auth/session";
import type { PolicyDecisionType } from "@/lib/policy-engine/types";
import type { RemediationVerificationStatus } from "@/lib/verification-engine/types";
import type { AutonomyTier } from "@/lib/governance/autonomyTier";

export type PipelineStepName =
  | "POLICY_EVALUATION"
  | "DECISION_GATE"
  | "APPROVAL_GATE"
  | "SAFETY_SNAPSHOT"
  | "COMMAND_DISPATCH"
  | "AGENT_EXECUTION"
  | "STATE_VERIFICATION"
  | "AUTOMATIC_ROLLBACK"
  | "AUDIT_RECORDING";

export interface PipelineTimelineEvent {
  step: PipelineStepName;
  status: "pending" | "success" | "blocked" | "failed" | "skipped";
  timestamp: string;
  durationMs: number;
  details?: string;
  metadata?: Record<string, unknown>;
}

export interface PipelineExecutionParams {
  tenantId: string;
  incidentId: string;
  agentId: string;
  action: string;
  caller: SessionUser;
  tokenId?: string;
  parameters?: Record<string, unknown>;
  autoRollbackOnFailure?: boolean;
}

export type PipelineFinalStatus =
  | "SUCCESS_VERIFIED"
  | "APPROVAL_REQUIRED"
  | "POLICY_DENIED"
  | "ROLLED_BACK"
  | "EXECUTION_FAILED";

export interface PipelineExecutionResult {
  pipelineId: string;
  tenantId: string;
  incidentId: string;
  agentId: string;
  action: string;
  tier: AutonomyTier;
  decision: PolicyDecisionType;
  finalStatus: PipelineFinalStatus;
  timeline: PipelineTimelineEvent[];
  commandId?: string;
  snapshotId?: string;
  verificationOutcome?: RemediationVerificationStatus;
  rollbackExecuted: boolean;
  totalDurationMs: number;
  auditHash?: string;
  error?: string;
}
