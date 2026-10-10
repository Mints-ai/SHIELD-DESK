export type RollbackType =
  | "snapshot_restore"
  | "network_rollback"
  | "configuration_rollback"
  | "package_rollback"
  | "service_rollback";

export type RollbackOutcomeStatus =
  | "ROLLBACK_REQUESTED"
  | "ROLLBACK_BLOCKED"
  | "ROLLBACK_DISPATCHED"
  | "ROLLBACK_IN_PROGRESS"
  | "ROLLBACK_FAILED"
  | "RESTORATION_VERIFIED"
  | "RESTORATION_UNVERIFIED";

export interface RollbackRequest {
  tenantId: string;
  agentId: string;
  commandId: string;
  snapshotId: string;
  rollbackType: RollbackType;
  reason: string;
  actorId: string;
  caller?: import("@/lib/auth/session").SessionUser;
  force?: boolean;
}

export interface RollbackResult {
  success: boolean;
  rollbackId: string;
  commandId: string;
  agentId: string;
  tenantId: string;
  snapshotId: string;
  rollbackType: RollbackType;
  output: string;
  revertedAt: string;
  rollbackHash: string;
  status: RollbackOutcomeStatus;
  isSimulated?: boolean;
  error?: string;
}
