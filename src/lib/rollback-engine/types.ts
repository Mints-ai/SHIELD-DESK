export type RollbackType =
  | "snapshot_restore"
  | "network_rollback"
  | "configuration_rollback"
  | "package_rollback"
  | "service_rollback";

export interface RollbackRequest {
  tenantId: string;
  agentId: string;
  commandId: string;
  snapshotId: string;
  rollbackType: RollbackType;
  reason: string;
  actorId: string;
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
}
