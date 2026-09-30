import { PolicyDecisionType, AssetCriticality, RiskSeverity, AutonomyMode, TenantSecurityPolicy } from "../policy-engine/types";

export interface DecisionRiskPayload {
  severity?: RiskSeverity;
  score?: number; // 0 to 10
  cveId?: string;
  cvss?: number;
  epss?: number;
  factors?: string[];
}

export interface DecisionBlastRadiusPayload {
  score?: number; // 0 to 100
  affectedAssetsCount?: number;
  affectedServices?: string[];
  affectedUsersCount?: number;
  exceeded?: boolean;
}

export interface DecisionActorPayload {
  id: string;
  role: string;
  tenantId: string;
  ipAddress?: string;
  mfaVerified?: boolean;
}

export interface DecisionEvidenceItem {
  id?: string;
  type: string;
  source: string;
  timestamp: string;
  data: Record<string, unknown>;
  hash?: string;
}

export interface DecisionInput {
  tenantId: string;
  incidentId?: string;
  assetId?: string;
  assetType?: string;
  hostname?: string;
  assetCriticality?: AssetCriticality;
  action: string;
  evidence: DecisionEvidenceItem[];
  risk?: DecisionRiskPayload;
  blastRadius?: DecisionBlastRadiusPayload;
  policy?: Partial<TenantSecurityPolicy>;
  autonomyMode?: AutonomyMode;
  actor: DecisionActorPayload;
}

export interface DecisionOutput {
  decision: PolicyDecisionType;
  risk: DecisionRiskPayload;
  reason: string;
  requiredApprovals: number;
  evidence: DecisionEvidenceItem[];
  action: string;
  tenantId: string;
  incidentId?: string;
  assetId?: string;
  enforceMfa: boolean;
  evaluatedAt: string;
  decisionHash: string;
}
