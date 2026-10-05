import {
  PolicyDecisionType,
  AssetCriticality,
  RiskSeverity,
  AutonomyMode,
  TenantSecurityPolicy,
} from "../policy-engine/types";
import { AutonomyTier } from "../governance/autonomyTier";

export interface ExplainableRiskFactor {
  factor: string;
  scoreDelta: number;
  weight: number;
  evidenceId: string;
  evidenceType?: string;
  description: string;
}

export interface DecisionRiskPayload {
  severity?: RiskSeverity;
  score?: number; // 0 to 10 (or 0 to 100)
  cveId?: string;
  cvss?: number;
  epss?: number;
  factors?: string[];
  factorsList?: ExplainableRiskFactor[];
  securityConfidence?: number;
}

export interface DecisionBlastRadiusPayload {
  score?: number; // 0 to 100
  affectedAssetsCount?: number;
  affectedServices?: string[];
  affectedUsersCount?: number;
  exceeded?: boolean;
  calculationMode?: "measured" | "inferred" | "simulated" | "estimated";
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
  assetAutonomyMode?: AutonomyMode;
  aiConfidence?: number; // 0.0 to 1.0 if proposed by AI
  actor: DecisionActorPayload;
}

export interface DecisionOutput {
  id?: string;
  decision: PolicyDecisionType;
  autonomyTier: AutonomyTier;
  autonomyMode: AutonomyMode;
  securityConfidence: number; // 0.0 to 1.0 deterministic confidence
  aiConfidence?: number; // 0.0 to 1.0 LLM confidence
  risk: DecisionRiskPayload;
  riskFactors?: ExplainableRiskFactor[];
  evidenceIds?: string[];
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
