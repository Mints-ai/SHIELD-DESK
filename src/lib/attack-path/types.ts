export type AttackStage =
  | "entry_point"
  | "exposure"
  | "vulnerability"
  | "identity"
  | "lateral_movement"
  | "target"
  | "business_impact";

export interface AttackPathStep {
  stepIndex: number;
  stage: AttackStage;
  sourceAssetId: string;
  sourceAssetName: string;
  targetAssetId: string;
  targetAssetName: string;
  technique?: string;
  mitreTactic?: string;
  rationale?: string;
  protocol?: string;
  port?: number;
  evidence: string[];
  likelihood: number;
  description: string;
}

export interface AttackPath {
  pathId: string;
  tenantId: string;
  targetAssetId: string;
  targetAssetName: string;
  entryPointAssetId: string;
  entryPointAssetName: string;
  steps: AttackPathStep[];
  totalLikelihood: number;
  aggregateRiskScore: number;
  chokePoints: string[];
  evidence: string[];
  rank?: number;
  killChainSummary?: string;
  explanation?: string;
  hopCount?: number;
}

export interface CriticalChokePoint {
  assetId: string;
  assetName: string;
  pathsSevered: number;
  recommendedRemediation: string;
  riskReductionPercentage?: number;
}

export interface AttackPathAnalysisReport {
  tenantId: string;
  targetAssetId: string;
  pathsFoundCount: number;
  paths: AttackPath[];
  criticalChokePoints: CriticalChokePoint[];
  highestRiskScore?: number;
  summary?: string;
  chokePointEfficacy?: CriticalChokePoint[];
  analyzedAt: string;
}
