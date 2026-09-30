export type AssetCriticality = "low" | "medium" | "high" | "critical";
export type RiskSeverity = "low" | "medium" | "high" | "critical";
export type AutonomyMode = "observe" | "assist" | "autopilot";

export type PolicyDecisionType =
  | "ALLOW"
  | "DENY"
  | "REQUIRE_APPROVAL"
  | "REQUIRE_DUAL_APPROVAL";

export interface PolicyRuleCondition {
  minRisk?: RiskSeverity;
  assetCriticality?: AssetCriticality;
  environment?: "development" | "staging" | "production";
}

export interface PolicyException {
  assetType?: string;
  hostnamePattern?: string;
  tag?: string;
  decisionOverride?: PolicyDecisionType;
  requireDualApproval?: boolean;
}

export interface ActionPolicy {
  action: string;
  description?: string;
  conditions?: PolicyRuleCondition;
  modeBehaviors: Record<AutonomyMode, PolicyDecisionType>;
  exceptions?: PolicyException[];
  maxBlastRadiusScore?: number;
  requireMfa?: boolean;
}

export interface TenantSecurityPolicy {
  tenantId: string;
  autonomyMode: AutonomyMode;
  defaultActionDecision: PolicyDecisionType;
  policies: Record<string, ActionPolicy>;
  businessHoursOnly?: boolean;
  businessHoursStartHourUtc?: number;
  businessHoursEndHourUtc?: number;
  updatedAt: string;
}

export interface PolicyEvaluationRequest {
  tenantId: string;
  action: string;
  assetCriticality?: AssetCriticality;
  riskSeverity?: RiskSeverity;
  isProduction?: boolean;
  assetType?: string;
  hostname?: string;
  blastRadiusScore?: number;
  autonomyMode?: AutonomyMode;
  tenantPolicy?: Partial<TenantSecurityPolicy>;
}

export interface PolicyEvaluationResult {
  decision: PolicyDecisionType;
  reason: string;
  matchedPolicy: string;
  requiredApprovals: number;
  isExceptionApplied: boolean;
  enforceMfa: boolean;
}
