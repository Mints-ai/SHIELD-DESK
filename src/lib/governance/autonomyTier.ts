/**
 * ShieldDesk Autonomy Tier Policy & Classification Engine
 *
 * Implements the core 4-tier risk classification system from the PRD (§5)
 * and Beginner's Guide (§2.5):
 *
 *   Tier 0 — Observation Only:
 *     Telemetry collection, event logging. Never acts. No human needed.
 *   Tier 1 — Low-Risk / Reversible:
 *     Reversible immediate containment (e.g. revoking exposed sessions, blocking
 *     a verified malicious external IP). Automatic execution once enabled, fully logged.
 *   Tier 2 — Medium-Risk / Human-Approved:
 *     Actions with potential operational blast radius (e.g. isolating a host,
 *     applying security patches). Prepares pending token, requires 1 distinct human sign-off.
 *   Tier 3 — High-Risk / Break-Glass:
 *     Potentially irreversible actions on critical assets (e.g. emergency terminal
 *     commands, core database reboots, disk wipe). Requires dual distinct human sign-offs.
 */

export type AutonomyTier = "Tier 0" | "Tier 1" | "Tier 2" | "Tier 3";

export interface TierClassification {
  tier: AutonomyTier;
  level: 0 | 1 | 2 | 3;
  label: string;
  description: string;
  requiredApprovers: number;
  requiresSeparationOfDuties: boolean;
  reversible: boolean;
  justification: string;
}

export const TIER_DEFINITIONS: Record<AutonomyTier, TierClassification> = {
  "Tier 0": {
    tier: "Tier 0",
    level: 0,
    label: "Observation Only",
    description: "Read-only telemetry gathering and event logging. Never executes state changes.",
    requiredApprovers: 0,
    requiresSeparationOfDuties: false,
    reversible: true,
    justification: "Telemetry read operations carry zero operational impact.",
  },
  "Tier 1": {
    tier: "Tier 1",
    level: 1,
    label: "Low-Risk / Reversible",
    description: "Well-understood, easily reversible defensive actions (e.g., revoking session tokens, blocking an IP).",
    requiredApprovers: 0,
    requiresSeparationOfDuties: false,
    reversible: true,
    justification: "Action is reversible and constrained in blast radius.",
  },
  "Tier 2": {
    tier: "Tier 2",
    level: 2,
    label: "Medium-Risk / Human-Approved",
    description: "Significant containment or remediation (e.g., isolating a host, applying a patch). Requires 1 human approval.",
    requiredApprovers: 1,
    requiresSeparationOfDuties: true,
    reversible: true,
    justification: "Host isolation or patching disrupts user workflow; requires named analyst authorization.",
  },
  "Tier 3": {
    tier: "Tier 3",
    level: 3,
    label: "High-Risk / Dual-Approved Break-Glass",
    description: "Potentially irreversible or emergency interventions on production systems. Requires dual human approvals.",
    requiredApprovers: 2,
    requiresSeparationOfDuties: true,
    reversible: false,
    justification: "High blast radius and potential service interruption require two distinct senior administrators.",
  },
};

import { PolicyEngine } from "../policy-engine/engine";

/**
 * Classifies an action type into its corresponding operational Autonomy Tier.
 * Delegates to the deterministic PolicyEngine while preserving legacy tier contracts.
 */
export function classifyResponseTier(
  actionType: string,
  context?: {
    isProduction?: boolean;
    assetType?: string;
    cveScore?: number;
    epssScore?: number;
    tenantId?: string;
    blastRadiusScore?: number;
  }
): TierClassification {
  const normalized = actionType.toLowerCase().replace(/[\s_-]+/g, "_");

  // Determine risk severity
  let riskSeverity: "low" | "medium" | "high" | "critical" = "medium";
  if (context?.cveScore && context.cveScore >= 8.5) riskSeverity = "critical";
  else if (context?.cveScore && context.cveScore >= 7.0) riskSeverity = "high";
  else if (context?.cveScore && context.cveScore < 4.0) riskSeverity = "low";

  // Determine asset criticality
  let assetCriticality: "low" | "medium" | "high" | "critical" = "medium";
  if (
    normalized.includes("database") ||
    normalized.includes("domain_controller") ||
    context?.assetType === "production_database"
  ) {
    assetCriticality = "critical";
  }

  const result = PolicyEngine.evaluatePolicy({
    tenantId: context?.tenantId || "default-tenant",
    action: actionType,
    assetType: context?.assetType,
    assetCriticality,
    riskSeverity,
    blastRadiusScore: context?.blastRadiusScore,
    isProduction: context?.isProduction,
  });

  if (result.decision === "REQUIRE_DUAL_APPROVAL") {
    return {
      ...TIER_DEFINITIONS["Tier 3"],
      justification: result.reason,
    };
  }

  if (result.decision === "REQUIRE_APPROVAL") {
    return {
      ...TIER_DEFINITIONS["Tier 2"],
      justification: result.reason,
    };
  }

  if (result.decision === "ALLOW") {
    const isTier0 =
      normalized.includes("gather") ||
      normalized.includes("read") ||
      normalized.includes("inspect") ||
      normalized.includes("telemetry") ||
      normalized.startsWith("get_");

    if (isTier0) {
      return {
        ...TIER_DEFINITIONS["Tier 0"],
        justification: result.reason,
      };
    }

    return {
      ...TIER_DEFINITIONS["Tier 1"],
      justification: result.reason,
    };
  }

  return {
    ...TIER_DEFINITIONS["Tier 2"],
    justification: result.reason,
  };
}

/**
 * Estimates AI model confidence for a proposed mitigation action.
 */
export function calculateModelConfidence(
  tier: AutonomyTier,
  hasExactCveMatch: boolean = true
): number {
  if (tier === "Tier 1") return 0.98;
  if (tier === "Tier 2") return hasExactCveMatch ? 0.96 : 0.88;
  if (tier === "Tier 3") return hasExactCveMatch ? 0.94 : 0.82;
  return 0.99;
}
