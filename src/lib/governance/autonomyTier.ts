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

/**
 * Classifies an action type into its corresponding operational Autonomy Tier.
 */
export function classifyResponseTier(
  actionType: string,
  context?: {
    isProduction?: boolean;
    assetType?: string;
    cveScore?: number;
    epssScore?: number;
  }
): TierClassification {
  const normalized = actionType.toLowerCase().replace(/[\s_-]+/g, "_");

  // Tier 3: Break-glass, emergency execution, destructive actions
  if (
    normalized.includes("emergency") ||
    normalized.includes("break_glass") ||
    normalized.includes("reboot_database") ||
    normalized.includes("wipe") ||
    normalized.includes("arbitrary_command") ||
    (context?.isProduction && normalized.includes("database_restart"))
  ) {
    return {
      ...TIER_DEFINITIONS["Tier 3"],
      justification: `Action '${actionType}' targets critical production assets with high blast radius.`,
    };
  }

  // Tier 2: Host isolation, patching, killing processes, firewall rule modification
  if (
    normalized.includes("isolate") ||
    normalized.includes("patch") ||
    normalized.includes("remediate") ||
    normalized.includes("kill_process") ||
    normalized.includes("quarantine") ||
    normalized.includes("disable_telemetry") ||
    (context?.cveScore && context.cveScore >= 7.0)
  ) {
    return {
      ...TIER_DEFINITIONS["Tier 2"],
      justification: `Action '${actionType}' alters host state or network connectivity; requires analyst approval.`,
    };
  }

  // Tier 1: Reversible containment (session revocation, temporary IP block)
  if (
    normalized.includes("revoke") ||
    normalized.includes("block_ip") ||
    normalized.includes("rotate_key") ||
    normalized.includes("invalidate_token") ||
    normalized.includes("update_rule")
  ) {
    return {
      ...TIER_DEFINITIONS["Tier 1"],
      justification: `Action '${actionType}' is safe and easily rolled back.`,
    };
  }

  // Tier 0: Default read-only / observation
  return TIER_DEFINITIONS["Tier 0"];
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
