import {
  PolicyEvaluationRequest,
  PolicyEvaluationResult,
  PolicyDecisionType,
  AutonomyMode,
  ActionPolicy,
} from "./types";
import { DEFAULT_ACTION_POLICIES, getDefaultTenantPolicy } from "./defaults";
import { AutonomyTier } from "../governance/autonomyTier";

export class PolicyEngine {
  /**
   * Evaluates a security action request against tenant, asset-level, and global policies.
   * Deterministically returns the required approval tier (0-3), autonomy mode, and decision.
   */
  public static evaluatePolicy(request: PolicyEvaluationRequest): PolicyEvaluationResult {
    const tenantPolicy = request.tenantPolicy || getDefaultTenantPolicy(request.tenantId);

    // 1. Resolve effective autonomy mode: Asset-level overrides tenant-level
    let effectiveAutonomyMode: AutonomyMode =
      request.assetAutonomyMode || request.autonomyMode || tenantPolicy.autonomyMode || "assist";

    // Safety Constraint: Critical assets cannot run in unattended autopilot mode
    if (request.assetCriticality === "critical" && effectiveAutonomyMode === "autopilot") {
      effectiveAutonomyMode = "assist";
    }

    const normalizedAction = request.action.toLowerCase().replace(/[\s.-]+/g, "_");

    // 2. Check for specific action policy
    let policy: ActionPolicy | undefined =
      tenantPolicy.policies?.[normalizedAction] || DEFAULT_ACTION_POLICIES[normalizedAction];

    // 3. Pattern-based inference for composite or descriptive action names
    if (!policy) {
      if (
        normalizedAction.includes("emergency") ||
        normalizedAction.includes("break_glass") ||
        normalizedAction.includes("reboot_database") ||
        normalizedAction.includes("wipe") ||
        normalizedAction.includes("arbitrary_command")
      ) {
        policy = DEFAULT_ACTION_POLICIES["emergency_reboot_database"];
      } else if (
        normalizedAction.includes("isolate") ||
        normalizedAction.includes("patch") ||
        normalizedAction.includes("remediate") ||
        normalizedAction.includes("kill_process") ||
        normalizedAction.includes("quarantine") ||
        normalizedAction.includes("disable_telemetry")
      ) {
        policy = DEFAULT_ACTION_POLICIES["isolate_host"];
      } else if (
        normalizedAction.includes("revoke") ||
        normalizedAction.includes("block_ip") ||
        normalizedAction.includes("rotate_key") ||
        normalizedAction.includes("invalidate_token")
      ) {
        policy = DEFAULT_ACTION_POLICIES["revoke_user_sessions"];
      } else if (
        normalizedAction.includes("gather") ||
        normalizedAction.includes("read") ||
        normalizedAction.includes("inspect") ||
        normalizedAction.includes("telemetry") ||
        normalizedAction.includes("get_")
      ) {
        policy = DEFAULT_ACTION_POLICIES["gather_telemetry"];
      }
    }

    if (!policy) {
      // Default fallback for unknown actions: Require human approval
      return {
        decision: "REQUIRE_APPROVAL",
        reason: `No explicit policy defined for action '${request.action}'. Defaulting to human approval.`,
        matchedPolicy: "default_fallback",
        requiredApprovals: 1,
        isExceptionApplied: false,
        enforceMfa: false,
        autonomyTier: "Tier 2",
        effectiveAutonomyMode,
      };
    }

    // 4. Base decision from effective autonomy mode
    let decision: PolicyDecisionType = policy.modeBehaviors[effectiveAutonomyMode] || "REQUIRE_APPROVAL";
    let reason = `Action '${request.action}' evaluated under '${effectiveAutonomyMode}' autonomy mode -> ${decision}.`;
    let isExceptionApplied = false;

    // 5. Evaluate Asset Type Exceptions (e.g. production_database, domain_controller)
    if (policy.exceptions && request.assetType) {
      const matchingException = policy.exceptions.find(
        (ex) => ex.assetType?.toLowerCase() === request.assetType?.toLowerCase()
      );

      if (matchingException) {
        if (matchingException.decisionOverride) {
          decision = matchingException.decisionOverride;
          reason = `Exception applied: Target asset type '${request.assetType}' requires override -> ${decision}.`;
          isExceptionApplied = true;
        } else if (matchingException.requireDualApproval) {
          decision = "REQUIRE_DUAL_APPROVAL";
          reason = `Exception applied: Target asset type '${request.assetType}' requires dual human sign-off.`;
          isExceptionApplied = true;
        }
      }
    }

    // 6. Critical Asset Escalation: If asset is critical and decision is ALLOW, escalate to approval
    if (request.assetCriticality === "critical" && decision === "ALLOW") {
      decision = "REQUIRE_APPROVAL";
      reason += " Escalated: Critical asset cannot be modified with zero human oversight.";
    }

    // 7. Blast Radius Threshold Escalation
    if (
      request.blastRadiusScore !== undefined &&
      policy.maxBlastRadiusScore !== undefined &&
      request.blastRadiusScore > policy.maxBlastRadiusScore
    ) {
      if (decision === "ALLOW") {
        decision = "REQUIRE_APPROVAL";
      } else if (decision === "REQUIRE_APPROVAL") {
        decision = "REQUIRE_DUAL_APPROVAL";
      }
      reason += ` Blast radius score (${request.blastRadiusScore}) exceeded threshold (${policy.maxBlastRadiusScore}); escalated approval level.`;
    }

    // 8. Map decision to required approvals count and Tier 0-3
    let requiredApprovals = 0;
    if (decision === "REQUIRE_APPROVAL") {
      requiredApprovals = 1;
    } else if (decision === "REQUIRE_DUAL_APPROVAL") {
      requiredApprovals = 2;
    }

    let autonomyTier: AutonomyTier = "Tier 1";
    if (normalizedAction.includes("gather") || normalizedAction.includes("read") || normalizedAction.includes("telemetry")) {
      autonomyTier = "Tier 0";
    } else if (decision === "REQUIRE_DUAL_APPROVAL" || normalizedAction.includes("emergency") || normalizedAction.includes("wipe")) {
      autonomyTier = "Tier 3";
    } else if (normalizedAction.includes("isolate") || normalizedAction.includes("patch") || decision === "REQUIRE_APPROVAL") {
      autonomyTier = "Tier 2";
    } else if (decision === "ALLOW") {
      autonomyTier = "Tier 1";
    }

    return {
      decision,
      reason,
      matchedPolicy: policy.action,
      requiredApprovals,
      isExceptionApplied,
      enforceMfa: policy.requireMfa || decision === "REQUIRE_DUAL_APPROVAL",
      autonomyTier,
      effectiveAutonomyMode,
    };
  }
}
