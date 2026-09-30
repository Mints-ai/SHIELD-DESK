import crypto from "node:crypto";
import { DecisionInput, DecisionOutput } from "./types";
import { PolicyEngine } from "../policy-engine/engine";
import { ProductionSafetyGuard } from "@/config";
import { isKillSwitchEngaged } from "../fleet/fleet";

export class DecisionEngine {
  /**
   * The Decision Engine is the mandatory gateway for high-impact actions.
   * Evaluates input context (tenant, asset, risk, blast radius, policy, actor, evidence)
   * and deterministically yields ALLOW, DENY, REQUIRE_APPROVAL, or REQUIRE_DUAL_APPROVAL.
   */
  public static async evaluate(input: DecisionInput): Promise<DecisionOutput> {
    const evaluatedAt = new Date().toISOString();
    const risk = input.risk || { severity: "medium", score: 5.0 };
    const blastRadius = input.blastRadius || { score: 10, exceeded: false };
    const evidence = [...(input.evidence || [])];

    // 1. Safety Guard Assertion (prevents simulated/demo command execution in production)
    try {
      ProductionSafetyGuard.assertProductionSafe(input.action, {
        tenantId: input.tenantId,
        actorId: input.actor.id,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Production safety violation";
      return DecisionEngine.buildOutput(
        "DENY",
        msg,
        0,
        risk,
        evidence,
        input,
        evaluatedAt,
        false
      );
    }

    // 2. Tenant Isolation Enforcement (actor tenant must match target resource tenant)
    if (input.actor.tenantId !== input.tenantId) {
      return DecisionEngine.buildOutput(
        "DENY",
        `Security boundary violation: Actor tenant '${input.actor.tenantId}' cannot propose actions for target tenant '${input.tenantId}'.`,
        0,
        risk,
        evidence,
        input,
        evaluatedAt,
        false
      );
    }

    // 3. Actor Permission Enforcement (Read-only roles cannot initiate active remediation)
    const readOnlyRoles = ["viewer", "auditor", "read_only", "billing_admin"];
    if (readOnlyRoles.includes(input.actor.role.toLowerCase())) {
      return DecisionEngine.buildOutput(
        "DENY",
        `Role '${input.actor.role}' does not hold operational permissions to execute or initiate remediation actions.`,
        0,
        risk,
        evidence,
        input,
        evaluatedAt,
        false
      );
    }

    // 4. Emergency Kill Switch Check
    try {
      const killSwitchActive = await isKillSwitchEngaged(input.tenantId);
      if (killSwitchActive) {
        return DecisionEngine.buildOutput(
          "DENY",
          `Tenant '${input.tenantId}' has an active Emergency Admin Kill Switch engaged. All active remediation is locked.`,
          0,
          risk,
          evidence,
          input,
          evaluatedAt,
          true
        );
      }
    } catch {
      // In standalone / non-db context, continue
    }

    // 5. Evaluate Deterministic Policy Engine
    const policyResult = PolicyEngine.evaluatePolicy({
      tenantId: input.tenantId,
      action: input.action,
      assetCriticality: input.assetCriticality,
      riskSeverity: risk.severity,
      assetType: input.assetType,
      hostname: input.hostname,
      blastRadiusScore: blastRadius.score,
      autonomyMode: input.autonomyMode,
      tenantPolicy: input.policy,
    });

    let finalDecision = policyResult.decision;
    let finalReason = policyResult.reason;
    let requiredApprovals = policyResult.requiredApprovals;

    // 6. Blast Radius Throttle Check
    if (blastRadius.exceeded) {
      finalDecision = "REQUIRE_DUAL_APPROVAL";
      requiredApprovals = 2;
      finalReason += " Blast radius threshold strictly exceeded; escalated to dual approval.";
    }

    // 7. Core Product Principle: PROVE BEFORE YOU ACT
    // If high-impact or destructive actions have zero evidence, block or escalate
    const isHighImpactAction =
      finalDecision === "REQUIRE_APPROVAL" ||
      finalDecision === "REQUIRE_DUAL_APPROVAL" ||
      input.action.includes("isolate") ||
      input.action.includes("terminate") ||
      input.action.includes("reboot");

    if (isHighImpactAction && evidence.length === 0) {
      if (finalDecision === "ALLOW") {
        finalDecision = "REQUIRE_APPROVAL";
        requiredApprovals = 1;
      }
      finalReason += " Notice: Zero prior evidence provided. Prove-Before-You-Act policy mandates human review.";
    }

    return DecisionEngine.buildOutput(
      finalDecision,
      finalReason,
      requiredApprovals,
      risk,
      evidence,
      input,
      evaluatedAt,
      policyResult.enforceMfa
    );
  }

  private static buildOutput(
    decision: DecisionOutput["decision"],
    reason: string,
    requiredApprovals: number,
    risk: DecisionOutput["risk"],
    evidence: DecisionOutput["evidence"],
    input: DecisionInput,
    evaluatedAt: string,
    enforceMfa: boolean
  ): DecisionOutput {
    // Generate tamper-evident SHA-256 signature for this decision record
    const payloadToHash = JSON.stringify({
      decision,
      tenantId: input.tenantId,
      action: input.action,
      actorId: input.actor.id,
      evaluatedAt,
      requiredApprovals,
    });
    const decisionHash = crypto.createHash("sha256").update(payloadToHash).digest("hex");

    return {
      decision,
      risk,
      reason,
      requiredApprovals,
      evidence,
      action: input.action,
      tenantId: input.tenantId,
      incidentId: input.incidentId,
      assetId: input.assetId,
      enforceMfa,
      evaluatedAt,
      decisionHash,
    };
  }
}
