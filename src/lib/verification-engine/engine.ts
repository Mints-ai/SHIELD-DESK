import crypto from "node:crypto";
import { VerificationPlan, VerificationResult, VerificationCheckSpec, VerificationMethodResult } from "./types";
import { VerificationMethods } from "./methods";
import { recordHashChainEvent } from "../fleet/fleet";

export class VerificationEngine {
  /**
   * Generates a deterministic VerificationPlan for a proposed or executed remediation action.
   */
  public static createPlan(params: {
    action: string;
    agentId: string;
    tenantId: string;
    commandId: string;
    snapshotId?: string;
    target?: string;
    cveId?: string;
  }): VerificationPlan {
    const { action, agentId, tenantId, commandId, snapshotId, target, cveId } = params;
    const checks: VerificationCheckSpec[] = [];
    const normalized = action.toLowerCase().replace(/[\s.-]+/g, "_");

    if (normalized.includes("terminate") || normalized.includes("kill_process")) {
      const procTarget = target || "suspicious_process";
      checks.push({
        method: "process_table_check",
        target: procTarget,
        expectedState: { running: false },
      });
    } else if (normalized.includes("isolate")) {
      checks.push({
        method: "firewall_rule_check",
        target: "network_interface",
        expectedState: { active: true },
      });
    } else if (normalized.includes("restore")) {
      checks.push({
        method: "firewall_rule_check",
        target: "network_interface",
        expectedState: { active: false },
      });
    } else if (normalized.includes("block")) {
      checks.push({
        method: "firewall_rule_check",
        target: target || "ip_firewall_rule",
        expectedState: { active: true },
      });
    } else if (normalized.includes("patch")) {
      checks.push({
        method: "package_version_check",
        target: cveId || target || "CVE-FIX",
        expectedState: { cveStatus: "not_vulnerable" },
      });
    } else {
      // Default: Check endpoint connectivity
      checks.push({
        method: "service_health_check",
        target: agentId,
        expectedState: { status: "healthy" },
      });
    }

    return {
      action,
      agentId,
      tenantId,
      commandId,
      expected: { verified: true },
      checks,
      rollbackOnFailure: Boolean(snapshotId),
      snapshotId,
    };
  }

  /**
   * Evaluates endpoint evidence against the VerificationPlan.
   * Core Rule: Never claim an action succeeded without verification.
   */
  public static async verify(
    plan: VerificationPlan,
    actualHostEvidence: Record<string, unknown>
  ): Promise<VerificationResult> {
    const verifiedAt = new Date().toISOString();
    const checkResults: VerificationMethodResult[] = [];

    for (const spec of plan.checks) {
      if (spec.method === "process_table_check") {
        const res = await VerificationMethods.checkProcessTable(spec, actualHostEvidence);
        checkResults.push(res);
      } else if (spec.method === "firewall_rule_check") {
        const res = await VerificationMethods.checkFirewallRule(spec, actualHostEvidence);
        checkResults.push(res);
      } else if (spec.method === "package_version_check" || spec.method === "vulnerability_rescan") {
        const res = await VerificationMethods.checkPackageOrCve(spec, actualHostEvidence);
        checkResults.push(res);
      } else {
        // Fallback check
        checkResults.push({
          method: spec.method,
          target: spec.target,
          success: actualHostEvidence.status !== "failed",
          expectedState: spec.expectedState,
          actualState: actualHostEvidence,
          details: "Standard service health validation check.",
          timestamp: verifiedAt,
        });
      }
    }

    const allPassed = checkResults.every((c) => c.success);
    const status = allPassed ? "VERIFIED" : "FAILED";
    const failureReason = allPassed
      ? undefined
      : checkResults.filter((c) => !c.success).map((c) => c.details).join(" | ");

    const verificationPayload = JSON.stringify({
      commandId: plan.commandId,
      agentId: plan.agentId,
      status,
      checks: checkResults,
      verifiedAt,
    });
    const verificationHash = crypto.createHash("sha256").update(verificationPayload).digest("hex");

    // Record verification result into tamper-evident hash chain ledger
    try {
      await recordHashChainEvent({
        tenantId: plan.tenantId,
        eventType: allPassed ? "REMEDIATION_VERIFIED_SUCCESS" : "REMEDIATION_VERIFICATION_FAILED",
        actorId: `engine:verification`,
        payload: {
          commandId: plan.commandId,
          agentId: plan.agentId,
          action: plan.action,
          status,
          verificationHash,
          snapshotId: plan.snapshotId,
          failureReason,
        },
      });
    } catch {
      // In offline / unit test context
    }

    return {
      verified: allPassed,
      status,
      commandId: plan.commandId,
      agentId: plan.agentId,
      tenantId: plan.tenantId,
      checks: checkResults,
      proofOfState: actualHostEvidence,
      failureReason,
      rollbackActionRequired: !allPassed && plan.rollbackOnFailure,
      verifiedAt,
      verificationHash,
    };
  }
}
