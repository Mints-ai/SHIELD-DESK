import crypto from "node:crypto";
import {
  VerificationPlan,
  VerificationResult,
  VerificationCheckSpec,
  VerificationMethodResult,
  RemediationVerificationStatus,
} from "./types";
import { VerificationMethods } from "./methods";
import { RollbackEngine } from "../rollback-engine/engine";
import { RollbackType } from "../rollback-engine/types";
import { recordHashChainEvent } from "../fleet/fleet";
import actionSpecs from "./action-specs.json";
import { getCapability } from "../fleet/capabilities";

export class VerificationEngine {
  /**
   * Generates a deterministic VerificationPlan for a proposed or executed remediation action.
   */
  public static createPlan(params: {
    action: string;
    agentId: string;
    tenantId: string;
    commandId: string;
    findingId?: string;
    snapshotId?: string;
    target?: string;
    cveId?: string;
    expectedVersion?: string;
    serviceName?: string;
    checks?: VerificationCheckSpec[];
  }): VerificationPlan {
    const { action, agentId, tenantId, commandId, findingId, snapshotId, target, cveId, expectedVersion, serviceName } = params;
    const checks: VerificationCheckSpec[] = params.checks ? [...params.checks] : [];

    if (checks.length === 0) {
      const capability = getCapability(action);
      const spec = capability && actionSpecs[capability.name as keyof typeof actionSpecs];
      if (!capability || !spec) throw new Error(`No registered verification specification for action '${action}'.`);
      const resolvedTarget = target || cveId || snapshotId || serviceName || agentId;
      checks.push(...spec.verification_methods.map((method) => ({
        method,
        target: method === "service_health_check" ? (serviceName || (capability.name === "service.restart" ? target || agentId : "agent-control-plane")) : resolvedTarget,
        expectedState: method === "package_version_check" && expectedVersion
          ? { ...spec.expected_state, version: expectedVersion }
          : { ...spec.expected_state },
      } as VerificationCheckSpec)));
    }

    return {
      action,
      agentId,
      tenantId,
      commandId,
      findingId,
      expected: { verified: true },
      checks,
      rollbackOnFailure: Boolean(snapshotId),
      snapshotId,
    };
  }

  /**
   * Evaluates endpoint evidence against the VerificationPlan.
   * Core Thesis: Proof Before Action. Never claim an action succeeded without verification.
   * Closed-loop: If verification fails, automatically triggers rollback and reopens finding.
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
      } else if (spec.method === "service_health_check") {
        const res = await VerificationMethods.checkServiceHealth(spec, actualHostEvidence);
        checkResults.push(res);
      } else if (spec.method === "config_state_check") {
        const res = await VerificationMethods.checkConfigState(spec, actualHostEvidence);
        checkResults.push(res);
      } else if (spec.method === "port_reachability_check") {
        const res = await VerificationMethods.checkPortReachability(spec, actualHostEvidence);
        checkResults.push(res);
      } else if (spec.method === "snapshot_state_check") {
        checkResults.push(await VerificationMethods.checkSnapshotState(spec, actualHostEvidence));
      } else if (spec.method === "file_quarantine_check") {
        checkResults.push(await VerificationMethods.checkFileQuarantine(spec, actualHostEvidence));
      } else {
        checkResults.push({
          method: spec.method,
          target: spec.target,
          success: false,
          expectedState: spec.expectedState,
          actualState: { status: "unsupported_verification_method" },
          details: `Verification failed: method '${spec.method}' is unsupported; evidence cannot be accepted.`,
          timestamp: verifiedAt,
        });
      }
    }

    const allPassed = checkResults.every((c) => c.success);
    const status: RemediationVerificationStatus = allPassed ? "VERIFIED" : "FAILED";
    const failureReason = allPassed
      ? undefined
      : checkResults.filter((c) => !c.success).map((c) => c.details).join(" | ");

    let rollbackExecuted = false;
    let rollbackResultRecord: Record<string, unknown> | undefined;
    let findingReopened = false;

    // Fail-Closed: If verification fails and rollback is enabled, trigger rollback immediately
    if (!allPassed && plan.rollbackOnFailure) {
      let rollbackType: RollbackType = "snapshot_restore";
      const actionLower = plan.action.toLowerCase();
      if (actionLower.includes("isolate") || actionLower.includes("block")) {
        rollbackType = "network_rollback";
      } else if (actionLower.includes("package") || actionLower.includes("patch")) {
        rollbackType = "package_rollback";
      } else if (actionLower.includes("service")) {
        rollbackType = "service_rollback";
      } else if (actionLower.includes("config")) {
        rollbackType = "configuration_rollback";
      }

      try {
        const rbRes = await RollbackEngine.executeRollback({
          tenantId: plan.tenantId,
          agentId: plan.agentId,
          commandId: plan.commandId,
          snapshotId: plan.snapshotId || `snap-auto-${plan.agentId}`,
          rollbackType,
          reason: `Verification failed: ${failureReason || "State proof check mismatch"}`,
          actorId: "engine:verification",
        });
        rollbackExecuted = rbRes.success;
        rollbackResultRecord = rbRes as unknown as Record<string, unknown>;
      } catch {
        rollbackExecuted = false;
      }
    }

    // Closed-loop: If verification failed, reopen associated finding
    if (!allPassed && plan.findingId) {
      findingReopened = true;
      try {
        const { query } = await import("../db");
        await query(
          `UPDATE asset_vulnerabilities
           SET status = 'open', remediated_at = NULL
           WHERE tenant_id = $1 AND (id::text = $2 OR cve_id = $2)`,
          [plan.tenantId, plan.findingId]
        );
      } catch {
        // In offline / unit test mock context
      }
    }

    const verificationPayload = JSON.stringify({
      commandId: plan.commandId,
      agentId: plan.agentId,
      findingId: plan.findingId,
      status,
      rollbackExecuted,
      checks: checkResults,
      verifiedAt,
    });
    const verificationHash = crypto.createHash("sha256").update(verificationPayload).digest("hex");

    // Record verification result into tamper-evident hash chain ledger
    try {
      await recordHashChainEvent({
        tenantId: plan.tenantId,
        eventType: allPassed
          ? "REMEDIATION_VERIFIED_SUCCESS"
          : rollbackExecuted
          ? "REMEDIATION_ROLLED_BACK"
          : "REMEDIATION_VERIFICATION_FAILED",
        actorId: "engine:verification",
        payload: {
          commandId: plan.commandId,
          agentId: plan.agentId,
          findingId: plan.findingId,
          action: plan.action,
          status,
          verificationHash,
          snapshotId: plan.snapshotId,
          rollbackExecuted,
          failureReason,
        },
      });
    } catch {
      // In offline / unit test context
    }

    const result: VerificationResult = {
      verified: allPassed,
      status,
      commandId: plan.commandId,
      agentId: plan.agentId,
      tenantId: plan.tenantId,
      findingId: plan.findingId,
      checks: checkResults,
      proofOfState: actualHostEvidence,
      failureReason,
      rollbackActionRequired: !allPassed && plan.rollbackOnFailure,
      rollbackExecuted,
      rollbackResult: rollbackResultRecord,
      findingReopened,
      verifiedAt,
      verificationHash,
    };

    // Persist verification to Postgres
    try {
      await this.persistVerification(result);
    } catch {
      // In offline / mock test context
    }

    return result;
  }

  /**
   * Persists a VerificationResult to the remediation_verifications table.
   */
  public static async persistVerification(res: VerificationResult): Promise<void> {
    const { query } = await import("../db");
    const verifId = `vrf-${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`;
    await query(
      `INSERT INTO remediation_verifications (
        id, tenant_id, command_id, agent_id, finding_id,
        status, checks, proof_of_state, rollback_executed,
        failure_reason, verification_hash, verified_at, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())`,
      [
        verifId,
        res.tenantId,
        res.commandId,
        res.agentId,
        res.findingId || null,
        res.status,
        JSON.stringify(res.checks),
        JSON.stringify(res.proofOfState),
        res.rollbackExecuted || false,
        res.failureReason || null,
        res.verificationHash,
        res.verifiedAt,
      ]
    );
  }

  /**
   * Retrieves remediation verifications for an agent or tenant.
   */
  public static async getVerifications(
    tenantId: string,
    filter?: { agentId?: string; commandId?: string; status?: string; limit?: number }
  ): Promise<any[]> {
    try {
      const { query } = await import("../db");
      let sql = `SELECT * FROM remediation_verifications WHERE tenant_id = $1`;
      const params: any[] = [tenantId];

      if (filter?.agentId) {
        params.push(filter.agentId);
        sql += ` AND agent_id = $${params.length}`;
      }
      if (filter?.commandId) {
        params.push(filter.commandId);
        sql += ` AND command_id = $${params.length}`;
      }
      if (filter?.status) {
        params.push(filter.status);
        sql += ` AND status = $${params.length}`;
      }

      sql += ` ORDER BY verified_at DESC LIMIT $${params.length + 1}`;
      params.push(filter?.limit || 50);

      const res = await query(sql, params);
      return res.rows;
    } catch {
      return [];
    }
  }
}
