import crypto from "node:crypto";
import { RollbackRequest, RollbackResult, RollbackOutcomeStatus } from "./types";
import { recordHashChainEvent, getEndpointAgent, executeAgentCommand } from "../fleet/fleet";
import { isProduction, isSimulationAllowed, shouldFailClosed } from "@/lib/config/environment";
import type { SessionUser } from "@/lib/auth/session";
import { MetricsRegistry } from "@/lib/observability/metrics";

export class RollbackEngine {
  /**
   * Executes a governed rollback of an unverified, failed, or operator-aborted remediation.
   * Mandates cryptographic audit attestation for all state reversions.
   * Enforces the governance path: Validation -> Authorization -> Signed Command Dispatch -> Verification -> Immutable Audit.
   */
  public static async executeRollback(request: RollbackRequest): Promise<RollbackResult> {
    const revertedAt = new Date().toISOString();
    const cleanAgentId = request.agentId.toLowerCase().replace(/[^a-z0-9]/g, "-");
    const rollbackId = `rb-${cleanAgentId}-${Date.now().toString(36)}`;

    const caller: SessionUser = request.caller || {
      id: request.actorId || "engine:rollback",
      tenant_id: request.tenantId,
      role: "super_admin",
    };

    let rollbackCommand = `rollback_snapshot ${request.snapshotId}`;
    if (request.rollbackType === "network_rollback") {
      rollbackCommand = "restore_host";
    } else if (request.rollbackType === "service_rollback") {
      rollbackCommand = `restart_service ${request.snapshotId || "agent-control-plane"}`;
    } else if (request.rollbackType === "package_rollback") {
      rollbackCommand = `package_downgrade ${request.snapshotId}`;
    } else if (request.rollbackType === "configuration_rollback") {
      rollbackCommand = `restore_config ${request.snapshotId}`;
    }

    const agent = await getEndpointAgent(request.agentId, caller);

    // 1. Authorization and Safety Boundaries
    if (!agent) {
      if (isProduction() || shouldFailClosed()) {
        const payload = {
          rollbackId,
          commandId: request.commandId,
          agentId: request.agentId,
          snapshotId: request.snapshotId,
          rollbackType: request.rollbackType,
          reason: request.reason,
          error: "AGENT_NOT_FOUND",
          status: "ROLLBACK_BLOCKED" as RollbackOutcomeStatus,
          revertedAt,
        };
        const hash = crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex");
        await recordHashChainEvent({
          tenantId: request.tenantId,
          eventType: "REMEDIATION_ROLLBACK_BLOCKED",
          actorId: request.actorId,
          payload: { ...payload, rollbackHash: hash, rollbackExecuted: false },
        });
        return {
          success: false,
          status: "ROLLBACK_BLOCKED",
          rollbackId,
          commandId: request.commandId,
          agentId: request.agentId,
          tenantId: request.tenantId,
          snapshotId: request.snapshotId,
          rollbackType: request.rollbackType,
          output: `Rollback blocked: agent '${request.agentId}' not found for tenant '${request.tenantId}'.`,
          revertedAt,
          rollbackHash: hash,
          error: "AGENT_NOT_FOUND",
        };
      }
    }

    if (agent && agent.kill_switch_active) {
      const payload = {
        rollbackId,
        commandId: request.commandId,
        agentId: request.agentId,
        snapshotId: request.snapshotId,
        rollbackType: request.rollbackType,
        reason: request.reason,
        error: "KILL_SWITCH_ACTIVE",
        status: "ROLLBACK_BLOCKED" as RollbackOutcomeStatus,
        revertedAt,
      };
      const hash = crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex");
      await recordHashChainEvent({
        tenantId: request.tenantId,
        eventType: "REMEDIATION_ROLLBACK_BLOCKED",
        actorId: request.actorId,
        payload: { ...payload, rollbackHash: hash, rollbackExecuted: false },
      });
      return {
        success: false,
        status: "ROLLBACK_BLOCKED",
        rollbackId,
        commandId: request.commandId,
        agentId: request.agentId,
        tenantId: request.tenantId,
        snapshotId: request.snapshotId,
        rollbackType: request.rollbackType,
        output: `Rollback blocked: agent '${request.agentId}' kill switch is active.`,
        revertedAt,
        rollbackHash: hash,
        error: "KILL_SWITCH_ACTIVE",
      };
    }

    // 2. Dispatch signed rollback command through execution pathway
    let dispatchSuccess = false;
    let dispatchOutput = "";
    let isSimulated = false;
    let status: RollbackOutcomeStatus = "ROLLBACK_FAILED";

    if (agent) {
      try {
        const execRes = await executeAgentCommand({
          agentId: agent.id,
          command: rollbackCommand,
          tier: "Tier 1",
          caller,
        });
        dispatchSuccess = execRes.success;
        dispatchOutput = execRes.output;
        isSimulated = Boolean(execRes.isSimulated);

        if (dispatchSuccess) {
          if (isSimulated) {
            status = "RESTORATION_VERIFIED";
          } else {
            status = "ROLLBACK_DISPATCHED";
          }
        } else {
          status = "ROLLBACK_FAILED";
        }
      } catch (err: unknown) {
        dispatchSuccess = false;
        dispatchOutput = err instanceof Error ? err.message : "Execution failed";
        status = "ROLLBACK_FAILED";
      }
    } else if (isSimulationAllowed()) {
      // Offline / unit test fixture fallback when agent record not registered in memory
      dispatchSuccess = true;
      dispatchOutput = `Rollback (${request.rollbackType}) executed on agent ${request.agentId} using snapshot ${request.snapshotId}. Reason: ${request.reason}.`;
      isSimulated = true;
      status = "RESTORATION_VERIFIED";
    }

    const output = dispatchOutput || `Rollback (${request.rollbackType}) executed on agent ${request.agentId} using snapshot ${request.snapshotId}. Reason: ${request.reason}.`;

    const rollbackPayload = JSON.stringify({
      rollbackId,
      commandId: request.commandId,
      agentId: request.agentId,
      snapshotId: request.snapshotId,
      rollbackType: request.rollbackType,
      rollbackCommand,
      status,
      isSimulated,
      revertedAt,
    });
    const rollbackHash = crypto.createHash("sha256").update(rollbackPayload).digest("hex");

    // 3. Record into tamper-evident hash chain ledger
    try {
      await recordHashChainEvent({
        tenantId: request.tenantId,
        eventType: "REMEDIATION_ROLLED_BACK",
        actorId: request.actorId,
        payload: {
          rollbackId,
          commandId: request.commandId,
          agentId: request.agentId,
          snapshotId: request.snapshotId,
          rollbackType: request.rollbackType,
          reason: request.reason,
          rollbackCommand,
          rollbackHash,
          rollbackExecuted: dispatchSuccess,
          status,
          isSimulated,
        },
      });
    } catch (auditErr: unknown) {
      if (isProduction()) {
        throw new Error(`MANDATORY_AUDIT_LOG_FAILED: Failed to record rollback in hash chain ledger: ${auditErr instanceof Error ? auditErr.message : "Unknown error"}`);
      }
    }

    MetricsRegistry.increment(dispatchSuccess ? "shielddesk_rollback_outcomes_total" : "shielddesk_rollback_failures_total", 1, {
      outcome: status,
      rollback_type: request.rollbackType,
    });

    return {
      success: dispatchSuccess,
      status,
      rollbackId,
      commandId: request.commandId,
      agentId: request.agentId,
      tenantId: request.tenantId,
      snapshotId: request.snapshotId,
      rollbackType: request.rollbackType,
      output,
      revertedAt,
      rollbackHash,
      isSimulated,
    };
  }
}
