import crypto from "node:crypto";
import { query } from "@/lib/db";
import { recordHashChainEvent } from "./fleet";
import { signCommand, verifyCommandSignature } from "./commandSigning";
import { getApprovalToken } from "@/lib/governance/approvalTokens";
import { AgentResultVerifier, SignedAgentResultPayload } from "./agentResultVerifier";
import { MTLSGuard } from "./mtlsGuard";
import { MetricsRegistry } from "@/lib/observability/metrics";
import { LicenseActivationService } from "@/lib/licensing/licenseActivation";
import { isProduction } from "@/lib/config/environment";

export type CommandLifecycleState =
  | "REQUESTED"
  | "APPROVED"
  | "SIGNED"
  | "QUEUED"
  | "DELIVERED"
  | "EXECUTING"
  | "EXECUTED"
  | "VERIFIED"
  | "ROLLED_BACK"
  | "FAILED";

export interface EphemeralDispatchToken {
  tokenId: string;
  commandId: string;
  agentId: string;
  tenantId: string;
  tier: string;
  nonce: string;
  tokenHash: string;
  expiresAt: string;
  isConsumed: boolean;
}

export interface DispatchCommandRequest {
  commandId?: string;
  agentId: string;
  tenantId: string;
  command: string;
  tier: "Tier 1" | "Tier 2" | "Tier 3";
  tokenId?: string; // Human approval token ID
  snapshotId?: string; // Pre-execution state snapshot
  dispatchedBy: string;
  parameters?: Record<string, unknown>;
}

export interface DispatchResult {
  success: boolean;
  commandId: string;
  dispatchToken: string;
  signature: string;
  nonce: string;
  state: CommandLifecycleState;
  error?: string;
  expiresAt: string;
}

export class ExecutionBroker {
  private static inMemoryDispatchTokens: Map<string, EphemeralDispatchToken> = new Map();
  private static inMemoryCommandStates: Map<string, CommandLifecycleState> = new Map();

  /**
   * Generates a short-lived (5-minute TTL) cryptographic dispatch token.
   */
  public static generateDispatchToken(params: {
    commandId: string;
    agentId: string;
    tenantId: string;
    tier: string;
    nonce: string;
    ttlSeconds?: number;
  }): EphemeralDispatchToken {
    const ttl = params.ttlSeconds || 300; // 5 minutes
    const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
    const tokenId = `dtok-${crypto.randomBytes(12).toString("hex")}`;

    const canonical = `${tokenId}|${params.commandId}|${params.agentId}|${params.tenantId}|${params.nonce}|${expiresAt}`;
    const tokenHash = crypto.createHash("sha256").update(canonical).digest("hex");

    const record: EphemeralDispatchToken = {
      tokenId,
      commandId: params.commandId,
      agentId: params.agentId,
      tenantId: params.tenantId,
      tier: params.tier,
      nonce: params.nonce,
      tokenHash,
      expiresAt,
      isConsumed: false,
    };

    this.inMemoryDispatchTokens.set(tokenId, record);
    return record;
  }

  /**
   * Validates that an ephemeral dispatch token is active and unexpired.
   */
  public static validateDispatchToken(tokenId: string, agentId?: string): { valid: boolean; reason?: string; token?: EphemeralDispatchToken } {
    const token = this.inMemoryDispatchTokens.get(tokenId);
    if (!token) {
      return { valid: false, reason: "Unknown or invalid dispatch token." };
    }

    if (token.isConsumed) {
      return { valid: false, reason: "Dispatch token already consumed. Replay attack blocked." };
    }

    if (new Date(token.expiresAt).getTime() < Date.now()) {
      return { valid: false, reason: "Dispatch token expired under fail-closed security policy." };
    }

    if (agentId && token.agentId !== agentId) {
      return { valid: false, reason: "Dispatch token agent binding mismatch." };
    }

    return { valid: true, token };
  }

  /**
   * The Execution Broker is the single authorized dispatch point for endpoint remediation commands.
   * Enforces Rule 2 (Fail Closed), Rule 3 (Broker as Single Dispatch Point), and Rule 8 (Lifecycle States).
   */
  public static async dispatchCommand(req: DispatchCommandRequest): Promise<DispatchResult> {
    const commandId = req.commandId || `cmd-${crypto.randomBytes(8).toString("hex")}`;
    const nonce = crypto.randomBytes(16).toString("hex");

    if (isProduction() && !(await LicenseActivationService.isDeviceActive(req.tenantId, req.agentId))) {
      return { success: false, commandId, dispatchToken: "", signature: "", nonce, state: "FAILED", error: "Active tenant-bound agent license activation is required before command dispatch.", expiresAt: "" };
    }

    // 1. Pre-execution Snapshot Verification (Rule 2)
    if ((req.tier === "Tier 2" || req.tier === "Tier 3") && !req.snapshotId) {
      return {
        success: false,
        commandId,
        dispatchToken: "",
        signature: "",
        nonce,
        state: "FAILED",
        error: "Rule 2 Invariant Violation: Pre-execution safety snapshot is missing. State changes without guaranteed reversibility are forbidden.",
        expiresAt: "",
      };
    }

    // 2. Mandatory Approval Verification for Tier 2 and Tier 3 (Rule 4)
    if (req.tier === "Tier 2" || req.tier === "Tier 3") {
      if (!req.tokenId) {
        return {
          success: false,
          commandId,
          dispatchToken: "",
          signature: "",
          nonce,
          state: "FAILED",
          error: `Rule 4 Violation: ${req.tier} actions strictly require an authorized approval token.`,
          expiresAt: "",
        };
      }

      const tokenRecord = await getApprovalToken(req.tokenId);
      if (!tokenRecord || tokenRecord.status !== "approved") {
        return {
          success: false,
          commandId,
          dispatchToken: "",
          signature: "",
          nonce,
          state: "FAILED",
          error: `Rule 4 Violation: Approval token '${req.tokenId}' is not in approved state. Dispatch blocked.`,
          expiresAt: "",
        };
      }

      // Check token expiry
      if (new Date(tokenRecord.expires_at).getTime() < Date.now()) {
        return {
          success: false,
          commandId,
          dispatchToken: "",
          signature: "",
          nonce,
          state: "FAILED",
          error: "Approval token has expired under fail-closed security policy.",
          expiresAt: "",
        };
      }
    }

    // 3. Generate Canonical RSA-SHA256 Command Signature (Transition: APPROVED -> SIGNED)
    const signature = signCommand({
      agentId: req.agentId,
      command: req.command,
      nonce,
      tier: req.tier,
    });

    if (!signature) {
      return {
        success: false,
        commandId,
        dispatchToken: "",
        signature: "",
        nonce,
        state: "FAILED",
        error: "Failed to generate cryptographic command signature.",
        expiresAt: "",
      };
    }

    // 4. Generate Short-Lived Ephemeral Dispatch Token (TTL: 300s)
    const dispatchToken = this.generateDispatchToken({
      commandId,
      agentId: req.agentId,
      tenantId: req.tenantId,
      tier: req.tier,
      nonce,
    });

    // 5. Transition State to QUEUED
    this.inMemoryCommandStates.set(commandId, "QUEUED");

    // 6. Persist to Database if available
    try {
      await query(
        `INSERT INTO execution_dispatch_tokens (
          id, command_id, agent_id, tenant_id, tier, token_hash, nonce, status, expires_at, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, NOW())`,
        [
          dispatchToken.tokenId,
          commandId,
          req.agentId,
          req.tenantId,
          req.tier,
          dispatchToken.tokenHash,
          nonce,
          dispatchToken.expiresAt,
        ]
      );

      await query(
        `INSERT INTO agent_commands (
          id, agent_id, tenant_id, command, tier, token_id, signature, nonce, status, snapshot_id, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, NOW())`,
        [
          commandId,
          req.agentId,
          req.tenantId,
          req.command,
          req.tier,
          req.tokenId || null,
          signature,
          nonce,
          req.snapshotId || null,
        ]
      );
    } catch {
      // In-memory fallback
    }

    // 7. Audit Logging to Tamper-Evident Hash Chain
    await recordHashChainEvent({
      tenantId: req.tenantId,
      eventType: "EXECUTION_BROKER_COMMAND_DISPATCHED",
      actorId: req.dispatchedBy,
      payload: {
        commandId,
        agentId: req.agentId,
        tier: req.tier,
        dispatchTokenId: dispatchToken.tokenId,
        expiresAt: dispatchToken.expiresAt,
        snapshotId: req.snapshotId || null,
      },
    });

    MetricsRegistry.increment("shielddesk_commands_dispatched_total", 1, { tier: req.tier });

    return {
      success: true,
      commandId,
      dispatchToken: dispatchToken.tokenId,
      signature,
      nonce,
      state: "QUEUED",
      expiresAt: dispatchToken.expiresAt,
    };
  }

  /**
   * Called when an agent polls or receives the command (Transition: QUEUED -> DELIVERED).
   */
  public static async markCommandDelivered(
    commandId: string,
    agentId: string,
    dispatchTokenId: string
  ): Promise<{ success: boolean; reason?: string }> {
    const tokenCheck = this.validateDispatchToken(dispatchTokenId, agentId);
    if (!tokenCheck.valid) {
      return { success: false, reason: tokenCheck.reason };
    }

    // Recheck device and kill-switch state at delivery time to close the dispatch/delivery race.
    const deviceCheck = await MTLSGuard.validateClientCertificate({ agentId, tenantId: tokenCheck.token!.tenantId });
    if (!deviceCheck.allowed) {
      tokenCheck.token!.isConsumed = true;
      return { success: false, reason: `mTLS device check failed: ${deviceCheck.reason}` };
    }

    // Consume synchronously before any asynchronous persistence so concurrent/replayed delivery is rejected.
    tokenCheck.token!.isConsumed = true;

    this.inMemoryCommandStates.set(commandId, "DELIVERED");

    try {
      await query(`UPDATE agent_commands SET status = 'delivered' WHERE id = $1`, [commandId]);
    } catch {
      // Fallback
    }

    return { success: true };
  }

  /**
   * Processes a signed execution result returned from an endpoint agent.
   * Verifies agent RSA-2048 / mTLS signature (Transition: EXECUTING -> EXECUTED).
   */
  public static async processSignedAgentResult(
    resultPayload: SignedAgentResultPayload,
    options?: { agentPublicKeyPem?: string; allowTestKey?: boolean }
  ): Promise<{
    success: boolean;
    state: CommandLifecycleState;
    reason?: string;
  }> {
    // 1. Verify mTLS / Device Certificate
    const mtlsCheck = await MTLSGuard.validateClientCertificate({
      agentId: resultPayload.agentId,
      tenantId: resultPayload.tenantId,
    });

    if (!mtlsCheck.allowed) {
      MetricsRegistry.increment("shielddesk_agent_result_rejections_total", 1, { reason: "mtls" });
      return {
        success: false,
        state: "FAILED",
        reason: `mTLS device check failed: ${mtlsCheck.reason}`,
      };
    }

    // 2. Verify Cryptographic Result Signature
    const verification = await AgentResultVerifier.verifyResult(resultPayload, options);
    if (!verification.verified) {
      MetricsRegistry.increment("shielddesk_agent_result_rejections_total", 1, { reason: "signature_or_freshness" });
      return {
        success: false,
        state: "FAILED",
        reason: `Agent result signature verification rejected: ${verification.reason}`,
      };
    }

    // 3. Mark Command EXECUTED
    const finalState: CommandLifecycleState = resultPayload.exitCode === 0 ? "EXECUTED" : "FAILED";
    MetricsRegistry.increment(resultPayload.exitCode === 0 ? "shielddesk_commands_executed_total" : "shielddesk_command_execution_failures_total");
    this.inMemoryCommandStates.set(resultPayload.commandId, finalState);

    // 4. Update Database
    try {
      await query(
        `UPDATE agent_commands SET status = $1, result = $2, completed_at = NOW() WHERE id = $3`,
        [
          finalState === "EXECUTED" ? "succeeded" : "failed",
          JSON.stringify({
            stdout: resultPayload.stdout,
            stderr: resultPayload.stderr,
            exitCode: resultPayload.exitCode,
            hostStateDigest: resultPayload.hostStateDigest,
          }),
          resultPayload.commandId,
        ]
      );
    } catch {
      // Fallback
    }

    // 5. Record Hash-Chain Audit
    await recordHashChainEvent({
      tenantId: resultPayload.tenantId,
      eventType: "AGENT_SIGNED_RESULT_VERIFIED",
      actorId: `agent:${resultPayload.agentId}`,
      payload: {
        commandId: resultPayload.commandId,
        exitCode: resultPayload.exitCode,
        hostStateDigest: resultPayload.hostStateDigest,
        verified: true,
      },
    });

    return {
      success: resultPayload.exitCode === 0,
      state: finalState,
    };
  }

  /**
   * Retrieves the current lifecycle state of a command.
   */
  public static getCommandState(commandId: string): CommandLifecycleState {
    return this.inMemoryCommandStates.get(commandId) || "REQUESTED";
  }
}
