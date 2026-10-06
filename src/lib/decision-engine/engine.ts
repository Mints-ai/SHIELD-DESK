import crypto from "node:crypto";
import { DecisionInput, DecisionOutput, ExplainableRiskFactor } from "./types";
import { PolicyEngine } from "../policy-engine/engine";
import { EvidenceEngine } from "./evidenceEngine";
import { ProductionSafetyGuard } from "@/config";
import { isKillSwitchEngaged } from "../fleet/fleet";
import { AutonomyTier } from "../governance/autonomyTier";
import { AutonomyMode } from "../policy-engine/types";

export class DecisionEngine {
  /**
   * The Decision Engine is the mandatory gateway for high-impact actions.
   * Evaluates input context (tenant, asset, risk, blast radius, policy, actor, evidence, confidence)
   * and deterministically yields ALLOW, DENY, REQUIRE_APPROVAL, or REQUIRE_DUAL_APPROVAL.
   */
  public static async evaluate(input: DecisionInput): Promise<DecisionOutput> {
    const evaluatedAt = new Date().toISOString();
    const blastRadius = input.blastRadius || { score: 10, exceeded: false };
    const evidence = [...(input.evidence || [])];

    // 1. Calculate Explainable Risk and Deterministic Security Confidence
    const riskAnalysis = EvidenceEngine.calculateExplainableRisk({
      tenantId: input.tenantId,
      cve: {
        cveId: input.risk?.cveId,
        cvss: input.risk?.cvss,
        epss: input.risk?.epss,
      },
      asset: {
        id: input.assetId,
        criticality: input.assetCriticality,
      },
      blastRadius: {
        score: blastRadius.score,
        calculationMode: blastRadius.calculationMode,
      },
      evidence,
    });

    const risk = {
      severity: input.risk?.severity || riskAnalysis.severity,
      score: input.risk?.score !== undefined ? input.risk.score : riskAnalysis.score,
      cveId: input.risk?.cveId,
      cvss: input.risk?.cvss,
      epss: input.risk?.epss,
      factors: input.risk?.factors || riskAnalysis.factors.map((f) => f.factor),
      factorsList: riskAnalysis.factors,
      securityConfidence: riskAnalysis.securityConfidence,
    };

    const securityConfidence = riskAnalysis.securityConfidence;
    const aiConfidence = typeof input.aiConfidence === "number" ? input.aiConfidence : undefined;

    // 2. Safety Guard Assertion (prevents simulated/demo command execution in production)
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
        "Tier 0",
        input.autonomyMode || "assist",
        securityConfidence,
        aiConfidence,
        risk,
        evidence,
        input,
        evaluatedAt,
        false
      );
    }

    // 3. Tenant Isolation Enforcement (actor tenant must match target resource tenant)
    if (input.actor.tenantId !== input.tenantId) {
      return DecisionEngine.buildOutput(
        "DENY",
        `Security boundary violation: Actor tenant '${input.actor.tenantId}' cannot propose actions for target tenant '${input.tenantId}'.`,
        0,
        "Tier 0",
        input.autonomyMode || "assist",
        securityConfidence,
        aiConfidence,
        risk,
        evidence,
        input,
        evaluatedAt,
        false
      );
    }

    // 4. Actor Permission Enforcement (Read-only roles cannot initiate active remediation)
    const readOnlyRoles = ["viewer", "auditor", "read_only", "billing_admin"];
    if (readOnlyRoles.includes(input.actor.role.toLowerCase())) {
      return DecisionEngine.buildOutput(
        "DENY",
        `Role '${input.actor.role}' does not hold operational permissions to execute or initiate remediation actions.`,
        0,
        "Tier 0",
        input.autonomyMode || "assist",
        securityConfidence,
        aiConfidence,
        risk,
        evidence,
        input,
        evaluatedAt,
        false
      );
    }

    // 5. Emergency Kill Switch Check
    try {
      const killSwitchActive = await isKillSwitchEngaged(input.tenantId);
      if (killSwitchActive) {
        return DecisionEngine.buildOutput(
          "DENY",
          `Tenant '${input.tenantId}' has an active Emergency Admin Kill Switch engaged. All active remediation is locked.`,
          0,
          "Tier 3",
          input.autonomyMode || "assist",
          securityConfidence,
          aiConfidence,
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

    // 6. Evaluate Deterministic Policy Engine (with asset-level autonomy)
    const policyResult = PolicyEngine.evaluatePolicy({
      tenantId: input.tenantId,
      action: input.action,
      assetCriticality: input.assetCriticality,
      riskSeverity: risk.severity,
      assetType: input.assetType,
      hostname: input.hostname,
      blastRadiusScore: blastRadius.score,
      autonomyMode: input.autonomyMode,
      assetAutonomyMode: input.assetAutonomyMode,
      tenantPolicy: input.policy,
    });

    let finalDecision = policyResult.decision;
    let finalReason = policyResult.reason;
    let requiredApprovals = policyResult.requiredApprovals;
    const autonomyTier = policyResult.autonomyTier || "Tier 1";
    const effectiveAutonomyMode = policyResult.effectiveAutonomyMode || input.autonomyMode || "assist";

    // 7. Blast Radius Throttle Check
    if (blastRadius.exceeded) {
      finalDecision = "REQUIRE_DUAL_APPROVAL";
      requiredApprovals = 2;
      finalReason += " Blast radius threshold strictly exceeded; escalated to dual approval.";
    }

    // 8. Core Product Principle: PROVE BEFORE YOU ACT
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

    // 9. Separate Security Confidence from AI Confidence:
    // If security confidence is below threshold, AI confidence NEVER allows unattended execution
    if (securityConfidence < 0.65 && isHighImpactAction) {
      if (finalDecision === "ALLOW") {
        finalDecision = "REQUIRE_APPROVAL";
        requiredApprovals = 1;
      }
      finalReason += ` Notice: Security confidence (${securityConfidence}) below autonomous threshold (0.65); escalated to human review despite AI confidence (${aiConfidence ?? "N/A"}).`;
    }

    if (securityConfidence < 0.40 && (input.assetCriticality === "critical" || (typeof blastRadius.score === "number" && blastRadius.score > 50))) {
      if (finalDecision === "REQUIRE_APPROVAL") {
        finalDecision = "REQUIRE_DUAL_APPROVAL";
        requiredApprovals = 2;
        finalReason += ` Notice: Critically low security confidence (${securityConfidence}) on critical scope; escalated to dual approval.`;
      }
    }

    return DecisionEngine.buildOutput(
      finalDecision,
      finalReason,
      requiredApprovals,
      autonomyTier,
      effectiveAutonomyMode,
      securityConfidence,
      aiConfidence,
      risk,
      evidence,
      input,
      evaluatedAt,
      policyResult.enforceMfa
    );
  }

  /**
   * Persists a decision record into the PostgreSQL `decision_records` table if DATABASE_URL is configured.
   */
  public static async persistDecisionRecord(output: DecisionOutput, actorPayload?: Record<string, unknown>): Promise<void> {
    if (!process.env.DATABASE_URL) return;

    try {
      const { query } = await import("../db");
      const recordId = output.id || `dec-${crypto.randomBytes(8).toString("hex")}`;
      await query(
        `INSERT INTO decision_records
          (id, tenant_id, incident_id, asset_id, action, decision, autonomy_tier, autonomy_mode,
           security_confidence, ai_confidence, risk_score, risk_factors, blast_radius_score,
           evidence_ids, evidence, reason, required_approvals, enforce_mfa, actor, decision_hash, evaluated_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, NOW())
         ON CONFLICT (id) DO NOTHING`,
        [
          recordId,
          output.tenantId,
          output.incidentId || null,
          output.assetId || null,
          output.action,
          output.decision,
          output.autonomyTier,
          output.autonomyMode,
          output.securityConfidence,
          output.aiConfidence ?? null,
          output.risk.score || 0,
          JSON.stringify(output.riskFactors || output.risk.factorsList || []),
          0,
          JSON.stringify(output.evidenceIds || []),
          JSON.stringify(output.evidence || []),
          output.reason,
          output.requiredApprovals,
          output.enforceMfa,
          JSON.stringify(actorPayload || {}),
          output.decisionHash,
          output.evaluatedAt,
        ]
      );
    } catch {
      // Non-blocking persistence error
    }
  }

  /**
   * Retrieves a persisted decision record by tenantId and ID.
   */
  public static async getDecisionRecord(tenantId: string, id: string): Promise<DecisionOutput | null> {
    if (!process.env.DATABASE_URL) return null;

    try {
      const { query } = await import("../db");
      const res = await query<{
        id: string;
        tenant_id: string;
        incident_id: string | null;
        asset_id: string | null;
        action: string;
        decision: string;
        autonomy_tier: string;
        autonomy_mode: string;
        security_confidence: string;
        ai_confidence: string | null;
        risk_score: string;
        risk_factors: unknown;
        evidence_ids: unknown;
        evidence: unknown;
        reason: string;
        required_approvals: number;
        enforce_mfa: boolean;
        decision_hash: string;
        evaluated_at: string;
      }>(
        `SELECT * FROM decision_records WHERE tenant_id = $1 AND id = $2`,
        [tenantId, id]
      );

      const row = res.rows[0];
      if (!row) return null;

      return {
        id: row.id,
        tenantId: row.tenant_id,
        incidentId: row.incident_id ?? undefined,
        assetId: row.asset_id ?? undefined,
        action: row.action,
        decision: row.decision as DecisionOutput["decision"],
        autonomyTier: row.autonomy_tier as AutonomyTier,
        autonomyMode: row.autonomy_mode as AutonomyMode,
        securityConfidence: parseFloat(row.security_confidence),
        aiConfidence: row.ai_confidence ? parseFloat(row.ai_confidence) : undefined,
        risk: {
          score: parseFloat(row.risk_score),
          factorsList: (row.risk_factors as ExplainableRiskFactor[]) || [],
        },
        riskFactors: (row.risk_factors as ExplainableRiskFactor[]) || [],
        evidenceIds: (row.evidence_ids as string[]) || [],
        evidence: (row.evidence as DecisionOutput["evidence"]) || [],
        reason: row.reason,
        requiredApprovals: row.required_approvals,
        enforceMfa: row.enforce_mfa,
        decisionHash: row.decision_hash,
        evaluatedAt: row.evaluated_at,
      };
    } catch {
      return null;
    }
  }

  /**
   * Lists decision records for a tenant with optional filtering.
   */
  public static async listDecisionRecords(
    tenantId: string,
    options?: { limit?: number; assetId?: string; decision?: string }
  ): Promise<DecisionOutput[]> {
    if (!process.env.DATABASE_URL) return [];

    try {
      const { query } = await import("../db");
      const limit = options?.limit ?? 50;
      let sql = `SELECT * FROM decision_records WHERE tenant_id = $1`;
      const params: unknown[] = [tenantId];

      if (options?.assetId) {
        params.push(options.assetId);
        sql += ` AND asset_id = $${params.length}`;
      }
      if (options?.decision) {
        params.push(options.decision);
        sql += ` AND decision = $${params.length}`;
      }

      params.push(limit);
      sql += ` ORDER BY created_at DESC LIMIT $${params.length}`;

      const res = await query<{
        id: string;
        tenant_id: string;
        incident_id: string | null;
        asset_id: string | null;
        action: string;
        decision: string;
        autonomy_tier: string;
        autonomy_mode: string;
        security_confidence: string;
        ai_confidence: string | null;
        risk_score: string;
        risk_factors: unknown;
        evidence_ids: unknown;
        evidence: unknown;
        reason: string;
        required_approvals: number;
        enforce_mfa: boolean;
        decision_hash: string;
        evaluated_at: string;
      }>(sql, params);

      return res.rows.map((row) => ({
        id: row.id,
        tenantId: row.tenant_id,
        incidentId: row.incident_id ?? undefined,
        assetId: row.asset_id ?? undefined,
        action: row.action,
        decision: row.decision as DecisionOutput["decision"],
        autonomyTier: row.autonomy_tier as AutonomyTier,
        autonomyMode: row.autonomy_mode as AutonomyMode,
        securityConfidence: parseFloat(row.security_confidence),
        aiConfidence: row.ai_confidence ? parseFloat(row.ai_confidence) : undefined,
        risk: {
          score: parseFloat(row.risk_score),
          factorsList: (row.risk_factors as ExplainableRiskFactor[]) || [],
        },
        riskFactors: (row.risk_factors as ExplainableRiskFactor[]) || [],
        evidenceIds: (row.evidence_ids as string[]) || [],
        evidence: (row.evidence as DecisionOutput["evidence"]) || [],
        reason: row.reason,
        requiredApprovals: row.required_approvals,
        enforceMfa: row.enforce_mfa,
        decisionHash: row.decision_hash,
        evaluatedAt: row.evaluated_at,
      }));
    } catch {
      return [];
    }
  }

  private static buildOutput(
    decision: DecisionOutput["decision"],
    reason: string,
    requiredApprovals: number,
    autonomyTier: AutonomyTier,
    autonomyMode: AutonomyMode,
    securityConfidence: number,
    aiConfidence: number | undefined,
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
      autonomyTier,
      securityConfidence,
    });
    const decisionHash = crypto.createHash("sha256").update(payloadToHash).digest("hex");
    const id = `dec-${decisionHash.slice(0, 16)}`;
    const evidenceIds = evidence.map((e) => e.id).filter(Boolean) as string[];

    return {
      id,
      decision,
      autonomyTier,
      autonomyMode,
      securityConfidence,
      aiConfidence,
      risk,
      riskFactors: risk.factorsList,
      evidenceIds,
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
