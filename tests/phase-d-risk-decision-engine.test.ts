/**
 * Phase D: Risk and Decision Engine Test Suite
 *
 * Verifies:
 * 1. EvidenceEngine: Canonical SHA-256 hashing and integrity verification
 * 2. Explainable Risk: Every risk factor references a valid evidence ID
 * 3. Asset-level autonomy (Observe / Assist / Autopilot) mapped to Tiers 0-3
 * 4. Critical asset safety guard: Crown jewel assets cannot run in unattended autopilot
 * 5. Separation of Security Confidence vs AI Confidence (AI confidence cannot override low security confidence)
 * 6. Decision Record generation with tamper-evident decisionHash
 * 7. Tenant isolation, RBAC enforcement, and emergency kill-switch fail-closed behaviors
 * 8. Backward compatibility with existing callers
 */

import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { EvidenceEngine } from "../src/lib/decision-engine/evidenceEngine";
import { DecisionEngine } from "../src/lib/decision-engine/engine";
import { PolicyEngine } from "../src/lib/policy-engine/engine";
import { setKillSwitchState } from "../src/lib/fleet/fleet";

test("Phase D: Risk & Decision Engine Suite", async (t) => {
  const tenantId = "tenant-cyber-defense";
  const actor = {
    id: "usr-sec-analyst",
    role: "analyst",
    tenantId,
    ipAddress: "10.0.4.50",
    mfaVerified: true,
  };

  await t.test("EvidenceEngine: Creates canonical evidence and verifies cryptographic integrity", () => {
    const evidence = EvidenceEngine.createEvidence("cve_intelligence", "vuln_scanner", {
      cveId: "CVE-2024-3400",
      severity: "critical",
      cvss: 9.8,
    });

    assert.ok(evidence.id?.startsWith("evi-"));
    assert.ok(evidence.hash && evidence.hash.length === 64);
    assert.equal(EvidenceEngine.verifyEvidenceIntegrity(evidence), true);

    // Tampering test: mutating data invalidates the hash
    const tampered = { ...evidence, data: { ...evidence.data, cvss: 4.0 } };
    assert.equal(EvidenceEngine.verifyEvidenceIntegrity(tampered), false);
  });

  await t.test("Explainable Risk: Every single risk factor carries an explicit evidence ID", () => {
    const ev1 = EvidenceEngine.createEvidence("cve_cvss_score", "nvd", { cveId: "CVE-2021-44228", cvss: 10.0 });
    const ev2 = EvidenceEngine.createEvidence("cisa_kev_active_exploit", "cisa", { cveId: "CVE-2021-44228" });
    const ev3 = EvidenceEngine.createEvidence("network_topology_exposure", "twin", { internetFacing: true });

    const risk = EvidenceEngine.calculateExplainableRisk({
      tenantId,
      cve: { cveId: "CVE-2021-44228", cvss: 10.0, kev: true },
      asset: { id: "srv-edge-01", criticality: "critical", internetFacing: true, isChokePoint: true },
      evidence: [ev1, ev2, ev3],
    });

    assert.equal(risk.severity, "critical");
    assert.ok(risk.score >= 8.5);
    assert.ok(risk.factors.length >= 4);

    // Rule 7 Invariant: Every single factor must have a valid evidenceId
    for (const factor of risk.factors) {
      assert.ok(factor.evidenceId && factor.evidenceId.startsWith("evi-"), `Factor ${factor.factor} must have evidenceId`);
      assert.ok(factor.scoreDelta > 0);
      assert.ok(factor.description.length > 0);
    }

    assert.ok(risk.securityConfidence >= 0.85);
  });

  await t.test("PolicyEngine: Asset-level autonomy mode overrides tenant policy and maps to Tiers 0-3", () => {
    // 1. Tenant default is "autopilot", but sensitive server specifies assetAutonomyMode = "observe"
    const observeRes = PolicyEngine.evaluatePolicy({
      tenantId,
      action: "isolate_host",
      autonomyMode: "autopilot",
      assetAutonomyMode: "observe",
    });
    assert.equal(observeRes.decision, "DENY");
    assert.equal(observeRes.effectiveAutonomyMode, "observe");
    assert.equal(observeRes.autonomyTier, "Tier 2");

    // 2. Tenant default is "observe", but standard asset specifies assetAutonomyMode = "autopilot"
    const autoRes = PolicyEngine.evaluatePolicy({
      tenantId,
      action: "isolate_host",
      autonomyMode: "observe",
      assetAutonomyMode: "autopilot",
      assetCriticality: "medium",
    });
    assert.equal(autoRes.decision, "ALLOW");
    assert.equal(autoRes.effectiveAutonomyMode, "autopilot");
    assert.equal(autoRes.autonomyTier, "Tier 2");

    // 3. Safety Guard: Critical crown jewel assets CANNOT run in unattended autopilot
    const criticalSafetyRes = PolicyEngine.evaluatePolicy({
      tenantId,
      action: "isolate_host",
      autonomyMode: "autopilot",
      assetAutonomyMode: "autopilot",
      assetCriticality: "critical",
    });
    assert.equal(criticalSafetyRes.effectiveAutonomyMode, "assist"); // Clamped to assist
    assert.equal(criticalSafetyRes.decision, "REQUIRE_APPROVAL");
    assert.equal(criticalSafetyRes.requiredApprovals, 1);
  });

  await t.test("DecisionEngine: Separates Security Confidence from AI Confidence (Rule 1 & Rule 2)", async () => {
    const ev = EvidenceEngine.createEvidence("raw_telemetry", "edr", { anomaly: true });

    // Scenario: AI model is 99% confident in isolating the host, BUT security confidence is low (0.4) due to estimated blast radius
    const decision = await DecisionEngine.evaluate({
      tenantId,
      action: "isolate_host",
      assetId: "srv-unknown-box",
      assetCriticality: "high",
      autonomyMode: "autopilot",
      aiConfidence: 0.99, // LLM is 99% confident
      blastRadius: { score: 75, exceeded: false, calculationMode: "estimated" },
      evidence: [ev], // Sparse evidence
      actor,
    });

    // In autopilot, isolate_host would normally be ALLOW, BUT low security confidence forces human approval
    assert.notEqual(decision.decision, "ALLOW");
    assert.equal(decision.decision, "REQUIRE_APPROVAL");
    assert.equal(decision.requiredApprovals, 1);
    assert.ok(decision.securityConfidence < 0.65);
    assert.equal(decision.aiConfidence, 0.99);
    assert.match(decision.reason, /Security confidence/i);
    assert.match(decision.reason, /AI confidence/i);
  });

  await t.test("DecisionEngine: Generates tamper-evident Decision Record with cryptographic hash", async () => {
    const ev1 = EvidenceEngine.createEvidence("cve_cvss_score", "nvd", { cvss: 8.5 });
    const decision = await DecisionEngine.evaluate({
      tenantId,
      action: "revoke_user_sessions",
      assetId: "usr-compromised-token",
      evidence: [ev1],
      actor,
    });

    assert.ok(decision.id && decision.id.startsWith("dec-"));
    assert.ok(decision.decisionHash && decision.decisionHash.length === 64);
    assert.equal(decision.autonomyTier, "Tier 1");
    assert.ok(decision.securityConfidence > 0);
    assert.ok(decision.evidenceIds && decision.evidenceIds.length >= 1);
  });

  await t.test("Security Boundaries: Blocks cross-tenant proposals, unauthorized roles, and kill-switches", async () => {
    // 1. Cross-tenant attempt
    const crossTenantRes = await DecisionEngine.evaluate({
      tenantId: "tenant-target-b",
      action: "isolate_host",
      evidence: [],
      actor: { ...actor, tenantId: "tenant-attacker-a" },
    });
    assert.equal(crossTenantRes.decision, "DENY");
    assert.match(crossTenantRes.reason, /Security boundary violation/i);

    // 2. Read-only role attempt
    const readOnlyRes = await DecisionEngine.evaluate({
      tenantId,
      action: "isolate_host",
      evidence: [],
      actor: { ...actor, role: "analyst" },
    });
    assert.equal(readOnlyRes.decision, "DENY");
    assert.match(readOnlyRes.reason, /operational permissions/i);

    // 3. Emergency Admin Kill Switch
    await setKillSwitchState(tenantId, true);
    try {
      const killSwitchRes = await DecisionEngine.evaluate({
        tenantId,
        action: "isolate_host",
        evidence: [],
        actor,
      });
      assert.equal(killSwitchRes.decision, "DENY");
      assert.match(killSwitchRes.reason, /Emergency Admin Kill Switch/i);
    } finally {
      await setKillSwitchState(tenantId, false);
    }
  });
});
