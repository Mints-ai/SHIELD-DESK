import "./setup";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { PolicyEngine } from "../src/lib/policy-engine";
import { DecisionEngine } from "../src/lib/decision-engine";
import { setKillSwitchState } from "../src/lib/fleet/fleet";

describe("Phase 2 & 5: Decision Engine & Policy Engine Isolation Suite", () => {
  // ---------------------------------------------------------------------------
  // Policy Engine Tests
  // ---------------------------------------------------------------------------
  describe("PolicyEngine Evaluation", () => {
    it("Mode Evaluation: Enforces Observe, Assist, and Autopilot behaviors", () => {
      // 1. Observe mode: Active host isolation is DENIED
      const observeRes = PolicyEngine.evaluatePolicy({
        tenantId: "tenant-acme",
        action: "isolate_host",
        autonomyMode: "observe",
      });
      assert.equal(observeRes.decision, "DENY");
      assert.equal(observeRes.requiredApprovals, 0);

      // 2. Assist mode: Host isolation REQUIRES 1 APPROVAL
      const assistRes = PolicyEngine.evaluatePolicy({
        tenantId: "tenant-acme",
        action: "isolate_host",
        autonomyMode: "assist",
      });
      assert.equal(assistRes.decision, "REQUIRE_APPROVAL");
      assert.equal(assistRes.requiredApprovals, 1);

      // 3. Autopilot mode: Standard host isolation is ALLOWED
      const autoRes = PolicyEngine.evaluatePolicy({
        tenantId: "tenant-acme",
        action: "isolate_host",
        autonomyMode: "autopilot",
      });
      assert.equal(autoRes.decision, "ALLOW");
      assert.equal(autoRes.requiredApprovals, 0);
    });

    it("Policy Exceptions: Critical asset types strictly override autopilot to require dual approval", () => {
      // Even in autopilot mode, isolating a production database must require dual approval
      const res = PolicyEngine.evaluatePolicy({
        tenantId: "tenant-acme",
        action: "isolate_host",
        assetType: "production_database",
        autonomyMode: "autopilot",
      });

      assert.equal(res.decision, "REQUIRE_DUAL_APPROVAL");
      assert.equal(res.requiredApprovals, 2);
      assert.equal(res.isExceptionApplied, true);
      assert.match(res.reason, /production_database/i);
    });

    it("Blast Radius Escalation: High blast radius escalates required approval count", () => {
      // Isolate host has maxBlastRadiusScore: 60. A blast radius score of 85 triggers escalation
      const res = PolicyEngine.evaluatePolicy({
        tenantId: "tenant-acme",
        action: "isolate_host",
        autonomyMode: "assist",
        blastRadiusScore: 85,
      });

      assert.equal(res.decision, "REQUIRE_DUAL_APPROVAL");
      assert.equal(res.requiredApprovals, 2);
      assert.match(res.reason, /blast radius score/i);
    });
  });

  // ---------------------------------------------------------------------------
  // Decision Engine Tests
  // ---------------------------------------------------------------------------
  describe("DecisionEngine Governance Gateway", () => {
    const validEvidence = [
      {
        type: "cve_finding",
        source: "trivy_scanner",
        timestamp: new Date().toISOString(),
        data: { cveId: "CVE-2024-9999", cvss: 9.8 },
      },
    ];

    it("DecisionEngine: Evaluates standard Tier 2 containment and attaches cryptographic hash", async () => {
      const output = await DecisionEngine.evaluate({
        tenantId: "tenant-acme",
        incidentId: "INC-2001",
        assetId: "ast-ws-001",
        action: "isolate_host",
        evidence: validEvidence,
        risk: { severity: "high", score: 8.5 },
        blastRadius: { score: 25, exceeded: false },
        actor: {
          id: "usr-soc-analyst",
          tenantId: "tenant-acme",
          role: "analyst",
        },
      });

      assert.equal(output.decision, "REQUIRE_APPROVAL");
      assert.equal(output.requiredApprovals, 1);
      assert.equal(output.tenantId, "tenant-acme");
      assert.equal(output.action, "isolate_host");
      assert.equal(output.evidence.length, 1);
      assert.ok(output.decisionHash && output.decisionHash.length === 64, "Must generate SHA-256 hash");
    });

    it("Tenant Isolation: Blocks cross-tenant action proposition (Anti-IDOR)", async () => {
      const output = await DecisionEngine.evaluate({
        tenantId: "tenant-acme",
        action: "isolate_host",
        evidence: validEvidence,
        actor: {
          id: "usr-hostile-actor",
          tenantId: "tenant-globex", // Mismatched tenant
          role: "analyst",
        },
      });

      assert.equal(output.decision, "DENY");
      assert.equal(output.requiredApprovals, 0);
      assert.match(output.reason, /Security boundary violation/i);
    });

    it("Role Permissions: Rejects remediation propositions by read-only roles", async () => {
      const output = await DecisionEngine.evaluate({
        tenantId: "tenant-acme",
        action: "isolate_host",
        evidence: validEvidence,
        actor: {
          id: "usr-auditor-01",
          tenantId: "tenant-acme",
          role: "viewer", // Read-only
        },
      });

      assert.equal(output.decision, "DENY");
      assert.match(output.reason, /does not hold operational permissions/i);
    });

    it("Emergency Kill Switch: Strictly returns DENY when tenant kill switch is engaged", async () => {
      // Engage kill switch
      await setKillSwitchState("tenant-acme", true);

      try {
        const output = await DecisionEngine.evaluate({
          tenantId: "tenant-acme",
          action: "terminate_process",
          evidence: validEvidence,
          actor: {
            id: "usr-soc-admin",
            tenantId: "tenant-acme",
            role: "system_admin",
          },
        });

        assert.equal(output.decision, "DENY");
        assert.match(output.reason, /Emergency Admin Kill Switch engaged/i);
      } finally {
        // Disengage kill switch
        await setKillSwitchState("tenant-acme", false);
      }
    });

    it("Prove Before You Act: Zero evidence on high-impact action escalates to human approval", async () => {
      const output = await DecisionEngine.evaluate({
        tenantId: "tenant-acme",
        action: "terminate_process",
        autonomyMode: "autopilot", // Autopilot would normally allow
        evidence: [], // Zero evidence!
        actor: {
          id: "usr-soc-admin",
          tenantId: "tenant-acme",
          role: "system_admin",
        },
      });

      assert.equal(output.decision, "REQUIRE_APPROVAL");
      assert.equal(output.requiredApprovals, 1);
      assert.match(output.reason, /Prove-Before-You-Act policy mandates human review/i);
    });
  });
});
