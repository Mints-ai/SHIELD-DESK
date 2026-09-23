import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import {
  getComplianceSummary,
  exportAuditEvidencePackage,
  ISO_27001_CONTROLS,
} from "../src/lib/compliance/iso27001";
import { getExecutiveRiskScorecard } from "../src/lib/reporting/scorecard";
import type { SessionUser } from "../src/lib/auth/session";

test("ShieldDesk Layer 4 & Phase 7: Compliance, ISO 27001 & Executive Scorecard Suite", async (t) => {
  const acmeAnalyst: SessionUser = {
    id: "dev-analyst",
    tenant_id: "acme-tenant",
    role: "user",
  };

  await t.test("ISO 27001 Control Mapping: covers essential incident and technological controls", () => {
    assert.ok(ISO_27001_CONTROLS.length >= 8, "Should cover at least 8 ISO 27001 controls");
    const incidentControl = ISO_27001_CONTROLS.find((c) => c.code === "A.5.24");
    assert.ok(incidentControl, "Must contain A.5.24 Incident management planning");
    assert.equal(incidentControl?.horizon, "immediate");

    const accessControl = ISO_27001_CONTROLS.find((c) => c.code === "A.9.2");
    assert.ok(accessControl, "Must contain A.9.2 Separation of duties");
    assert.equal(accessControl?.compliancePct, 100);
  });

  await t.test("Compliance Summary: computes high audit readiness score", async () => {
    const summary = await getComplianceSummary(acmeAnalyst);
    assert.ok(summary.overallScore >= 90, "Overall score must be >= 90 for enterprise audit readiness");
    assert.equal(summary.soc2Readiness, "AUDIT_READY");
    assert.ok(summary.fullyAutomated >= 6, "Must have at least 6 fully automated controls");
    assert.ok(summary.auditEvidenceCount > 0, "Must track audit evidence records");
  });

  await t.test("Audit Evidence Package: exports complete verifiable attestation with hash chain", async () => {
    const pkg = await exportAuditEvidencePackage(acmeAnalyst);
    assert.ok(pkg.reportId.startsWith("AUDIT-ISO27001-ACME-TENANT-"), "Report ID must be tenant-scoped");
    assert.equal(pkg.tenant, "acme-tenant");
    assert.ok(pkg.evidenceRecords.governanceTokens.length >= 0);
    assert.ok(pkg.evidenceRecords.endpointAgents.length >= 4);
    assert.ok(pkg.evidenceRecords.hashChainHead, "Must include cryptographic hash chain head");
  });

  await t.test("Phase 7 Executive Risk Scorecard: calculates MTTD/MTTR reductions and Posture Grade", async () => {
    const scorecard = await getExecutiveRiskScorecard(acmeAnalyst);
    assert.equal(scorecard.tenantId, "acme-tenant");
    assert.ok(scorecard.postureScore >= 80, "Posture score must be high");
    assert.equal(scorecard.postureGrade, "A");
    assert.ok(scorecard.mttdMinutes.reductionPct > 90, "MTTD reduction should exceed 90%");
    assert.ok(scorecard.mttrMinutes.reductionPct > 90, "MTTR reduction should exceed 90%");
    assert.ok(scorecard.threatDistribution.length >= 3, "Must display threat distribution categories");
  });
});
