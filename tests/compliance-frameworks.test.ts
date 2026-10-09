import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import {
  FRAMEWORKS,
  getFrameworkMetadata,
  getFrameworkComplianceSummary,
} from "../src/lib/compliance/frameworks";
import { runComplianceAuditScan } from "../src/lib/compliance/scanner";
import type { SessionUser } from "../src/lib/auth/session";

test("SD-028 Compliance Platform: Frameworks & Telemetry Test Suite", async (t) => {
  const testUser: SessionUser = {
    id: "auditor-01",
    tenant_id: "acme-tenant",
    role: "system_admin",
  };

  await t.test("Framework Coverage: provides 4 regulatory compliance frameworks", () => {
    assert.equal(FRAMEWORKS.length, 4, "Must define 4 enterprise compliance frameworks");
    const iso = getFrameworkMetadata("iso-27001");
    const soc2 = getFrameworkMetadata("soc-2");
    const nist = getFrameworkMetadata("nist-csf");
    const hipaa = getFrameworkMetadata("hipaa");

    assert.ok(iso, "ISO 27001 must exist");
    assert.ok(soc2, "SOC 2 Type II must exist");
    assert.ok(nist, "NIST CSF 2.0 must exist");
    assert.ok(hipaa, "HIPAA Security Rule must exist");

    assert.equal(iso?.id, "iso27001");
    assert.equal(soc2?.id, "soc2");
    assert.equal(nist?.id, "nist");
    assert.equal(hipaa?.id, "hipaa");
  });

  await t.test("Dynamic Score Calculation: ISO 27001 summary is computed from live telemetry", async () => {
    const summary = await getFrameworkComplianceSummary(testUser, "iso-27001");
    assert.equal(summary.tenantId, "acme-tenant");
    assert.equal(summary.frameworkId, "iso27001");
    assert.ok(summary.overallScore >= 0 && summary.overallScore <= 100);
    assert.ok(summary.controls.length >= 8, "ISO 27001 must have at least 8 controls");
    assert.ok(summary.fullyAutomated >= 4, "Must have automated controls");
    assert.ok(summary.auditEvidenceCount > 0, "Must track live evidence records");

    // Check specific control properties
    const malwareControl = summary.controls.find((c) => c.code === "A.8.7");
    assert.ok(malwareControl, "Must contain malware protection control A.8.7");
    assert.ok(malwareControl?.auditEvidenceSource.includes("yara_rule_matches"));
  });

  await t.test("Dynamic Score Calculation: SOC 2 Type II re-maps telemetry correctly", async () => {
    const summary = await getFrameworkComplianceSummary(testUser, "soc-2");
    assert.equal(summary.tenantId, "acme-tenant");
    assert.equal(summary.frameworkId, "soc2");
    assert.ok(summary.controls.length >= 6, "SOC 2 must have controls");

    const accessControl = summary.controls.find((c) => c.code === "CC6.1");
    assert.ok(accessControl, "Must contain CC6.1 Access Control");
    assert.equal(accessControl?.compliancePct, 100);
  });

  await t.test("Dynamic Score Calculation: NIST CSF 2.0 maps govern/identify/protect/detect/respond/recover", async () => {
    const summary = await getFrameworkComplianceSummary(testUser, "nist-csf");
    assert.equal(summary.tenantId, "acme-tenant");
    assert.equal(summary.frameworkId, "nist");

    const anomaliesControl = summary.controls.find((c) => c.code.includes("DE.AE"));
    assert.ok(anomaliesControl, "Must contain DE.AE Anomalies and Events");
    assert.equal(anomaliesControl?.horizon, "immediate");
  });

  await t.test("Dynamic Score Calculation: HIPAA Security Rule safeguards", async () => {
    const summary = await getFrameworkComplianceSummary(testUser, "hipaa");
    assert.equal(summary.tenantId, "acme-tenant");
    assert.equal(summary.frameworkId, "hipaa");

    const auditControl = summary.controls.find((c) => c.code.includes("164.312(b)"));
    assert.ok(auditControl, "Must contain 164.312(b) Audit Controls");
  });

  await t.test("Automated Live Compliance Scanner: executes real-time checks across 4 pillars", async () => {
    const scanReport = await runComplianceAuditScan(testUser);
    assert.equal(scanReport.tenantId, "acme-tenant");
    assert.ok(scanReport.checks.length >= 4, "Scan must perform at least 4 critical audit checks");

    const checkIds = scanReport.checks.map((c) => c.id);
    assert.ok(checkIds.includes("CHK-AGENT-TELEMETRY"), "Must include Agent Telemetry check");
    assert.ok(checkIds.includes("CHK-VULN-SLA"), "Must include Vulnerability SLA check");
    assert.ok(checkIds.includes("CHK-SOD-ENFORCEMENT"), "Must include Separation of Duties check");
    assert.ok(checkIds.includes("CHK-LEDGER-TAMPER"), "Must include Hash Chain Ledger check");

    assert.ok(typeof scanReport.passedChecks === "number");
    assert.ok(typeof scanReport.totalChecks === "number");
    assert.ok(scanReport.healthScore >= 80, "Health score must be high in healthy state");
  });
});
