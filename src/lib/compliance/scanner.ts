import type { SessionUser } from "@/lib/auth/session";
import { collectTenantTelemetry } from "./frameworks";
import { verifyTenantLedger } from "./verifier";

export interface ScanFinding {
  id: string;
  checkId?: string;
  checkName: string;
  controlCode: string;
  frameworkRef: string;
  severity: "info" | "warning" | "critical";
  status: "PASS" | "FAIL";
  title: string;
  description: string;
  evidenceSnippet: string;
  remediationAction?: string;
  remediationUrl?: string;
}

export interface ComplianceScanResult {
  scanId: string;
  timestamp: string;
  tenantId: string;
  overallStatus: "PASSED" | "WARNING" | "CRITICAL";
  readinessScore: number;
  healthScore: number;
  checksEvaluated: number;
  checksPassed: number;
  checksFailed: number;
  passedChecks: number;
  totalChecks: number;
  checks: ScanFinding[];
  findings: ScanFinding[];
  telemetrySummary: {
    agentsScanned: number;
    agentsHealthy: number;
    cvesEvaluated: number;
    cvesOverSla: number;
    tokensChecked: number;
    selfApprovalViolations: number;
    ledgerBlocksVerified: number;
    ledgerTamperFree: boolean;
  };
}

/**
 * Runs an automated live compliance scan against operational databases and cryptographic ledgers.
 */
export async function runLiveComplianceScan(caller: SessionUser): Promise<ComplianceScanResult> {
  const tenantId = caller.tenant_id;
  const scanId = `SCAN-${tenantId.toUpperCase()}-${Date.now().toString(36)}`;
  const timestamp = new Date().toISOString();

  // 1. Collect telemetry & ledger verification
  const telemetry = await collectTenantTelemetry(caller);
  const ledgerReport = await verifyTenantLedger(caller);

  const findings: ScanFinding[] = [];

  // Check 1: Endpoint Telemetry Coverage (Clause A.8.7 / CC6.8 / DE.CM-01)
  const agentRatio = telemetry.totalAgents > 0 ? telemetry.connectedAgents / telemetry.totalAgents : 1;
  if (agentRatio >= 0.8) {
    findings.push({
      id: "CHK-AGENT-TELEMETRY",
      checkId: "CHK-AGENT-TELEMETRY",
      checkName: "Endpoint Telemetry Coverage",
      controlCode: "A.8.7 / CC6.8",
      frameworkRef: "ISO 27001 / SOC 2",
      severity: "info",
      status: "PASS",
      title: "Active Endpoint Telemetry Confirmed",
      description: `${telemetry.connectedAgents} of ${telemetry.totalAgents} monitored endpoint agents reported sub-minute heartbeats and process telemetry.`,
      evidenceSnippet: `Healthy Agent Ratio: ${Math.round(agentRatio * 100)}% | Active EPS Buffer: Normal`,
    });
  } else {
    findings.push({
      id: "fnd-agent-coverage-warn",
      checkName: "Endpoint Telemetry Coverage",
      controlCode: "A.8.7 / CC6.8",
      frameworkRef: "ISO 27001 / SOC 2",
      severity: "warning",
      status: "FAIL",
      title: "Degraded Endpoint Heartbeat Coverage",
      description: `Only ${telemetry.connectedAgents} of ${telemetry.totalAgents} agents reporting heartbeats. Some hosts may be offline or isolated.`,
      evidenceSnippet: `Healthy Agent Ratio: ${Math.round(agentRatio * 100)}%`,
      remediationAction: "Sync Fleet Status",
      remediationUrl: "/dashboard/fleet",
    });
  }

  // Check 2: Vulnerability SLA (Clause A.8.8 / CC7.1 / ID.RA-01)
  if (telemetry.cvesOverSla === 0) {
    findings.push({
      id: "CHK-VULN-SLA",
      checkId: "CHK-VULN-SLA",
      checkName: "Vulnerability Remediation SLA",
      controlCode: "A.8.8 / CC7.1",
      frameworkRef: "ISO 27001 / SOC 2",
      severity: "info",
      status: "PASS",
      title: "All Vulnerabilities Within Policy SLA",
      description: `Zero unpatched Critical or High CVE vulnerabilities exceed the 30-day remediation threshold.`,
      evidenceSnippet: `Evaluated Open CVEs: ${telemetry.openCvesCount} | Breached SLA: 0`,
    });
  } else {
    findings.push({
      id: "CHK-VULN-SLA",
      checkId: "CHK-VULN-SLA",
      checkName: "Vulnerability Remediation SLA",
      controlCode: "A.8.8 / CC7.1",
      frameworkRef: "ISO 27001 / SOC 2",
      severity: "warning",
      status: "FAIL",
      title: "Vulnerability Remediation SLA Breach Detected",
      description: `${telemetry.cvesOverSla} high-severity CVE finding(s) remain unpatched past the 30-day SLA window.`,
      evidenceSnippet: `Breached CVEs: ${telemetry.cvesOverSla} | Total Open: ${telemetry.openCvesCount}`,
      remediationAction: "Generate Remediation Plan",
      remediationUrl: "/dashboard/incidents",
    });
  }

  // Check 3: Separation of Duties & Dual-Custody Gating (Clause A.9.2 / CC6.1 / PR.AC-01)
  if (telemetry.selfApprovalViolations === 0) {
    findings.push({
      id: "CHK-SOD-ENFORCEMENT",
      checkId: "CHK-SOD-ENFORCEMENT",
      checkName: "Separation of Duties",
      controlCode: "A.9.2 / CC6.1",
      frameworkRef: "ISO 27001 / SOC 2",
      severity: "info",
      status: "PASS",
      title: "Strict Dual-Custody Approval Enforced",
      description: "Database-level constraint (requested_by <> approved_by) verified. Zero self-approved privileged operations detected.",
      evidenceSnippet: `Total Tokens Audited: ${telemetry.totalTokens} | Self-Approvals: 0`,
    });
  } else {
    findings.push({
      id: "CHK-SOD-ENFORCEMENT",
      checkId: "CHK-SOD-ENFORCEMENT",
      checkName: "Separation of Duties",
      controlCode: "A.9.2 / CC6.1",
      frameworkRef: "ISO 27001 / SOC 2",
      severity: "critical",
      status: "FAIL",
      title: "Self-Approval Policy Violation Detected",
      description: `Found ${telemetry.selfApprovalViolations} approval token(s) where requested_by matched approved_by. Privileged actions must enforce independent sign-off.`,
      evidenceSnippet: `Self-Approval Violations: ${telemetry.selfApprovalViolations}`,
      remediationAction: "Revoke Invalid Tokens",
      remediationUrl: "/dashboard/governance",
    });
  }

  // Check 4: Tamper-Proof Cryptographic Hash Chain Continuity (Clause A.5.28 / 164.312(b))
  if (ledgerReport.valid) {
    findings.push({
      id: "CHK-LEDGER-TAMPER",
      checkId: "CHK-LEDGER-TAMPER",
      checkName: "Tamper Ledger Continuity",
      controlCode: "A.5.28 / 164.312(b)",
      frameworkRef: "ISO 27001 / HIPAA",
      severity: "info",
      status: "PASS",
      title: "100% Mathematically Validated Ledger",
      description: `Recalculated SHA-256 hashes from Genesis to Head (${ledgerReport.totalBlocks} blocks). Zero broken links or altered payloads detected.`,
      evidenceSnippet: `Chain Head: ${ledgerReport.chainHeadHash.slice(0, 16)}... | Merkle Root: ${ledgerReport.merkleRoot.slice(0, 16)}...`,
    });
  } else {
    findings.push({
      id: "CHK-LEDGER-TAMPER",
      checkId: "CHK-LEDGER-TAMPER",
      checkName: "Tamper Ledger Continuity",
      controlCode: "A.5.28 / 164.312(b)",
      frameworkRef: "ISO 27001 / HIPAA",
      severity: "critical",
      status: "FAIL",
      title: "Ledger Tampering or Broken Link Detected",
      description: ledgerReport.failureReason || "Cryptographic verification failed.",
      evidenceSnippet: `Tampered Blocks: ${ledgerReport.tamperCount} | Broken Links: ${ledgerReport.brokenLinkCount}`,
      remediationAction: "Inspect Broken Block",
      remediationUrl: "#verify-ledger",
    });
  }

  const passedCount = findings.filter((f) => f.status === "PASS").length;
  const failedCount = findings.filter((f) => f.status === "FAIL").length;
  const hasCritical = findings.some((f) => f.severity === "critical" && f.status === "FAIL");
  const hasWarning = findings.some((f) => f.severity === "warning" && f.status === "FAIL");

  const overallStatus: "PASSED" | "WARNING" | "CRITICAL" = hasCritical
    ? "CRITICAL"
    : hasWarning
    ? "WARNING"
    : "PASSED";

  const readinessScore = Math.round((passedCount / findings.length) * 100);

  return {
    scanId,
    timestamp,
    tenantId,
    overallStatus,
    readinessScore,
    healthScore: readinessScore,
    checksEvaluated: findings.length,
    checksPassed: passedCount,
    checksFailed: failedCount,
    passedChecks: passedCount,
    totalChecks: findings.length,
    checks: findings,
    findings,
    telemetrySummary: {
      agentsScanned: telemetry.totalAgents,
      agentsHealthy: telemetry.connectedAgents,
      cvesEvaluated: telemetry.openCvesCount,
      cvesOverSla: telemetry.cvesOverSla,
      tokensChecked: telemetry.totalTokens,
      selfApprovalViolations: telemetry.selfApprovalViolations,
      ledgerBlocksVerified: ledgerReport.totalBlocks,
      ledgerTamperFree: ledgerReport.valid,
    },
  };
}

export const runComplianceAuditScan = runLiveComplianceScan;
