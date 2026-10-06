import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { ClosedLoopOrchestrator } from "../src/lib/orchestration";
import { requestApprovalToken, approveActionToken } from "../src/lib/governance/approvalTokens";
import type { SessionUser } from "../src/lib/auth/session";

test("ShieldDesk Phase 9: Closed-Loop AI SOC & Autonomous Remediation Pipeline", async (t) => {
  const analystUser: SessionUser = {
    id: "usr-secops-analyst",
    tenant_id: "acme-tenant",
    role: "analyst",
  };

  const approverUser: SessionUser = {
    id: "usr-soc-lead",
    tenant_id: "acme-tenant",
    role: "super_admin",
  };

  await t.test("Tier 1 Autonomous Remediation: End-to-end auto-containment and state verification", async () => {
    const result = await ClosedLoopOrchestrator.execute({
      tenantId: "acme-tenant",
      incidentId: "inc-tier1-c2-block",
      agentId: "FIN-WS-042",
      action: "block_ip 198.51.100.99",
      caller: analystUser,
    });

    assert.equal(result.finalStatus, "SUCCESS_VERIFIED");
    assert.equal(result.tier, "Tier 1");
    assert.equal(result.decision, "ALLOW");
    assert.equal(result.verificationOutcome, "VERIFIED");
    assert.equal(result.rollbackExecuted, false);
    assert.ok(result.auditHash, "Must record immutable audit hash");
    assert.ok(result.commandId, "Must have valid command ID");
    assert.ok(result.snapshotId, "Must capture pre-flight safety snapshot");

    // Check timeline steps
    const stepNames = result.timeline.map((s) => s.step);
    assert.ok(stepNames.includes("POLICY_EVALUATION"));
    assert.ok(stepNames.includes("DECISION_GATE"));
    assert.ok(stepNames.includes("APPROVAL_GATE"));
    assert.ok(stepNames.includes("SAFETY_SNAPSHOT"));
    assert.ok(stepNames.includes("AGENT_EXECUTION"));
    assert.ok(stepNames.includes("STATE_VERIFICATION"));
    assert.ok(stepNames.includes("AUDIT_RECORDING"));

    // Approval gate should be skipped for Tier 1
    const approvalStep = result.timeline.find((s) => s.step === "APPROVAL_GATE");
    assert.equal(approvalStep?.status, "skipped");
  });

  await t.test("Tier 2 Human Governance: Blocks unapproved action and proceeds with approved token", async () => {
    // 1. Attempt Tier 2 action without approval token -> must block at APPROVAL_GATE
    const blockedResult = await ClosedLoopOrchestrator.execute({
      tenantId: "acme-tenant",
      incidentId: "inc-tier2-ransomware",
      agentId: "FIN-WS-042",
      action: "isolate_host",
      caller: analystUser,
    });

    assert.equal(blockedResult.finalStatus, "APPROVAL_REQUIRED");
    assert.equal(blockedResult.decision, "REQUIRE_APPROVAL");
    assert.equal(blockedResult.commandId, undefined, "Unapproved command must NEVER be dispatched");

    const approvalStep = blockedResult.timeline.find((s) => s.step === "APPROVAL_GATE");
    assert.equal(approvalStep?.status, "blocked");

    // 2. Request and approve a governance token
    const tokenRes = await requestApprovalToken(
      { uid: analystUser.id, tenantId: analystUser.tenant_id, role: analystUser.role },
      {
        taskId: "t-isolate-host-approved",
        actionType: "isolate_host",
        blastRadius: "Workstation FIN-WS-042",
        targetEndpointIds: ["FIN-WS-042", "ea111111-1111-1111-1111-111111111111"],
      }
    );
    assert.ok(tokenRes.token);
    const tokenId = tokenRes.token.id;

    const approveRes = await approveActionToken(
      { uid: approverUser.id, tenantId: approverUser.tenant_id, role: approverUser.role },
      { tokenId }
    );
    assert.equal(approveRes.success, true);

    // 3. Re-run pipeline with approved token -> should succeed and verify
    const approvedResult = await ClosedLoopOrchestrator.execute({
      tenantId: "acme-tenant",
      incidentId: "inc-tier2-ransomware",
      agentId: "FIN-WS-042",
      action: "isolate_host",
      caller: analystUser,
      tokenId,
    });

    assert.equal(approvedResult.finalStatus, "SUCCESS_VERIFIED");
    assert.equal(approvedResult.verificationOutcome, "VERIFIED");
    assert.ok(approvedResult.commandId);
  });

  await t.test("Verification Failure Triggers Automatic Rollback (Rule 3 Invariant)", async () => {
    // Simulate remediation execution where host state verification fails
    const failResult = await ClosedLoopOrchestrator.execute({
      tenantId: "acme-tenant",
      incidentId: "inc-flaky-remediation",
      agentId: "FIN-WS-042",
      action: "block_ip 10.99.99.1",
      caller: analystUser,
      parameters: {
        // Inject failure: Firewall rule was not actually active
        evidenceOverride: {
          firewallDropActive: false,
          blockedIps: [],
        },
      },
    });

    assert.equal(failResult.finalStatus, "ROLLED_BACK");
    assert.equal(failResult.verificationOutcome, "FAILED");
    assert.equal(failResult.rollbackExecuted, true, "Rollback must be automatically triggered upon verification failure");

    const rollbackStep = failResult.timeline.find((s) => s.step === "AUTOMATIC_ROLLBACK");
    assert.equal(rollbackStep?.status, "success");
    assert.match(failResult.error || "", /Verification failed/);
  });
});
