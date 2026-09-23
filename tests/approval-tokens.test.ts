import "./setup";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  requestApprovalToken,
  approveActionToken,
  rejectActionToken,
  listApprovalTokens,
} from "@/lib/governance/approvalTokens";
import { classifyResponseTier } from "@/lib/governance/autonomyTier";
import type { ChatSession } from "@/lib/auth/session";

describe("ShieldDesk Priority 2: Approval Tokens & Layer 4 Governance Suite", () => {
  const acmeAnalyst: ChatSession = {
    uid: "dev-analyst",
    role: "user",
    tenantId: "acme-tenant",
  };

  const acmeAdmin: ChatSession = {
    uid: "dev-admin",
    role: "system_admin",
    tenantId: "acme-tenant",
  };

  const globexAnalyst: ChatSession = {
    uid: "dev-other",
    role: "user",
    tenantId: "globex-tenant",
  };

  it("Step 4 / Phase 1: requestApprovalToken creates a pending token with 24h expiration", async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const res: any = await requestApprovalToken(acmeAnalyst, {
      taskId: "t1111111-1111-1111-1111-111111111111",
      actionType: "isolate_host",
      blastRadius: "Workstation FIN-WS-042",
    });

    assert.ok(res.token, "Token record must be returned");
    assert.strictEqual(res.token.status, "pending");
    assert.strictEqual(res.token.requested_by, "dev-analyst");
    assert.strictEqual(res.token.tier, "Tier 2");
    assert.ok(res.token.expires_at, "Must have an expiration date");
  });

  it("FR-3: Separation of Duties — requester CANNOT self-approve their own action token", async () => {
    // 1. dev-analyst creates a token
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const created: any = await requestApprovalToken(acmeAnalyst, {
      taskId: "t3333333-3333-3333-3333-333333333333",
      actionType: "deploy_patch",
    });
    assert.ok(created.token);

    // 2. dev-analyst attempts to approve their OWN token -> MUST be rejected
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const decision: any = await approveActionToken(acmeAnalyst, {
      tokenId: created.token.id,
    });

    assert.ok("error" in decision, "Must reject self-approval");
    assert.strictEqual(
      decision.error,
      "separation_of_duties_violation",
      "Must explicitly enforce separation of duties"
    );
  });

  it("FR-3: Distinct authorized approver can successfully approve action token", async () => {
    // 1. dev-analyst creates a token
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const created: any = await requestApprovalToken(acmeAnalyst, {
      taskId: "t4444444-4444-4444-4444-444444444444",
      actionType: "isolate_host",
    });
    assert.ok(created.token);

    // 2. Distinct approver (dev-admin) approves
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const decision: any = await approveActionToken(acmeAdmin, {
      tokenId: created.token.id,
    });

    assert.ok(decision.success, "Approval should succeed for distinct approver");
    assert.strictEqual(decision.token.status, "approved");
    assert.strictEqual(decision.token.approved_by, "dev-admin");
  });

  it("Anti-Replay Protection: Cannot re-approve an already approved token", async () => {
    // 1. Create and approve token
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const created: any = await requestApprovalToken(acmeAnalyst, {
      taskId: "t1111111-1111-1111-1111-111111111111",
      actionType: "isolate_host",
    });
    await approveActionToken(acmeAdmin, { tokenId: created.token.id });

    // 2. Attempt to replay approval -> MUST fail
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const secondApproval: any = await approveActionToken(acmeAdmin, {
      tokenId: created.token.id,
    });

    assert.ok("error" in secondApproval, "Replaying approval must be prevented");
    assert.strictEqual(secondApproval.error, "token_already_processed");
  });

  it("FR-2: Tenant Isolation — user from Globex cannot view or approve Acme's token (Anti-enumeration 404)", async () => {
    // globexAnalyst attempts to approve Acme's seeded token
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const res: any = await approveActionToken(globexAnalyst, {
      tokenId: "tok11111-1111-1111-1111-111111111111",
    });

    assert.ok("error" in res, "Must reject cross-tenant approval");
    assert.strictEqual(
      res.error,
      "not_found",
      "Must return anti-enumeration 404 ('not_found'), never 403"
    );
  });

  it("Rejection Workflow: Distinct analyst can reject a token with rationale", async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const created: any = await requestApprovalToken(acmeAnalyst, {
      taskId: "t1111111-1111-1111-1111-111111111111",
      actionType: "remediate_task",
    });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rejection: any = await rejectActionToken(acmeAdmin, {
      tokenId: created.token.id,
      reason: "Asset is critical production host with scheduled maintenance",
    });

    assert.ok(rejection.success, "Rejection should succeed");
    assert.strictEqual(rejection.token.status, "rejected");
    assert.strictEqual(
      rejection.token.rejection_reason,
      "Asset is critical production host with scheduled maintenance"
    );
  });

  it("Autonomy Tier Policy: classifyResponseTier accurately classifies actions into Tiers 0-3", () => {
    // Tier 0
    const t0 = classifyResponseTier("gather_telemetry");
    assert.strictEqual(t0.tier, "Tier 0");
    assert.strictEqual(t0.requiredApprovers, 0);

    // Tier 1
    const t1 = classifyResponseTier("revoke_user_sessions");
    assert.strictEqual(t1.tier, "Tier 1");
    assert.strictEqual(t1.requiredApprovers, 0);
    assert.strictEqual(t1.reversible, true);

    // Tier 2
    const t2 = classifyResponseTier("isolate_workstation_host");
    assert.strictEqual(t2.tier, "Tier 2");
    assert.strictEqual(t2.requiredApprovers, 1);
    assert.strictEqual(t2.requiresSeparationOfDuties, true);

    // Tier 3
    const t3 = classifyResponseTier("emergency_reboot_database");
    assert.strictEqual(t3.tier, "Tier 3");
    assert.strictEqual(t3.requiredApprovers, 2);
    assert.strictEqual(t3.reversible, false);
  });
});
