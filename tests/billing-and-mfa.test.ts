import "./setup";
import test, { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { GET as billingGET, POST as billingPOST } from "@/app/api/billing/route";
import { createSessionToken } from "@/lib/auth/token";
import { getTenantSubscription, canEnrollEndpoint, updateTenantSubscription, BILLING_PLANS } from "@/lib/billing/plans";
import { verifyTotpCode } from "@/lib/auth/totp";
import { approveActionToken, requestApprovalToken } from "@/lib/governance/approvalTokens";

describe("ShieldDesk Mandatory MFA & SaaS Billing Enforcement Suite", () => {
  after(async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    if ((global as any).__shieldDeskPgPool) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (global as any).__shieldDeskPgPool.end().catch(() => {});
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global as any).__shieldDeskPgPool = undefined;
    }
  });

  const adminUser = {
    uid: "usr-admin-1",
    id: "usr-admin-1",
    tenantId: "acme-tenant",
    tenant_id: "acme-tenant",
    role: "system_admin" as const,
  };

  const adminToken = createSessionToken({
    uid: "usr-admin-1",
    tenantId: "acme-tenant",
    role: "system_admin",
  });

  const viewerToken = createSessionToken({
    uid: "usr-viewer-1",
    tenantId: "acme-tenant",
    role: "analyst",
  });

  it("Item 1: TOTP verification strictly validates code format and rejects invalid tokens", async () => {
    // Test 1: Invalid length
    const invalidLen = await verifyTotpCode("usr-admin-1", "123", "JBSWY3DPEHPK3PXP");
    assert.equal(invalidLen.valid, false);

    // Test 2: Invalid 6-digit code
    const invalidCode = await verifyTotpCode("usr-admin-1", "000000", "JBSWY3DPEHPK3PXP");
    assert.equal(invalidCode.valid, false);
  });

  it("Item 1: Action approval enforces mandatory MFA in production for privileged approvers", async () => {
    // 1. Request token in test mode
    const reqRes = await requestApprovalToken(
      { uid: "usr-requester-1", tenantId: "acme-tenant", role: "analyst" },
      { taskId: "task-prod-containment", actionType: "isolate_host" }
    );
    assert.ok(reqRes.token);

    const origAppEnv = process.env.APP_ENV;
    try {
      // 2. Under production policy, privileged approvers must have MFA enrolled
      process.env.APP_ENV = "production";

      const approveRes = await approveActionToken(adminUser, {
        tokenId: reqRes.token.id,
      });

      assert.equal(approveRes.error, "mfa_required");
      assert.match(approveRes.message || "", /MFA enrollment is mandatory/i);
    } finally {
      process.env.APP_ENV = origAppEnv;
    }
  });

  it("Item 5: Billing API returns tenant subscription, quotas, and plan tiers", async () => {
    const req = new NextRequest("http://localhost:3000/api/billing", {
      headers: { authorization: `Bearer ${adminToken}` },
    });

    const res = await billingGET(req);
    assert.equal(res.status, 200);

    const data = await res.json();
    assert.equal(data.success, true);
    assert.equal(data.tenantId, "acme-tenant");
    assert.ok(data.subscription);
    assert.ok(data.quota);
    assert.ok(Array.isArray(data.plans));
    assert.equal(data.plans.length, 3);
  });

  it("Item 5: Endpoint enrollment quota accurately restricts Community vs Pro tier", async () => {
    // Community: Max 5
    const commQuotaAllowed = await canEnrollEndpoint("globex-tenant", 4);
    assert.equal(commQuotaAllowed.allowed, true);

    const commQuotaExceeded = await canEnrollEndpoint("globex-tenant", 5);
    assert.equal(commQuotaExceeded.allowed, false);
    assert.equal(commQuotaExceeded.upgradeRequired, true);

    // Professional: Max 100
    const proQuota = await canEnrollEndpoint("acme-tenant", 50);
    assert.equal(proQuota.allowed, true);
    assert.equal(proQuota.maxEndpoints, 100);
  });

  it("Item 5: Non-admin users are strictly blocked from upgrading subscriptions", async () => {
    const req = new NextRequest("http://localhost:3000/api/billing", {
      method: "POST",
      headers: {
        authorization: `Bearer ${viewerToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        action: "create_checkout_order",
        targetTier: "enterprise",
      }),
    });

    const res = await billingPOST(req);
    assert.equal(res.status, 403, "Non-admins must be forbidden from billing operations");
  });

  it("Item 5: Admin can generate checkout order and confirm upgrade", async () => {
    // 1. Create checkout order
    const orderReq = new NextRequest("http://localhost:3000/api/billing", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        action: "create_checkout_order",
        targetTier: "enterprise",
        provider: "razorpay",
      }),
    });

    const orderRes = await billingPOST(orderReq);
    assert.equal(orderRes.status, 200);
    const orderData = await orderRes.json();
    assert.equal(orderData.success, true);
    assert.equal(orderData.provider, "razorpay");
    assert.equal(orderData.currency, "INR");
    assert.ok(orderData.orderId);

    // 2. Confirm upgrade
    const confirmReq = new NextRequest("http://localhost:3000/api/billing", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        action: "confirm_upgrade",
        targetTier: "enterprise",
        provider: "razorpay",
        paymentId: "pay_test_123456",
        orderId: orderData.orderId,
      }),
    });

    const confirmRes = await billingPOST(confirmReq);
    assert.equal(confirmRes.status, 200);
    const confirmData = await confirmRes.json();
    assert.equal(confirmData.success, true);
    assert.equal(confirmData.subscription.tier, "enterprise");
  });
});
