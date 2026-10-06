import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { StripeWebhookManager } from "../src/lib/billing/stripeWebhook";
import { getTenantSubscription } from "../src/lib/billing/plans";

test("Stripe billing lifecycle and signature enforcement", async (t) => {
  await t.test("signature verification fails closed without a configured secret", () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const body = JSON.stringify({ id: "evt-signature" });
    const check = StripeWebhookManager.verifyStripeSignature(body, `t=${timestamp},v1=00`, "");
    assert.equal(check.valid, false);
    assert.match(check.reason || "", /not configured/);
  });

  await t.test("applies upgrade, payment failure/grace, renewal/reactivation, downgrade, refund and cancellation transitions idempotently", async () => {
    const tenantId = `tenant-stripe-lifecycle-${crypto.randomUUID()}`;
    const run = async (id: string, type: string, payload: Record<string, unknown>) => {
      await StripeWebhookManager.recordAndQueueStripeEvent({ stripeEventId: id, eventType: type, tenantId, payload });
      return StripeWebhookManager.processQueuedStripeEvent(id);
    };

    assert.equal((await run(`evt-create-${tenantId}`, "customer.subscription.created", { id: "sub-life", status: "active", metadata: { tier: "professional" } })).success, true);
    assert.equal((await getTenantSubscription(tenantId)).tier, "professional");
    await run(`evt-fail-${tenantId}`, "invoice.payment_failed", {});
    assert.equal((await getTenantSubscription(tenantId)).status, "past_due");
    await run(`evt-paid-${tenantId}`, "invoice.paid", {});
    assert.equal((await getTenantSubscription(tenantId)).status, "active");
    await run(`evt-upgrade-${tenantId}`, "customer.subscription.updated", { id: "sub-life", status: "active", metadata: { tier: "enterprise" } });
    assert.equal((await getTenantSubscription(tenantId)).tier, "enterprise");
    await run(`evt-refund-${tenantId}`, "charge.refunded", { amount: 1000, amount_refunded: 1000 });
    assert.equal((await getTenantSubscription(tenantId)).status, "cancelled");
    const replay = await StripeWebhookManager.processQueuedStripeEvent(`evt-refund-${tenantId}`);
    assert.equal(replay.actionTaken, "already_processed");
    await run(`evt-cancel-${tenantId}`, "customer.subscription.deleted", { id: "sub-life" });
    assert.equal((await getTenantSubscription(tenantId)).tier, "community");
    assert.equal((await getTenantSubscription(tenantId)).status, "cancelled");
  });

  await t.test("rejects queued events without a tenant binding instead of assigning a default tenant", async () => {
    const id = `evt-no-tenant-${crypto.randomUUID()}`;
    await StripeWebhookManager.recordAndQueueStripeEvent({ stripeEventId: id, eventType: "invoice.paid", payload: {} });
    const result = await StripeWebhookManager.processQueuedStripeEvent(id);
    assert.equal(result.success, false);
    assert.match(result.error || "", /tenant binding/);
  });
});
