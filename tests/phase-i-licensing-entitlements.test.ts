/**
 * Phase I: SaaS Licensing, Entitlements, Offline Cache & Stripe Webhook Test Suite
 *
 * Verifies:
 * 1. Commercial License states, activation & tenant binding
 * 2. Signed offline entitlement cache generation & verification with grace period
 * 3. Non-Negotiable Rule 4: Server-side EntitlementService.require(...) gate
 * 4. Fail-closed behavior on expired/suspended licenses and exceeded quotas
 * 5. Cryptographic timestamped Stripe webhook signature verification
 * 6. Deduplication and transactional idempotency by stripe_event_id
 * 7. Background queue worker subscription lifecycle synchronization
 */

import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  EntitlementService,
  EntitlementViolationError,
} from "../src/lib/billing/entitlements";
import { issueCommercialLicense } from "../src/lib/billing/licenses";
import { StripeWebhookManager } from "../src/lib/billing/stripeWebhook";
import { getTenantSubscription } from "../src/lib/billing/plans";

test("Phase I: SaaS Licensing, Entitlements & Stripe Pipeline Suite", async (t) => {
  const tenantId = "tenant-enterprise-sec";
  const signingSecret = "test_signing_secret_key_12345";
  process.env.SHIELDDESK_LICENSE_SECRET = signingSecret;

  await t.test("License Lifecycle: Activation, tenant binding & expiration state transitions", async () => {
    // 1. Issue commercial enterprise license
    const issued = issueCommercialLicense(
      {
        tenantId,
        tier: "enterprise",
        maxEndpoints: 500,
        maxUsers: 50,
        features: ["telemetryIngest", "automatedRemediationTier1", "dualApprovalTier3"],
        expiresAt: new Date(Date.now() + 86400000 * 365).toISOString(),
      },
      signingSecret
    );

    assert.ok(issued.rawLicense.length > 50);

    // 2. Activate for correct tenant
    const activated = await EntitlementService.activateLicense({
      tenantId,
      licenseKey: issued.rawLicense,
    });

    assert.equal(activated.tier, "enterprise");
    assert.equal(activated.maxEndpoints, 500);
    assert.equal(activated.status, "active");

    // 3. Reject cross-tenant activation attempt
    await assert.rejects(
      async () => {
        await EntitlementService.activateLicense({
          tenantId: "foreign-tenant-xyz",
          licenseKey: issued.rawLicense,
        });
      },
      {
        message: /License tenant mismatch/,
      }
    );

    // 4. Test state computation
    const state = await EntitlementService.getLicenseState(tenantId);
    assert.equal(state.state, "active");

    // 5. Test suspended state
    await EntitlementService.setLicenseStatus(tenantId, "suspended");
    const suspendedState = await EntitlementService.getLicenseState(tenantId);
    assert.equal(suspendedState.state, "suspended");

    // Re-activate for subsequent tests
    await EntitlementService.setLicenseStatus(tenantId, "active");
  });

  await t.test("Signed Offline Entitlement Cache: Air-gapped verification & grace period", async () => {
    // 1. Generate signed cache
    const cache = await EntitlementService.generateOfflineEntitlementCache({
      tenantId,
      validityDays: 14,
      graceDays: 7,
    });

    assert.ok(cache.cacheToken.length > 50);
    assert.ok(cache.signature.length > 32);

    // 2. Verify valid cache token
    const verification = EntitlementService.verifyOfflineEntitlementCache(cache.cacheToken);
    assert.equal(verification.valid, true);
    assert.equal(verification.inGracePeriod, false);
    assert.equal(verification.payload?.tenantId, tenantId);
    assert.equal(verification.payload?.tier, "enterprise");

    // 3. Negative case: Tampered token fails cryptographic verification
    const tamperedPayload = Buffer.from(
      JSON.stringify({ ...cache.payload, maxEndpoints: 999999 })
    ).toString("base64url");
    const tamperedToken = Buffer.from(
      JSON.stringify({ payload: { ...cache.payload, maxEndpoints: 999999 }, signature: cache.signature })
    ).toString("base64url");

    const tamperedCheck = EntitlementService.verifyOfflineEntitlementCache(tamperedToken);
    assert.equal(tamperedCheck.valid, false);
    assert.ok(tamperedCheck.reason?.includes("verification failed"));
  });

  await t.test("EntitlementService.require: Enforces server-side feature gates and fail-closed security", async () => {
    // 1. Allowed feature on Enterprise tier
    const enterpriseAllowed = await EntitlementService.require({
      tenantId,
      feature: "automatedRemediationTier1",
    });
    assert.equal(enterpriseAllowed.allowed, true);
    assert.equal(enterpriseAllowed.tier, "enterprise");

    // 2. Disallowed feature on Community tier fails closed
    const communityTenant = "tenant-free-trial";
    await assert.rejects(
      async () => {
        await EntitlementService.require({
          tenantId: communityTenant,
          feature: "automatedRemediationTier1", // Community plan has automatedRemediationTier1: false
        });
      },
      (err: any) => {
        assert.ok(err instanceof EntitlementViolationError);
        assert.equal(err.status, 403);
        assert.ok(err.message.includes("is not entitled for tier"));
        return true;
      }
    );

    // 3. Endpoint quota exceeded fails closed
    await assert.rejects(
      async () => {
        await EntitlementService.require({
          tenantId,
          feature: "telemetryIngest",
          currentEndpointsCount: 500, // 500/500 allowed endpoints max
        });
      },
      (err: any) => {
        assert.ok(err instanceof EntitlementViolationError);
        assert.ok(err.message.includes("Endpoint quota exceeded"));
        return true;
      }
    );

    // 4. Suspended license fails closed
    await EntitlementService.setLicenseStatus(tenantId, "suspended");
    await assert.rejects(
      async () => {
        await EntitlementService.require({
          tenantId,
          feature: "telemetryIngest",
        });
      },
      (err: any) => {
        assert.ok(err instanceof EntitlementViolationError);
        assert.ok(err.message.includes("fail-closed"));
        return true;
      }
    );

    // Reset status
    await EntitlementService.setLicenseStatus(tenantId, "active");
  });

  await t.test("Stripe Webhook: Timestamped HMAC-SHA256 signature verification and replay defense", () => {
    const secret = "whsec_test_stripe_secret_998877";
    const now = Math.floor(Date.now() / 1000);
    const payload = JSON.stringify({ id: "evt_test_1", type: "invoice.paid" });

    // Generate valid Stripe signature header: t=<timestamp>,v1=<hash>
    const validHash = crypto
      .createHmac("sha256", secret)
      .update(`${now}.${payload}`)
      .digest("hex");
    const validHeader = `t=${now},v1=${validHash}`;

    const validCheck = StripeWebhookManager.verifyStripeSignature(payload, validHeader, secret);
    assert.equal(validCheck.valid, true);

    // Negative case: Replay attack (stale timestamp older than 300s tolerance)
    const staleTime = now - 600; // 10 minutes old
    const staleHash = crypto
      .createHmac("sha256", secret)
      .update(`${staleTime}.${payload}`)
      .digest("hex");
    const staleHeader = `t=${staleTime},v1=${staleHash}`;

    const replayCheck = StripeWebhookManager.verifyStripeSignature(payload, staleHeader, secret);
    assert.equal(replayCheck.valid, false);
    assert.ok(replayCheck.reason?.includes("Replay attack blocked"));

    // Negative case: Tampered payload body
    const tamperedCheck = StripeWebhookManager.verifyStripeSignature(
      payload + "tampered_metachar",
      validHeader,
      secret
    );
    assert.equal(tamperedCheck.valid, false);
    assert.ok(tamperedCheck.reason?.includes("signature mismatch"));
  });

  await t.test("Stripe Idempotency: Deduplicates by stripe_event_id and executes queue worker", async () => {
    const stripeEventId = `evt_order_${crypto.randomBytes(6).toString("hex")}`;
    const webhookTenant = "tenant-stripe-checkout";

    // 1. First event delivery: Queued
    const firstDelivery = await StripeWebhookManager.recordAndQueueStripeEvent({
      stripeEventId,
      eventType: "checkout.session.completed",
      tenantId: webhookTenant,
      payload: {
        id: "cs_test_123",
        metadata: { tier: "enterprise" },
      },
    });

    assert.equal(firstDelivery.isDuplicate, false);
    assert.equal(firstDelivery.eventRecord.status, "pending");

    // 2. Second event delivery (duplicate webhook): Acknowledged idempotently
    const secondDelivery = await StripeWebhookManager.recordAndQueueStripeEvent({
      stripeEventId,
      eventType: "checkout.session.completed",
      tenantId: webhookTenant,
      payload: {
        id: "cs_test_123",
        metadata: { tier: "enterprise" },
      },
    });

    assert.equal(secondDelivery.isDuplicate, true);

    // 3. Worker execution: Processes event and updates subscription tier
    const processResult = await StripeWebhookManager.processQueuedStripeEvent(stripeEventId);
    assert.equal(processResult.success, true);
    assert.equal(processResult.actionTaken, "activated_tier_enterprise");

    // 4. Verify tenant subscription was transitioned
    const sub = await getTenantSubscription(webhookTenant);
    assert.equal(sub.tier, "enterprise");
    assert.equal(sub.status, "active");

    // 5. Subsequent worker execution returns already_processed
    const reProcess = await StripeWebhookManager.processQueuedStripeEvent(stripeEventId);
    assert.equal(reProcess.success, true);
    assert.equal(reProcess.actionTaken, "already_processed");
  });

  await t.test("Subscription Sync: Payment failure triggers grace period and cancellation suspends access", async () => {
    const eventIdFail = `evt_fail_${crypto.randomBytes(6).toString("hex")}`;
    const eventIdCancel = `evt_cancel_${crypto.randomBytes(6).toString("hex")}`;
    const testTenant = "tenant-dunning-test";

    // 1. Ingest invoice.payment_failed
    await StripeWebhookManager.recordAndQueueStripeEvent({
      stripeEventId: eventIdFail,
      eventType: "invoice.payment_failed",
      tenantId: testTenant,
      payload: { amount_due: 49900 },
    });
    const failResult = await StripeWebhookManager.processQueuedStripeEvent(eventIdFail);
    assert.equal(failResult.success, true);
    assert.equal(failResult.actionTaken, "transitioned_to_grace_period");

    // 2. Ingest customer.subscription.deleted
    await StripeWebhookManager.recordAndQueueStripeEvent({
      stripeEventId: eventIdCancel,
      eventType: "customer.subscription.deleted",
      tenantId: testTenant,
      payload: { status: "canceled" },
    });
    const cancelResult = await StripeWebhookManager.processQueuedStripeEvent(eventIdCancel);
    assert.equal(cancelResult.success, true);
    assert.equal(cancelResult.actionTaken, "subscription_cancelled_downgraded_to_community");

    // Tenant subscription downgraded
    const sub = await getTenantSubscription(testTenant);
    assert.equal(sub.tier, "community");
  });
});
