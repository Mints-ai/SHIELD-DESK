import "./setup";
import test, { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { NextRequest } from "next/server";
import { createSessionToken } from "@/lib/auth/token";
import { GET as getPlansRoute } from "@/app/api/v1/plans/route";
import { POST as checkoutRoute } from "@/app/api/v1/billing/checkout-sessions/route";
import { GET as checkoutStatusRoute } from "@/app/api/v1/billing/checkout-status/route";
import { POST as portalRoute } from "@/app/api/v1/billing/portal-sessions/route";
import { GET as subscriptionRoute } from "@/app/api/v1/billing/subscription/route";
import { POST as changePlanRoute } from "@/app/api/v1/billing/change-plan/route";
import { POST as cancelRoute } from "@/app/api/v1/billing/cancel/route";
import { GET as invoicesRoute } from "@/app/api/v1/billing/invoices/route";
import { POST as licenseOperationPOST, GET as licenseOperationGET } from "@/app/api/v1/licenses/[operation]/route";
import { GET as listActivationsRoute } from "@/app/api/v1/licenses/activations/route";
import { POST as deactivateRoute } from "@/app/api/v1/licenses/activations/[id]/deactivate/route";
import { POST as revokeRoute } from "@/app/api/v1/licenses/[operation]/revoke/route";
import { POST as webhookRoute } from "@/app/api/billing/webhook/route";
import { issueEndpointCertificate } from "@/lib/fleet/certificates";
import { MTLSGuard } from "@/lib/fleet/mtlsGuard";
import {
  generateHighEntropyLicense,
  hashLicenseKey,
  verifyCommercialLicense,
  issueCommercialLicense,
  verifyAsymmetricEntitlementToken,
} from "@/lib/billing/licenses";
import { StripeWebhookManager } from "@/lib/billing/stripeWebhook";
import { getTenantSubscription, updateTenantSubscription } from "@/lib/billing/plans";
import { EntitlementService } from "@/lib/billing/entitlements";
import { LicenseActivationService } from "@/lib/licensing/licenseActivation";
import { CANONICAL_CATALOG } from "@/lib/billing/catalog";

describe("Commercial Licensing, Stripe Billing & Customer Purchase Test Suite", () => {
  after(async () => {
    // Clean up background DB pools so test runner exits promptly
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    if ((global as any).__shieldDeskPgPool) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (global as any).__shieldDeskPgPool.end().catch(() => {});
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global as any).__shieldDeskPgPool = undefined;
    }
  });

  const tenantA = `tenant-comm-a-${crypto.randomBytes(4).toString("hex")}`;
  const tenantB = `tenant-comm-b-${crypto.randomBytes(4).toString("hex")}`;

  const adminTokenA = createSessionToken({
    uid: "usr-admin-a",
    tenantId: tenantA,
    role: "system_admin",
  });

  const analystTokenA = createSessionToken({
    uid: "usr-analyst-a",
    tenantId: tenantA,
    role: "analyst",
  });

  const adminTokenB = createSessionToken({
    uid: "usr-admin-b",
    tenantId: tenantB,
    role: "system_admin",
  });

  // 1. CANONICAL PRODUCT CATALOGUE
  it("Phase 1: GET /api/v1/plans returns public catalogue without secret leak", async () => {
    const res = await getPlansRoute();
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.success, true);
    assert.ok(Array.isArray(data.plans));
    assert.ok(data.plans.length >= 3);

    const planIds = data.plans.map((p: any) => p.id);
    assert.ok(planIds.includes("community"));
    assert.ok(planIds.includes("professional"));
    assert.ok(planIds.includes("enterprise"));

    // Verify fields and that secrets are not leaked
    for (const plan of data.plans) {
      assert.ok(plan.name);
      assert.ok(plan.pricing);
      assert.ok(typeof plan.maxEndpoints === "number");
      assert.equal(typeof plan.secret, "undefined");
      assert.equal(typeof plan.stripeSecret, "undefined");
    }
  });

  // 2. REAL STRIPE CHECKOUT SESSIONS
  it("Phase 2: POST /api/v1/billing/checkout-sessions enforces RBAC, validation, and no premature upgrade", async () => {
    // 1. Unauthenticated request rejected
    const unauthReq = new NextRequest("http://localhost:3000/api/v1/billing/checkout-sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ planId: "professional", billingInterval: "month" }),
    });
    const unauthRes = await checkoutRoute(unauthReq);
    assert.equal(unauthRes.status, 401);

    // 2. Analyst (non-billing-admin) rejected
    const analystReq = new NextRequest("http://localhost:3000/api/v1/billing/checkout-sessions", {
      method: "POST",
      headers: {
        authorization: `Bearer ${analystTokenA}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ planId: "professional", billingInterval: "month" }),
    });
    const analystRes = await checkoutRoute(analystReq);
    assert.equal(analystRes.status, 403);

    // 3. Invalid tier / tampered request rejected
    const invalidPlanReq = new NextRequest("http://localhost:3000/api/v1/billing/checkout-sessions", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminTokenA}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ planId: "hacker_tier_free", billingInterval: "month" }),
    });
    const invalidPlanRes = await checkoutRoute(invalidPlanReq);
    assert.equal(invalidPlanRes.status, 400);

    // 4. Valid checkout session creation
    const validReq = new NextRequest("http://localhost:3000/api/v1/billing/checkout-sessions", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminTokenA}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        planId: "professional",
        billingInterval: "month",
        currency: "USD",
        deploymentType: "hosted_saas",
      }),
    });
    const validRes = await checkoutRoute(validReq);
    assert.equal(validRes.status, 200);
    const sessionData = await validRes.json();
    assert.equal(sessionData.success, true);
    assert.ok(sessionData.checkoutUrl);
    assert.ok(sessionData.attemptId);
    assert.equal(sessionData.plan, "professional");

    // 5. CRITICAL: Premature upgrade check: tenant must STILL be community tier
    const sub = await getTenantSubscription(tenantA);
    assert.notEqual(sub.tier, "professional", "Checkout creation must NOT grant paid entitlements before verified payment");
  });

  // 3. CHECKOUT STATUS POLLING
  it("Phase 2: GET /api/v1/billing/checkout-status denies cross-tenant access and does not grant paid access", async () => {
    // 1. Create a checkout attempt for tenant A
    const attemptReq = new NextRequest("http://localhost:3000/api/v1/billing/checkout-sessions", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminTokenA}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        planId: "enterprise",
        billingInterval: "year",
        deploymentType: "customer_hosted",
      }),
    });
    const attemptRes = await checkoutRoute(attemptReq);
    assert.equal(attemptRes.status, 200);
    const attemptData = await attemptRes.json();
    const checkoutAttemptId = attemptData.attemptId;
    assert.ok(checkoutAttemptId);

    // 2. Tenant B attempting to read Tenant A's checkout status -> rejected / 400+
    const crossTenantReq = new NextRequest(
      `http://localhost:3000/api/v1/billing/checkout-status?attemptId=${checkoutAttemptId}`,
      {
        method: "GET",
        headers: { authorization: `Bearer ${adminTokenB}` },
      }
    );
    const crossRes = await checkoutStatusRoute(crossTenantReq);
    assert.equal(crossRes.status >= 400, true);

    // 3. Tenant A polling returns pending status and DOES NOT upgrade subscription
    const ownerPollReq = new NextRequest(
      `http://localhost:3000/api/v1/billing/checkout-status?attemptId=${checkoutAttemptId}`,
      {
        method: "GET",
        headers: { authorization: `Bearer ${adminTokenA}` },
      }
    );
    const pollRes = await checkoutStatusRoute(ownerPollReq);
    assert.equal(pollRes.status, 200);
    const pollData = await pollRes.json();
    assert.equal(pollData.success, true);
    assert.equal(pollData.status, "pending");

    // Verify tenant is NOT upgraded
    const currentSub = await getTenantSubscription(tenantA);
    assert.notEqual(currentSub.tier, "enterprise");
  });

  // 4. STRIPE CUSTOMER PORTAL
  it("Phase 2: POST /api/v1/billing/portal-sessions requires admin authorization", async () => {
    // Analyst rejected
    const analystReq = new NextRequest("http://localhost:3000/api/v1/billing/portal-sessions", {
      method: "POST",
      headers: { authorization: `Bearer ${analystTokenA}` },
    });
    const analystRes = await portalRoute(analystReq);
    assert.equal(analystRes.status, 403);

    // Admin allowed
    const adminReq = new NextRequest("http://localhost:3000/api/v1/billing/portal-sessions", {
      method: "POST",
      headers: { authorization: `Bearer ${adminTokenA}` },
    });
    const adminRes = await portalRoute(adminReq);
    assert.equal(adminRes.status, 200);
    const portalData = await adminRes.json();
    assert.equal(portalData.success, true);
    assert.ok(portalData.portalUrl);
  });

  // 5. STRIPE WEBHOOK DURABILITY & PROVISIONING
  it("Phase 3: Stripe Webhook persists, deduplicates, and provisions subscription & license", async () => {
    const stripeEventId = `evt_comm_test_${crypto.randomBytes(6).toString("hex")}`;
    const webhookTenant = `tenant-webhook-${crypto.randomBytes(4).toString("hex")}`;

    // 1. Signature failure without valid secret
    const badSigReq = new NextRequest("http://localhost:3000/api/billing/webhook", {
      method: "POST",
      headers: { "stripe-signature": "t=12345,v1=bad_signature" },
      body: JSON.stringify({ id: stripeEventId }),
    });
    const badSigRes = await webhookRoute(badSigReq);
    assert.equal(badSigRes.status, 401);

    // 2. Deliver valid event through StripeWebhookManager
    const firstDelivery = await StripeWebhookManager.recordAndQueueStripeEvent({
      stripeEventId,
      eventType: "checkout.session.completed",
      tenantId: webhookTenant,
      payload: {
        id: `cs_${stripeEventId}`,
        subscription: `sub_${stripeEventId}`,
        metadata: {
          tenant_id: webhookTenant,
          tier: "enterprise",
          billing_interval: "year",
        },
      },
    });

    assert.equal(firstDelivery.isDuplicate, false);
    assert.equal(firstDelivery.eventRecord.status, "pending");

    // 3. Duplicate event delivery is acknowledged idempotently
    const secondDelivery = await StripeWebhookManager.recordAndQueueStripeEvent({
      stripeEventId,
      eventType: "checkout.session.completed",
      tenantId: webhookTenant,
      payload: {
        id: `cs_${stripeEventId}`,
        metadata: { tenant_id: webhookTenant, tier: "enterprise" },
      },
    });

    assert.equal(secondDelivery.isDuplicate, true);

    // 4. Worker executes and provisions tenant
    const processResult = await StripeWebhookManager.processQueuedStripeEvent(stripeEventId);
    assert.equal(processResult.success, true);
    assert.equal(processResult.actionTaken, "activated_tier_enterprise");

    // 5. Tenant state verified
    const sub = await getTenantSubscription(webhookTenant);
    assert.equal(sub.tier, "enterprise");
    assert.equal(sub.status, "active");

    // 6. Entitlements verified
    const plan = CANONICAL_CATALOG[sub.tier];
    assert.equal(plan.maxEndpoints, 10000);
    assert.equal(plan.features.automatedRemediationTier1, true);
    assert.equal(plan.features.complianceVault, true);

    // 7. Re-processing returns already_processed
    const reProcess = await StripeWebhookManager.processQueuedStripeEvent(stripeEventId);
    assert.equal(reProcess.actionTaken, "already_processed");
  });

  // 6. HIGH-ENTROPY CRYPTOGRAPHIC LICENSING & ZERO RAW KEY PERSISTENCE
  it("Phase 5: High-entropy license generation, peppered hash lookup, and asymmetric token issuance", async () => {
    const licTenant = `tenant-lic-${crypto.randomBytes(4).toString("hex")}`;
    const plan = CANONICAL_CATALOG.enterprise;

    // 1. Generate high-entropy commercial license
    const artifact = generateHighEntropyLicense({
      tenantId: licTenant,
      tier: "enterprise",
      maxEndpoints: plan.maxEndpoints,
      maxUsers: plan.maxUsers,
      features: [...Object.keys(plan.features), "endpointFleet"],
      expiresAt: new Date(Date.now() + 86400 * 1000).toISOString(),
    });

    assert.ok(artifact.displayPrefix.startsWith("SD-ENT"));
    assert.ok(artifact.rawLicenseKey.includes("."));
    assert.ok(artifact.keyHash);
    assert.ok(artifact.displaySuffix);

    // Verify raw key is NOT equal to keyHash
    assert.notEqual(artifact.rawLicenseKey, artifact.keyHash);

    // Verify peppered hash matches
    const computedHash = hashLicenseKey(artifact.rawLicenseKey);
    assert.equal(computedHash, artifact.keyHash);

    // 2. Activate installation with license key and device certificate
    const installationId = `inst-${crypto.randomUUID()}`;
    const deviceIdentity = `edge-sensor-${crypto.randomUUID()}`;
    const cert = await issueEndpointCertificate({ agentId: deviceIdentity, tenantId: licTenant });
    MTLSGuard.registerAgent({
      id: deviceIdentity,
      tenant_id: licTenant,
      cert_fingerprint: cert.fingerprintSha256.replaceAll(":", "").toLowerCase(),
    });

    const activationRes = await LicenseActivationService.activate({
      tenantId: licTenant,
      licenseKey: artifact.rawLicenseKey,
      installationId,
      deviceIdentity,
      certificatePem: cert.certificatePem,
      platform: "linux-x86_64",
      productVersion: "1.0.0",
    });

    assert.equal(activationRes.state, "ACTIVE");
    assert.ok(activationRes.entitlementToken);

    // 3. Verify asymmetric entitlement token signature
    const tokenCheck = verifyAsymmetricEntitlementToken(activationRes.entitlementToken);
    assert.equal(tokenCheck.valid, true);
    assert.equal(tokenCheck.payload?.tenantId, licTenant);
    assert.equal(tokenCheck.payload?.tier, "enterprise");
    assert.equal(tokenCheck.payload?.installationId, installationId);

    // 4. Refresh entitlement token
    const refreshRes = await LicenseActivationService.refresh({
      tenantId: licTenant,
      installationId,
      deviceIdentity,
      certificatePem: cert.certificatePem,
      licenseKey: artifact.rawLicenseKey,
    });
    assert.equal(refreshRes.state, "ACTIVE");
    assert.ok(refreshRes.entitlementToken);

    // 5. List activations
    const activations = await LicenseActivationService.listActivations(licTenant);
    assert.equal(activations.length, 1);
    assert.equal(activations[0].installationId, installationId);
    assert.equal(activations[0].state, "ACTIVE");

    // 6. Deactivate installation
    const deactRes = await LicenseActivationService.deactivate({
      tenantId: licTenant,
      installationId,
      deviceIdentity,
      certificatePem: cert.certificatePem,
      licenseKey: artifact.rawLicenseKey,
    });
    assert.equal(deactRes.state, "SUSPENDED");

    // 7. Revoke license
    const revokeRes = await LicenseActivationService.revoke(licTenant, artifact.payload.licenseId, "administrative_action");
    assert.equal(revokeRes.success, true);

    // Subsequent activation attempts fail
    await assert.rejects(
      async () => {
        await LicenseActivationService.activate({
          tenantId: licTenant,
          licenseKey: artifact.rawLicenseKey,
          installationId: `inst-new-${crypto.randomUUID()}`,
          deviceIdentity,
          certificatePem: cert.certificatePem,
        });
      },
      /revoked/i
    );
  });

  // 7. LICENSE REST APIS (ACTIVATE, REFRESH, DEACTIVATE, REVOKE)
  it("Phase 5: License REST APIs enforce tenant binding and authorization", async () => {
    // Issue license for tenant A
    const licTenant = tenantA;
    const plan = CANONICAL_CATALOG.professional;
    const artifact = generateHighEntropyLicense({
      tenantId: licTenant,
      tier: "professional",
      maxEndpoints: plan.maxEndpoints,
      maxUsers: plan.maxUsers,
      features: [...Object.keys(plan.features), "endpointFleet"],
      expiresAt: new Date(Date.now() + 86400 * 1000).toISOString(),
    });

    const deviceIdentityA = `server-a-${crypto.randomUUID()}`;
    const certA = await issueEndpointCertificate({ agentId: deviceIdentityA, tenantId: tenantA });
    MTLSGuard.registerAgent({
      id: deviceIdentityA,
      tenant_id: tenantA,
      cert_fingerprint: certA.fingerprintSha256.replaceAll(":", "").toLowerCase(),
    });

    // Cross-tenant activation rejected: Tenant B attempting to activate Tenant A's license
    const crossReq = new NextRequest("http://localhost:3000/api/v1/licenses/activate", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminTokenB}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        tenantId: tenantB,
        licenseKey: artifact.rawLicenseKey,
        installationId: "inst-b-attempt",
        deviceIdentity: deviceIdentityA,
        certificatePem: certA.certificatePem,
      }),
    });
    const crossRes = await licenseOperationPOST(crossReq, { params: Promise.resolve({ operation: "activate" }) });
    assert.equal(crossRes.status, 403);

    // Authorized activation for Tenant A
    const authReq = new NextRequest("http://localhost:3000/api/v1/licenses/activate", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminTokenA}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        tenantId: tenantA,
        licenseKey: artifact.rawLicenseKey,
        installationId: "inst-a-valid",
        deviceIdentity: deviceIdentityA,
        certificatePem: certA.certificatePem,
        platform: "linux",
        productVersion: "1.0.0",
      }),
    });
    const authRes = await licenseOperationPOST(authReq, { params: Promise.resolve({ operation: "activate" }) });
    assert.equal(authRes.status, 200);
    const authData = await authRes.json();
    assert.equal(authData.success, true);
    assert.ok(authData.activation);

    // List activations for Tenant A
    const listReq = new NextRequest("http://localhost:3000/api/v1/licenses/activations", {
      method: "GET",
      headers: { authorization: `Bearer ${adminTokenA}` },
    });
    const listRes = await listActivationsRoute(listReq);
    assert.equal(listRes.status, 200);
    const listData = await listRes.json();
    assert.ok(Array.isArray(listData.activations));
    assert.ok(listData.activations.some((a: any) => a.installationId === "inst-a-valid"));

    // Tenant B cannot see Tenant A's activations
    const listReqB = new NextRequest("http://localhost:3000/api/v1/licenses/activations", {
      method: "GET",
      headers: { authorization: `Bearer ${adminTokenB}` },
    });
    const listResB = await listActivationsRoute(listReqB);
    assert.equal(listResB.status, 200);
    const listDataB = await listResB.json();
    assert.equal(listDataB.activations.some((a: any) => a.installationId === "inst-a-valid"), false);

    // Deactivate installation
    const deactReq = new NextRequest("http://localhost:3000/api/v1/licenses/activations/inst-a-valid/deactivate", {
      method: "POST",
      headers: { authorization: `Bearer ${adminTokenA}` },
    });
    const deactRes = await deactivateRoute(deactReq, { params: Promise.resolve({ id: "inst-a-valid" }) });
    assert.equal(deactRes.status, 200);
    const deactData = await deactRes.json();
    assert.equal(deactData.success, true);

    // Revoke license under administrative control
    const revokeReq = new NextRequest(`http://localhost:3000/api/v1/licenses/${artifact.payload.licenseId}/revoke`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminTokenA}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ reason: "end_of_pilot" }),
    });
    const revokeRes = await revokeRoute(revokeReq, { params: Promise.resolve({ operation: artifact.payload.licenseId }) });
    assert.equal(revokeRes.status, 200);
    const revokeData = await revokeRes.json();
    assert.equal(revokeData.success, true);
  });

  // 8. SUBSCRIPTION, PLAN CHANGE, INVOICE AND CANCELLATION APIS
  it("Phase 6: Subscription retrieval, plan upgrade, invoice history, and cancellation", async () => {
    // 1. Current subscription status
    const subReq = new NextRequest("http://localhost:3000/api/v1/billing/subscription", {
      method: "GET",
      headers: { authorization: `Bearer ${adminTokenA}` },
    });
    const subRes = await subscriptionRoute(subReq);
    assert.equal(subRes.status, 200);
    const subData = await subRes.json();
    assert.equal(subData.success, true);
    assert.ok(subData.subscription);
    assert.ok(subData.entitlements);
    assert.ok(subData.subscription.maxEndpoints);

    // 2. Change plan (upgrade)
    const changeReq = new NextRequest("http://localhost:3000/api/v1/billing/change-plan", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminTokenA}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ targetTier: "enterprise", billingInterval: "month" }),
    });
    const changeRes = await changePlanRoute(changeReq);
    assert.equal(changeRes.status, 200);
    const changeData = await changeRes.json();
    assert.equal(changeData.success, true);
    assert.equal(changeData.subscription.tier, "enterprise");

    // 3. Invoices retrieval
    const invReq = new NextRequest("http://localhost:3000/api/v1/billing/invoices", {
      method: "GET",
      headers: { authorization: `Bearer ${adminTokenA}` },
    });
    const invRes = await invoicesRoute(invReq);
    assert.equal(invRes.status, 200);
    const invData = await invRes.json();
    assert.equal(invData.success, true);
    assert.ok(Array.isArray(invData.invoices));

    // 4. Cancel subscription
    const cancelReq = new NextRequest("http://localhost:3000/api/v1/billing/cancel", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminTokenA}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ immediate: false, reason: "consolidating_tools" }),
    });
    const cancelRes = await cancelRoute(cancelReq);
    assert.equal(cancelRes.status, 200);
    const cancelData = await cancelRes.json();
    assert.equal(cancelData.success, true);
    assert.equal(cancelData.immediate, false);
    assert.ok(cancelData.currentPeriodEnd);
  });
});
