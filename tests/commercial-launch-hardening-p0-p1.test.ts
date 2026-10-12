import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { assertValidConfiguration } from "@/config/schema";
import { CheckoutService } from "@/lib/billing/checkoutService";
import { resolveServerStripePriceId } from "@/lib/billing/catalog";
import { getSessionFromRequest } from "@/lib/auth/session";
import { RollbackEngine } from "@/lib/rollback-engine/engine";
import { GET as licenseGET } from "@/app/api/v1/licenses/[operation]/route";
import { POST as legacyBillingPOST } from "@/app/api/billing/route";
import { getTenantSubscription } from "@/lib/billing/plans";
import { getOrCreateStripeCustomer } from "@/lib/billing/stripeClient";
import { StripeWebhookManager } from "@/lib/billing/stripeWebhook";
import { LicenseActivationService } from "@/lib/licensing/licenseActivation";
import { createSessionToken } from "@/lib/auth/token";
import { issueEndpointCertificate } from "@/lib/fleet/certificates";
import { issueCommercialLicense } from "@/lib/billing/licenses";

describe("Commercial Launch Hardening & P0/P1 Security Gate Suite", () => {
  describe("Phase 1: Production Environment Guards & Secret Isolation", () => {
    it("Rejects mock Stripe secret keys (sk_test_mock) in production", () => {
      const origNodeEnv = process.env.NODE_ENV;
      const origAppEnv = process.env.APP_ENV;
      const origKey = process.env.STRIPE_SECRET_KEY;
      try {
        process.env.APP_ENV = "production";
        delete (process.env as any).NODE_ENV;
        process.env.STRIPE_SECRET_KEY = "sk_test_mock_invalid_12345";
        process.env.STRIPE_WEBHOOK_SECRET = "whsec_valid_signing_secret_for_tests";
        process.env.SHIELDDESK_LICENSE_SECRET = "license_secret_high_entropy_random_32_characters_string";
        process.env.SHIELDDESK_LICENSE_PEPPER = "pepper_secret_high_entropy_random_32_characters_string";
        process.env.SHIELDDESK_SESSION_SECRET = "session_secret_high_entropy_random_32_characters_string";
        process.env.SHIELDDESK_INGEST_API_KEY = "ingest_api_key_valid_32_characters_string";
        process.env.DATABASE_URL = "postgres://test:test@localhost:5432/shielddesk";

        assert.throws(
          () => assertValidConfiguration(),
          /Mock-prefixed STRIPE_SECRET_KEY is strictly forbidden in production deployments/
        );
      } finally {
        if (origNodeEnv !== undefined) (process.env as any).NODE_ENV = origNodeEnv;
        else delete (process.env as any).NODE_ENV;
        if (origAppEnv !== undefined) process.env.APP_ENV = origAppEnv;
        else delete process.env.APP_ENV;
        if (origKey !== undefined) process.env.STRIPE_SECRET_KEY = origKey;
        else delete process.env.STRIPE_SECRET_KEY;
      }
    });

    it("Rejects mock Stripe webhook secrets (whsec_mock) in production", () => {
      const origAppEnv = process.env.APP_ENV;
      const origKey = process.env.STRIPE_SECRET_KEY;
      const origWhsec = process.env.STRIPE_WEBHOOK_SECRET;
      try {
        process.env.APP_ENV = "production";
        delete (process.env as any).NODE_ENV;
        process.env.STRIPE_SECRET_KEY = "sk_live_valid_format_test_key_12345";
        process.env.STRIPE_WEBHOOK_SECRET = "whsec_mock_fake_secret";
        process.env.SHIELDDESK_LICENSE_SECRET = "license_secret_high_entropy_random_32_characters_string";
        process.env.SHIELDDESK_LICENSE_PEPPER = "pepper_secret_high_entropy_random_32_characters_string";
        process.env.SHIELDDESK_SESSION_SECRET = "session_secret_high_entropy_random_32_characters_string";
        process.env.SHIELDDESK_INGEST_API_KEY = "ingest_api_key_valid_32_characters_string";
        process.env.DATABASE_URL = "postgres://test:test@localhost:5432/shielddesk";

        assert.throws(
          () => assertValidConfiguration(),
          /Mock-prefixed STRIPE_WEBHOOK_SECRET is strictly forbidden in production deployments/
        );
      } finally {
        if (origAppEnv !== undefined) process.env.APP_ENV = origAppEnv;
        else delete process.env.APP_ENV;
        if (origKey !== undefined) process.env.STRIPE_SECRET_KEY = origKey;
        else delete process.env.STRIPE_SECRET_KEY;
        if (origWhsec !== undefined) process.env.STRIPE_WEBHOOK_SECRET = origWhsec;
        else delete process.env.STRIPE_WEBHOOK_SECRET;
      }
    });

    it("Requires dedicated, isolated SHIELDDESK_LICENSE_PEPPER distinct from signing secret in production", () => {
      const origAppEnv = process.env.APP_ENV;
      const origPepper = process.env.SHIELDDESK_LICENSE_PEPPER;
      const origSigning = process.env.SHIELDDESK_LICENSE_SECRET;
      try {
        process.env.APP_ENV = "production";
        delete (process.env as any).NODE_ENV;
        process.env.STRIPE_SECRET_KEY = "sk_live_valid_format_test_key_12345";
        process.env.STRIPE_WEBHOOK_SECRET = "whsec_live_valid_format_test_12345";
        const sharedSecret = "shared_secret_high_entropy_random_32_characters_string";
        process.env.SHIELDDESK_LICENSE_SECRET = sharedSecret;
        process.env.SHIELDDESK_LICENSE_PEPPER = sharedSecret; // Violates isolation invariant
        process.env.SHIELDDESK_SESSION_SECRET = "session_secret_high_entropy_random_32_characters_string";
        process.env.SHIELDDESK_INGEST_API_KEY = "ingest_api_key_valid_32_characters_string";
        process.env.DATABASE_URL = "postgres://test:test@localhost:5432/shielddesk";

        assert.throws(
          () => assertValidConfiguration(),
          /Dedicated SHIELDDESK_LICENSE_PEPPER must be isolated from license signing and session secrets/
        );
      } finally {
        if (origAppEnv !== undefined) process.env.APP_ENV = origAppEnv;
        else delete process.env.APP_ENV;
        if (origPepper !== undefined) process.env.SHIELDDESK_LICENSE_PEPPER = origPepper;
        else delete process.env.SHIELDDESK_LICENSE_PEPPER;
        if (origSigning !== undefined) process.env.SHIELDDESK_LICENSE_SECRET = origSigning;
        else delete process.env.SHIELDDESK_LICENSE_SECRET;
      }
    });
  });

  describe("Phase 1 & 4: Commercial Catalogue & Checkout Service Guards", () => {
    it("Rejects mock Price IDs and unconfigured paid prices in production", () => {
      const origAppEnv = process.env.APP_ENV;
      try {
        process.env.APP_ENV = "production";
        delete process.env.STRIPE_PRICE_PROFESSIONAL_MONTHLY;

        assert.throws(
          () => resolveServerStripePriceId("professional", "month"),
          /CRITICAL BILLING CONFIGURATION ERROR: Stripe Price ID for professional \(month\)/
        );
      } finally {
        if (origAppEnv !== undefined) process.env.APP_ENV = origAppEnv;
        else delete process.env.APP_ENV;
      }
    });

    it("Fails closed when createCheckoutSession is called with mock key in production", async () => {
      const origAppEnv = process.env.APP_ENV;
      const origKey = process.env.STRIPE_SECRET_KEY;
      try {
        process.env.APP_ENV = "production";
        process.env.STRIPE_SECRET_KEY = "sk_test_mock_attempt";

        await assert.rejects(
          async () => {
            await CheckoutService.createCheckoutSession({
              tenantId: "tenant-prod-test-01",
              userId: "usr-prod-01",
              role: "system_admin",
              planId: "professional",
              interval: "month",
            });
          },
          /Mock Stripe secret keys are strictly prohibited in production/
        );
      } finally {
        if (origAppEnv !== undefined) process.env.APP_ENV = origAppEnv;
        else delete process.env.APP_ENV;
        if (origKey !== undefined) process.env.STRIPE_SECRET_KEY = origKey;
        else delete process.env.STRIPE_SECRET_KEY;
      }
    });
  });

  describe("Phase 2: Database Outage Fail-Closed Verification", () => {
    it("getTenantSubscription fails closed on database outage in production", async () => {
      const origAppEnv = process.env.APP_ENV;
      const origEnforce = process.env.SHIELDDESK_ENFORCE_PROD_DB;
      try {
        process.env.APP_ENV = "production";
        process.env.SHIELDDESK_ENFORCE_PROD_DB = "true";

        await assert.rejects(
          async () => {
            await getTenantSubscription("acme-tenant");
          },
          /CRITICAL_DATABASE_UNAVAILABLE/
        );
      } finally {
        if (origAppEnv !== undefined) process.env.APP_ENV = origAppEnv;
        else delete process.env.APP_ENV;
        if (origEnforce !== undefined) process.env.SHIELDDESK_ENFORCE_PROD_DB = origEnforce;
        else delete process.env.SHIELDDESK_ENFORCE_PROD_DB;
      }
    });

    it("getOrCreateStripeCustomer fails closed on database outage in production (no cus_mock_ fallback)", async () => {
      const origAppEnv = process.env.APP_ENV;
      const origEnforce = process.env.SHIELDDESK_ENFORCE_PROD_DB;
      try {
        process.env.APP_ENV = "production";
        process.env.SHIELDDESK_ENFORCE_PROD_DB = "true";

        await assert.rejects(
          async () => {
            await getOrCreateStripeCustomer({
              tenantId: "tenant-failclosed-test",
              email: "billing@failclosed.test",
            });
          },
          /CRITICAL_DATABASE_UNAVAILABLE/
        );
      } finally {
        if (origAppEnv !== undefined) process.env.APP_ENV = origAppEnv;
        else delete process.env.APP_ENV;
        if (origEnforce !== undefined) process.env.SHIELDDESK_ENFORCE_PROD_DB = origEnforce;
        else delete process.env.SHIELDDESK_ENFORCE_PROD_DB;
      }
    });

    it("getCheckoutStatus bypasses mock records and fails closed on DB outage in production", async () => {
      const origAppEnv = process.env.APP_ENV;
      const origEnforce = process.env.SHIELDDESK_ENFORCE_PROD_DB;
      try {
        process.env.APP_ENV = "production";
        process.env.SHIELDDESK_ENFORCE_PROD_DB = "true";

        await assert.rejects(
          async () => {
            await CheckoutService.getCheckoutStatus({
              tenantId: "acme-tenant",
              attemptId: "chk_mock_test_session",
            });
          },
          /CRITICAL_DATABASE_UNAVAILABLE/
        );
      } finally {
        if (origAppEnv !== undefined) process.env.APP_ENV = origAppEnv;
        else delete process.env.APP_ENV;
        if (origEnforce !== undefined) process.env.SHIELDDESK_ENFORCE_PROD_DB = origEnforce;
        else delete process.env.SHIELDDESK_ENFORCE_PROD_DB;
      }
    });

    it("recordAndQueueStripeEvent fails closed if DB insert fails in production", async () => {
      const origAppEnv = process.env.APP_ENV;
      const origEnforce = process.env.SHIELDDESK_ENFORCE_PROD_DB;
      try {
        process.env.APP_ENV = "production";
        process.env.SHIELDDESK_ENFORCE_PROD_DB = "true";

        await assert.rejects(
          async () => {
            await StripeWebhookManager.recordAndQueueStripeEvent({
              stripeEventId: "evt_test_unpersisted_12345",
              eventType: "checkout.session.completed",
              tenantId: "acme-tenant",
              payload: { id: "cs_123", metadata: { tenant_id: "acme-tenant" } },
            });
          },
          /CRITICAL_DATABASE_UNAVAILABLE/
        );
      } finally {
        if (origAppEnv !== undefined) process.env.APP_ENV = origAppEnv;
        else delete process.env.APP_ENV;
        if (origEnforce !== undefined) process.env.SHIELDDESK_ENFORCE_PROD_DB = origEnforce;
        else delete process.env.SHIELDDESK_ENFORCE_PROD_DB;
      }
    });

    it("LicenseActivationService.activate fails closed if DB persistence fails in production", async () => {
      const origAppEnv = process.env.APP_ENV;
      const origEnforce = process.env.SHIELDDESK_ENFORCE_PROD_DB;
      try {
        const caller = {
          id: "dev-admin",
          tenant_id: "acme-tenant",
          role: "system_admin" as const,
        };
        const cert = await issueEndpointCertificate({
          agentId: "FIN-WS-042",
          tenantId: "acme-tenant",
          validityDays: 1,
        });
        const lic = issueCommercialLicense({
          tenantId: "acme-tenant",
          tier: "professional",
          maxEndpoints: 10,
          maxUsers: 5,
          features: ["endpointFleet"],
          expiresAt: new Date(Date.now() + 86400000).toISOString(),
        });

        process.env.APP_ENV = "production";
        process.env.SHIELDDESK_ENFORCE_PROD_DB = "true";

        await assert.rejects(
          async () => {
            await LicenseActivationService.activate({
              tenantId: "acme-tenant",
              installationId: "inst-fc-001",
              deviceIdentity: "FIN-WS-042",
              certificatePem: cert.certificatePem,
              licenseKey: lic.rawLicense,
            });
          },
          /CRITICAL_DATABASE_UNAVAILABLE/
        );
      } finally {
        if (origAppEnv !== undefined) process.env.APP_ENV = origAppEnv;
        else delete process.env.APP_ENV;
        if (origEnforce !== undefined) process.env.SHIELDDESK_ENFORCE_PROD_DB = origEnforce;
        else delete process.env.SHIELDDESK_ENFORCE_PROD_DB;
      }
    });
  });

  describe("Phase 3: Tenant Isolation & Authentication Hardening", () => {
    it("getSessionFromRequest fails closed when app_metadata.tenant_id is missing (never defaults to acme-tenant)", async () => {
      const req = new NextRequest("http://localhost:3000/api/dashboard", {
        headers: {
          authorization: "Bearer sb_test_token_without_tenant",
        },
      });

      const session = await getSessionFromRequest(req);
      assert.equal(session, null, "Authenticated user without valid tenant claim must be rejected with null session");
    });
  });

  describe("Phase 5: Legacy Billing Route Containment", () => {
    it("POST /api/billing blocks confirm_upgrade and checkout order in production", async () => {
      const origAppEnv = process.env.APP_ENV;
      try {
        process.env.APP_ENV = "production";

        const token = createSessionToken({
          uid: "usr-admin-01",
          tenantId: "acme-tenant",
          role: "system_admin",
        });

        const req = new NextRequest("http://localhost:3000/api/billing", {
          method: "POST",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ action: "confirm_upgrade", targetTier: "professional" }),
        });

        const res = await legacyBillingPOST(req);
        assert.equal(res.status, 403, "Legacy billing mutations must be blocked with 403 Forbidden in production");
        const json = await res.json();
        assert.match(json.error, /prohibited in production/);
      } finally {
        if (origAppEnv !== undefined) process.env.APP_ENV = origAppEnv;
        else delete process.env.APP_ENV;
      }
    });
  });

  describe("Phase 6: License API Security Policy", () => {
    it("GET /api/v1/licenses/entitlements strictly rejects raw licenseKey in query parameters", async () => {
      const token = createSessionToken({
        uid: "usr-admin-01",
        tenantId: "acme-tenant",
        role: "system_admin",
      });

      const req = new NextRequest(
        "http://localhost:3000/api/v1/licenses/entitlements?installationId=inst-01&licenseKey=SDCOMM_raw_secret_key",
        {
          headers: { authorization: `Bearer ${token}` },
        }
      );

      const params = Promise.resolve({ operation: "entitlements" });
      const res = await licenseGET(req, { params });
      assert.equal(res.status, 400, "Raw license key in GET query parameter must be blocked with 400");
      const json = await res.json();
      assert.match(json.error, /Security Policy: Transmitting raw license keys in GET query parameters is prohibited/);
    });
  });

  describe("Phase 8: Rollback Engine Simulation Verification", () => {
    it("Simulated rollback outcome is strictly tagged SIMULATION_ONLY, never RESTORATION_VERIFIED", async () => {
      const outcome = await RollbackEngine.executeRollback({
        tenantId: "acme-tenant",
        agentId: "FIN-WS-SIM-01",
        commandId: "cmd-sim-01",
        snapshotId: "snap-sim-01",
        rollbackType: "network_rollback",
        reason: "Test simulation rollback status",
        actorId: "analyst-01",
      });

      assert.equal(
        outcome.status,
        "SIMULATION_ONLY",
        "Rule 3 invariant: Simulated rollbacks must be tagged SIMULATION_ONLY"
      );
      assert.notEqual(
        outcome.status,
        "RESTORATION_VERIFIED",
        "Simulation must NEVER claim RESTORATION_VERIFIED"
      );
    });
  });
});
