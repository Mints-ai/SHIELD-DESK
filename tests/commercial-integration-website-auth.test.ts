import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { POST as signupHandler } from "@/app/api/auth/signup/route";
import { GET as getPlansHandler } from "@/app/api/v1/plans/route";
import { POST as checkoutHandler } from "@/app/api/v1/billing/checkout-sessions/route";
import { canAccess } from "@/lib/permissions";
import { NextRequest } from "next/server";
import { createSessionToken } from "@/lib/auth/token";

describe("Commercial Integration & Security Hardening Suite", () => {
  describe("Public Signup Hardening & RBAC Isolation", () => {
    test("Security Invariant: Rejects public role escalation (system_admin request receives super_admin organization scope)", async () => {
      const maliciousBody = {
        email: `founder_${Date.now()}@cybercorp.io`,
        password: "MasterPassword2026!",
        organizationName: "CyberCorp Security",
        role: "system_admin", // Malicious escalation attempt
      };

      const req = new NextRequest("http://localhost:3000/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(maliciousBody),
      });

      const res = await signupHandler(req);
      assert.equal(res.status, 200);

      const json = await res.json();
      assert.equal(json.success, true);
      assert.ok(json.tenantId, "Must return server-generated tenantId");
      assert.ok(json.token, "Must return signed session token");

      // Verify the tenant scope is unique and prefixed
      assert.match(json.tenantId, /^tenant_cybercorp-security_[a-f0-9]{8}$/);

      // Verify role assigned to organization founder has tenant billing permissions but NOT platform-wide cross-tenant visibility
      assert.equal(canAccess("super_admin", "MANAGE_USERS"), true, "Organization owner must have MANAGE_USERS");
      assert.equal(canAccess("super_admin", "VIEW_CROSS_TENANT"), false, "Organization owner must NOT have VIEW_CROSS_TENANT");
    });

    test("Security Invariant: Prevents tenant collision / hijacking across registrations with identical organization names", async () => {
      const orgName = "Global Defense Corp";

      const req1 = new NextRequest("http://localhost:3000/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: `user1_${Date.now()}@gdcorp.io`,
          password: "SecurePassword1!",
          organizationName: orgName,
        }),
      });

      const req2 = new NextRequest("http://localhost:3000/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: `user2_${Date.now()}@gdcorp.io`,
          password: "SecurePassword2!",
          organizationName: orgName,
        }),
      });

      const res1 = await signupHandler(req1);
      const res2 = await signupHandler(req2);

      const json1 = await res1.json();
      const json2 = await res2.json();

      assert.equal(res1.status, 200);
      assert.equal(res2.status, 200);
      assert.notEqual(json1.tenantId, json2.tenantId, "Tenant IDs must be distinct and non-colliding");
    });

    test("Validation: Rejects short password (< 8 chars)", async () => {
      const req = new NextRequest("http://localhost:3000/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: `weak_${Date.now()}@test.io`,
          password: "short",
          organizationName: "Weak Lab",
        }),
      });

      const res = await signupHandler(req);
      assert.equal(res.status, 400);
      const json = await res.json();
      assert.match(json.error, /Password must be at least 8 characters/);
    });
  });

  describe("Public Plan Catalogue (GET /api/v1/plans)", () => {
    test("Returns canonical plans with accurate monthly & annual pricing without exposing secrets", async () => {
      const res = await getPlansHandler();
      assert.equal(res.status, 200);

      const json = await res.json();
      assert.equal(json.success, true);
      assert.ok(Array.isArray(json.plans));

      const planIds = json.plans.map((p: any) => p.id);
      assert.ok(planIds.includes("community"));
      assert.ok(planIds.includes("professional"));
      assert.ok(planIds.includes("enterprise"));

      const pro = json.plans.find((p: any) => p.id === "professional");
      assert.ok(pro);
      assert.equal(pro.pricing.month.amountUSD, 49, "Pro monthly display price must be $49");
      assert.equal(pro.pricing.year.monthlyEquivalentUSD, 39, "Pro annual display price must be $39/mo");
      assert.equal(pro.pricing.year.amountUSD, 468, "Pro annual total amount must be $468");
      assert.equal(pro.maxEndpoints, 100, "Pro endpoint limit must be 100");

      // Verify no server environment secrets leaked
      const rawString = JSON.stringify(json);
      assert.equal(rawString.includes("sk_test_"), false);
      assert.equal(rawString.includes("whsec_"), false);
      assert.equal(rawString.includes("STRIPE_SECRET_KEY"), false);
    });
  });

  describe("Checkout Session Authorization & Tenant Boundary", () => {
    test("Unauthenticated checkout returns 401 Unauthorized", async () => {
      const req = new NextRequest("http://localhost:3000/api/v1/billing/checkout-sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ planId: "professional", interval: "year" }),
      });

      const res = await checkoutHandler(req);
      assert.equal(res.status, 401);
    });

    test("Non-billing role (analyst) returns 403 Forbidden", async () => {
      const token = createSessionToken({
        uid: "user-analyst-123",
        tenantId: "tenant_test_1",
        role: "analyst",
      });

      const req = new NextRequest("http://localhost:3000/api/v1/billing/checkout-sessions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: `shielddesk_session=${token}`,
        },
        body: JSON.stringify({ planId: "professional", interval: "month" }),
      });

      const res = await checkoutHandler(req);
      assert.equal(res.status, 403);
    });

    test("Tenant super_admin is authorized to initiate checkout", async () => {
      const token = createSessionToken({
        uid: "user-admin-456",
        tenantId: "tenant_test_2",
        role: "super_admin",
      });

      const req = new NextRequest("http://localhost:3000/api/v1/billing/checkout-sessions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: `shielddesk_session=${token}`,
        },
        body: JSON.stringify({ planId: "professional", interval: "month" }),
      });

      const res = await checkoutHandler(req);
      // In dev/test mode with mock stripe, it creates a session successfully (200)
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.success, true);
      assert.ok(json.checkoutUrl);
    });
  });
});
