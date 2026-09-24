import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { POST as loginPOST } from "../src/app/api/auth/login/route";
import { GET as fleetGET } from "../src/app/api/fleet/route";
import { GET as fleetIdGET } from "../src/app/api/fleet/[id]/route";
import { POST as fleetCommandPOST } from "../src/app/api/fleet/[id]/command/route";
import { POST as killSwitchPOST } from "../src/app/api/fleet/kill-switch/route";
import { GET as complianceGET } from "../src/app/api/compliance/route";
import { GET as scorecardGET } from "../src/app/api/reports/scorecard/route";
import { POST as ingestPOST } from "../src/app/api/ingest/webhooks/route";
import { getSessionFromRequest, getSessionUser } from "../src/lib/auth/session";
import { createSessionToken, verifySessionToken } from "../src/lib/auth/token";
import { hashPassword, verifyPassword } from "../src/lib/auth/password";

test("ShieldDesk Phase 0 Security & Auth Hardening Suite", async (t) => {
  // -------------------------------------------------------------------------
  // S1: Dev Personas strictly blocked in production
  // -------------------------------------------------------------------------
  await t.test("S1: Dev persona quick-login is rejected with 401 in production", async () => {
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";

    try {
      const req = new NextRequest("http://localhost:3000/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ userId: "dev-admin" }),
      });

      const res = await loginPOST(req);
      assert.equal(res.status, 401);
      const data = await res.json();
      assert.match(data.error, /disabled in production/i);
    } finally {
      process.env.NODE_ENV = originalEnv;
    }
  });

  // -------------------------------------------------------------------------
  // S2: Cryptographic Session Signing (tamper-proof tokens)
  // -------------------------------------------------------------------------
  await t.test("S2: Forged unsigned user ID in cookie or Bearer is strictly rejected", async () => {
    // Forged raw user ID in cookie
    const forgedCookieReq = new Request("http://localhost:3000/api/test", {
      headers: { cookie: "shielddesk_session=dev-admin" },
    });
    const sessionFromCookie = await getSessionFromRequest(forgedCookieReq);
    assert.equal(sessionFromCookie, null, "Unsigned user ID cookie must fail closed");

    // Forged raw user ID in Bearer
    const forgedBearerReq = new Request("http://localhost:3000/api/test", {
      headers: { authorization: "Bearer dev-admin" },
    });
    const sessionFromBearer = await getSessionFromRequest(forgedBearerReq);
    assert.equal(sessionFromBearer, null, "Unsigned Bearer token must fail closed");
  });

  await t.test("S2: Tampered session token fails cryptographic verification", async () => {
    const validToken = createSessionToken({
      uid: "usr-soc-001",
      tenantId: "acme-tenant",
      role: "user",
    });

    const [payload, sig] = validToken.split(".");
    // Tamper with signature
    const tamperedSig = sig.slice(0, -4) + "XXXX";
    const verified = verifySessionToken(`${payload}.${tamperedSig}`);
    assert.equal(verified, null, "Tampered signature must fail verification");

    // Tamper with payload
    const tamperedPayload = Buffer.from(
      JSON.stringify({ uid: "usr-soc-001", tenantId: "acme-tenant", role: "system_admin", exp: 9999999999, iat: 1000 })
    ).toString("base64url");
    const verifiedTamperedPayload = verifySessionToken(`${tamperedPayload}.${sig}`);
    assert.equal(verifiedTamperedPayload, null, "Tampered payload with valid original signature must fail");
  });

  await t.test("S2: Valid signed session token authenticates successfully", async () => {
    const validToken = createSessionToken({
      uid: "usr-soc-verified",
      tenantId: "acme-tenant",
      role: "system_admin",
    });

    const req = new Request("http://localhost:3000/api/test", {
      headers: { cookie: `shielddesk_session=${validToken}` },
    });

    const session = await getSessionFromRequest(req);
    assert.ok(session, "Valid signed session must be accepted");
    assert.equal(session.uid, "usr-soc-verified");
    assert.equal(session.tenantId, "acme-tenant");
    assert.equal(session.role, "system_admin");
  });

  // -------------------------------------------------------------------------
  // S3: Password Verification & Elimination of Demo Split Fallback
  // -------------------------------------------------------------------------
  await t.test("S3: Password hashing and timing-safe verification", async () => {
    const password = "SuperSecretSecOpsPassword#2026";
    const hashed = await hashPassword(password);

    assert.ok(hashed.includes(":"), "Hash must contain salt delimiter");
    const isMatch = await verifyPassword(password, hashed);
    assert.equal(isMatch, true, "Correct password must verify");

    const isWrongMatch = await verifyPassword("WrongPassword123!", hashed);
    assert.equal(isWrongMatch, false, "Incorrect password must be rejected");
  });

  await t.test("S3: Local login rejects unseeded/unregistered email without falling back", async () => {
    const req = new NextRequest("http://localhost:3000/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        email: "nonexistent.analyst@example.com",
        password: "anyRandomPassword!",
      }),
    });

    const res = await loginPOST(req);
    // Must return 401 Unauthorized or 503 if offline db, NEVER 200 with demo user
    assert.notEqual(res.status, 200, "Unregistered user must never succeed via demo fallback");
    assert.ok([401, 503].includes(res.status));
  });

  // -------------------------------------------------------------------------
  // S4: getSessionUser() and All Protected Routes Fail Closed (401 Unauthorized)
  // -------------------------------------------------------------------------
  await t.test("S4: getSessionUser() returns null when no credentials are provided", async () => {
    const emptyReq = new Request("http://localhost:3000/api/fleet");
    const user = await getSessionUser(emptyReq);
    assert.equal(user, null, "Unauthenticated request must return null (fail closed)");
  });

  await t.test("S4: GET /api/fleet returns 401 without session credentials", async () => {
    const req = new NextRequest("http://localhost:3000/api/fleet");
    const res = await fleetGET(req);
    assert.equal(res.status, 401);
  });

  await t.test("S4: GET /api/fleet/[id] returns 401 without session credentials", async () => {
    const req = new NextRequest("http://localhost:3000/api/fleet/FIN-WS-042");
    const res = await fleetIdGET(req, { params: Promise.resolve({ id: "FIN-WS-042" }) });
    assert.equal(res.status, 401);
  });

  await t.test("S4: POST /api/fleet/[id]/command returns 401 without session credentials", async () => {
    const req = new NextRequest("http://localhost:3000/api/fleet/FIN-WS-042/command", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ command: "take_safety_snapshot" }),
    });
    const res = await fleetCommandPOST(req, { params: Promise.resolve({ id: "FIN-WS-042" }) });
    assert.equal(res.status, 401);
  });

  await t.test("S4: POST /api/fleet/kill-switch returns 401 without session credentials", async () => {
    const req = new NextRequest("http://localhost:3000/api/fleet/kill-switch", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agentId: "FIN-WS-042", active: true }),
    });
    const res = await killSwitchPOST(req);
    assert.equal(res.status, 401);
  });

  await t.test("S4: GET /api/compliance returns 401 without session credentials", async () => {
    const req = new NextRequest("http://localhost:3000/api/compliance");
    const res = await complianceGET(req);
    assert.equal(res.status, 401);
  });

  await t.test("S4: GET /api/reports/scorecard returns 401 without session credentials", async () => {
    const req = new NextRequest("http://localhost:3000/api/reports/scorecard");
    const res = await scorecardGET(req);
    assert.equal(res.status, 401);
  });

  // -------------------------------------------------------------------------
  // S6: Ingestion Webhook Hardening
  // -------------------------------------------------------------------------
  await t.test("S6: Ingest returns 503 when server has no configured API key", async () => {
    const origKey = process.env.SHIELDDESK_INGEST_API_KEY;
    const origKeys = process.env.SHIELDDESK_INGEST_API_KEYS;
    delete process.env.SHIELDDESK_INGEST_API_KEY;
    delete process.env.SHIELDDESK_INGEST_API_KEYS;

    try {
      const req = new NextRequest("http://localhost:3000/api/ingest/webhooks", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-shielddesk-api-key": "any-key",
        },
        body: JSON.stringify({ title: "Test Alert" }),
      });
      const res = await ingestPOST(req);
      assert.equal(res.status, 503, "Must fail closed with 503 when unconfigured");
    } finally {
      process.env.SHIELDDESK_INGEST_API_KEY = origKey;
      process.env.SHIELDDESK_INGEST_API_KEYS = origKeys;
    }
  });

  await t.test("S6: Ingest returns 401 with missing or invalid API key", async () => {
    // Missing key
    const missingReq = new NextRequest("http://localhost:3000/api/ingest/webhooks", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ title: "Test Alert" }),
    });
    const missingRes = await ingestPOST(missingReq);
    assert.equal(missingRes.status, 401);

    // Invalid key
    const invalidReq = new NextRequest("http://localhost:3000/api/ingest/webhooks", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-shielddesk-api-key": "incorrect-secret-key-probe",
      },
      body: JSON.stringify({ title: "Test Alert" }),
    });
    const invalidRes = await ingestPOST(invalidReq);
    assert.equal(invalidRes.status, 401);
  });

  await t.test("S6: Ingest rejects cross-tenant spoofing when key is tenant-bound", async () => {
    // Key is bound to globex-tenant, but caller attempts to inject into acme-tenant
    const spoofReq = new NextRequest("http://localhost:3000/api/ingest/webhooks", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-shielddesk-api-key": "test-globex-ingest-key",
        "x-shielddesk-tenant": "acme-tenant", // Cross-tenant spoofing attempt
      },
      body: JSON.stringify({ title: "Cross Tenant Attack" }),
    });

    const res = await ingestPOST(spoofReq);
    assert.equal(res.status, 403, "Must reject cross-tenant spoofing with 403 Forbidden");
  });
});
