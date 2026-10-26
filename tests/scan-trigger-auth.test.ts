import "./setup";
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { NextRequest } from "next/server";
import { POST as scansPOST } from "../src/app/api/scans/route";
import {
  createAdminAssertionToken,
  resetCachedKeysForTesting,
} from "@/lib/auth/internalKeys";
import { createSessionToken } from "@/lib/auth/token";

const TEST_INTERNAL_KEY = "sd_test_service_key_min_32_characters_long_entropy_secure!";
const TEST_ASSERTION_SECRET = "sd_test_assertion_key_min_32_chars_cryptographically_isolated!";

describe("Task 2: End-to-End Scan Trigger Service Authentication & Authorization", () => {
  const origEnv = { ...process.env };

  beforeEach(() => {
    resetCachedKeysForTesting();
    (process.env as any).NODE_ENV = "production";
    process.env.APP_ENV = "production";
    process.env.DEMO_MODE = "false";
    process.env.SHIELDDESK_INTERNAL_KEY = TEST_INTERNAL_KEY;
    process.env.SHIELDDESK_ADMIN_ASSERTION_SECRET = TEST_ASSERTION_SECRET;
    process.env.SHIELDDESK_SESSION_SECRET = "sd_test_user_session_secret_32_chars_minimum!";
  });

  afterEach(() => {
    process.env = { ...origEnv };
    resetCachedKeysForTesting();
  });

  it("1. Unauthenticated request to POST /api/scans returns 401", async () => {
    const req = new NextRequest("http://localhost:3000/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "cve_scan", target_path: "." }),
    });

    const res = await scansPOST(req);
    assert.strictEqual(res.status, 401);
    const body = await res.json();
    assert.strictEqual(body.error, "Unauthorized");
  });

  it("2. Spoofed X-ShieldDesk-User header without credentials returns 401", async () => {
    const req = new NextRequest("http://localhost:3000/api/scans", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "super_admin",
        "X-ShieldDesk-Operator-Id": "admin-spoofed",
        "X-ShieldDesk-Operator-Role": "super_admin",
      },
      body: JSON.stringify({ action: "cve_scan", target_path: "." }),
    });

    const res = await scansPOST(req);
    assert.strictEqual(res.status, 401, "Arbitrary identity headers must never create a trusted session");
  });

  it("3. Invalid internal service key returns 401", async () => {
    const req = new NextRequest("http://localhost:3000/api/scans", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-Internal-Key": "completely_wrong_service_key_value_32_chars!",
      },
      body: JSON.stringify({ action: "cve_scan", target_path: "." }),
    });

    const res = await scansPOST(req);
    assert.strictEqual(res.status, 401);
    const body = await res.json();
    assert.ok(body.error.includes("Invalid internal service credentials"));
  });

  it("4. Valid service key but missing admin assertion returns 403", async () => {
    const req = new NextRequest("http://localhost:3000/api/scans", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-Internal-Key": TEST_INTERNAL_KEY,
      },
      body: JSON.stringify({ action: "cve_scan", target_path: "." }),
    });

    const res = await scansPOST(req);
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.ok(body.error.includes("Missing administrator cryptographic assertion token"));
  });

  it("5. Valid service key with forged/tampered assertion signature returns 403", async () => {
    const token = createAdminAssertionToken({
      operatorId: "admin-sec-1",
      role: "super_admin",
      operation: "trigger_scan",
      secret: TEST_ASSERTION_SECRET,
    });
    // Tamper with signature
    const parts = token.split(".");
    const tamperedToken = `${parts[0]}.forged_invalid_signature_xyz`;

    const req = new NextRequest("http://localhost:3000/api/scans", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-Internal-Key": TEST_INTERNAL_KEY,
        "X-ShieldDesk-Admin-Assertion": tamperedToken,
      },
      body: JSON.stringify({ action: "cve_scan", target_path: "." }),
    });

    const res = await scansPOST(req);
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.ok(body.error.includes("signature verification failed"));
  });

  it("6. Valid service key with assertion signed with service key (key confusion) returns 403", async () => {
    // Malicious or confused client signs with service key instead of assertion secret
    const keyConfusedToken = createAdminAssertionToken({
      operatorId: "admin-sec-1",
      role: "super_admin",
      operation: "trigger_scan",
      secret: TEST_INTERNAL_KEY, // Wrong key!
    });

    const req = new NextRequest("http://localhost:3000/api/scans", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-Internal-Key": TEST_INTERNAL_KEY,
        "X-ShieldDesk-Admin-Assertion": keyConfusedToken,
      },
      body: JSON.stringify({ action: "cve_scan", target_path: "." }),
    });

    const res = await scansPOST(req);
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.ok(body.error.includes("signature verification failed"));
  });

  it("7. Valid service key with assertion for wrong operation (intel_sync) returns 403", async () => {
    const token = createAdminAssertionToken({
      operatorId: "admin-sec-1",
      role: "super_admin",
      operation: "intel_sync", // Operation mismatch!
      secret: TEST_ASSERTION_SECRET,
    });

    const req = new NextRequest("http://localhost:3000/api/scans", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-Internal-Key": TEST_INTERNAL_KEY,
        "X-ShieldDesk-Admin-Assertion": token,
      },
      body: JSON.stringify({ action: "cve_scan", target_path: "." }),
    });

    const res = await scansPOST(req);
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.ok(body.error.includes("Operation mismatch"));
  });

  it("8. Valid service key and signed trigger_scan assertion authorizes scan execution", async () => {
    const token = createAdminAssertionToken({
      operatorId: "admin-service-operator",
      role: "super_admin",
      operation: "trigger_scan",
      secret: TEST_ASSERTION_SECRET,
    });

    const req = new NextRequest("http://localhost:3000/api/scans", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-Internal-Key": TEST_INTERNAL_KEY,
        "X-ShieldDesk-Admin-Assertion": token,
        "X-ShieldDesk-Tenant-Id": "acme-corp",
      },
      body: JSON.stringify({ action: "cve_scan", target_path: "." }),
    });

    const res = await scansPOST(req);
    // Authenticated and authorized: executes scan logic (either 200 with findings/success or 503 if remote scan daemon offline)
    assert.notStrictEqual(res.status, 401, "Must not return 401 Unauthorized");
    assert.notStrictEqual(res.status, 403, "Must not return 403 Forbidden");
    const body = await res.json();
    assert.ok(res.status === 200 || (res.status === 503 && body.code === "FAIL_CLOSED_DEPENDENCY_OFFLINE"));
  });

  it("9. Ordinary browser request with valid user session continues to authenticate and authorize", async () => {
    const userSessionToken = createSessionToken({
      uid: "usr-sec-analyst-1",
      tenantId: "tenant-globex",
      role: "system_admin",
    });

    const req = new NextRequest("http://localhost:3000/api/scans", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        authorization: `Bearer ${userSessionToken}`,
      },
      body: JSON.stringify({ action: "cve_scan", target_path: "." }),
    });

    const res = await scansPOST(req);
    assert.notStrictEqual(res.status, 401, "User session must be authenticated");
    assert.notStrictEqual(res.status, 403, "Admin user must not be forbidden");
  });
});
