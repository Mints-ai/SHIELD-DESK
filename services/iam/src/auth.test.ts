import test from "node:test";
import assert from "node:assert/strict";
import {
  signAccessToken,
  verifyAccessToken,
  hashPassword,
  comparePassword,
  issueAgentToken,
  validateAgentToken,
  generateMfaSetup,
  verifyMfaToken,
} from "./auth.js";

test("IAM Auth Suite: Password hashing and comparison", async () => {
  const password = "SuperSecretPassword123!";
  const hash = await hashPassword(password);
  assert.notEqual(hash, password, "Password must be hashed");

  const isMatch = await comparePassword(password, hash);
  assert.equal(isMatch, true, "Valid password must compare successfully");

  const isWrongMatch = await comparePassword("WrongPassword!", hash);
  assert.equal(isWrongMatch, false, "Invalid password must fail comparison");
});

test("IAM Auth Suite: JWT Access Token generation & claim validation", () => {
  const payload = {
    sub: "u1111111-1111-1111-1111-111111111111",
    tenant_id: "acme_tenant",
    role: "admin" as const,
    mfa: true,
  };

  const token = signAccessToken(payload);
  assert.ok(typeof token === "string" && token.length > 20, "Token must be a valid JWT string");

  const verified = verifyAccessToken(token);
  assert.equal(verified.sub, payload.sub, "Subject must match");
  assert.equal(verified.tenant_id, payload.tenant_id, "Tenant ID must match");
  assert.equal(verified.role, payload.role, "Role must match");
  assert.equal(verified.mfa, true, "MFA flag must match");
});

test("IAM Auth Suite: Agent token issuance and Redis cache validation", async () => {
  const tenantId = "ten_shieldcorp_99";
  const token = await issueAgentToken(tenantId);

  assert.ok(token.startsWith("agt_"), "Agent token must have 'agt_' prefix");

  const resolvedTenant = await validateAgentToken(token);
  assert.equal(resolvedTenant, tenantId, "Agent token must resolve to correct tenant ID");

  const invalidTenant = await validateAgentToken("agt_nonexistent_token");
  assert.equal(invalidTenant, null, "Invalid agent token must resolve to null");
});

test("IAM Auth Suite: TOTP MFA Secret & Token Verification", async () => {
  const { secret, qrCodeUrl } = await generateMfaSetup("analyst@acme.corp");

  assert.ok(secret && secret.length >= 16, "MFA secret must be valid base32 string");
  assert.ok(qrCodeUrl.startsWith("data:image/png;base64,"), "QR code must be a data URL");
});
