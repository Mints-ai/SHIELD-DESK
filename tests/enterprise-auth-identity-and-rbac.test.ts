import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
  rotateRefreshToken,
  generateApiKey,
  verifyApiKey,
  revokeApiKey,
  resolveTenantSsoConfig,
  processSsoCallback,
  scimCreateUser,
  scimUpdateUser,
  scimDeprovisionUser,
  scimGetUser,
} from "../src/lib/auth";
import { canAccess } from "../src/lib/permissions";

test("ShieldDesk Phase 4: Enterprise Identity, Auth & RBAC Hardening", async (t) => {
  await t.test("Short-Lived Access Tokens & Refresh Token Rotation", () => {
    const user = {
      uid: "usr-secops-44",
      tenantId: "acme-tenant",
      role: "analyst" as const,
    };

    // 1. Generate 15-minute access token
    const accessToken = createAccessToken(user, 900);
    assert.ok(accessToken.includes("."), "Access token must be signed JWT/HMAC token");

    // 2. Generate long-lived refresh token
    const { token: refresh1, familyId } = createRefreshToken(user);
    assert.ok(refresh1);
    assert.ok(familyId);

    const verified = verifyRefreshToken(refresh1);
    assert.ok(verified);
    assert.equal(verified?.uid, "usr-secops-44");
    assert.equal(verified?.familyId, familyId);

    // 3. Normal rotation: yields new access token and fresh refresh token
    const rotation1 = rotateRefreshToken(refresh1);
    assert.ok(rotation1);
    assert.ok(rotation1.accessToken);
    assert.ok(rotation1.refreshToken);
    assert.notEqual(rotation1.refreshToken, refresh1, "Rotated refresh token must be a fresh string");

    // 4. Replay Attack Detection: Attempting to reuse old refresh1 MUST fail and revoke family
    const replayAttempt = rotateRefreshToken(refresh1);
    assert.equal(replayAttempt, null, "Consumed refresh token must be rejected");

    // 5. Subsequent attempts with tokens from the revoked family are now blocked
    const subsequentAttempt = rotateRefreshToken(rotation1.refreshToken);
    assert.equal(subsequentAttempt, null, "Revoked token family must reject all child tokens");
  });

  await t.test("Hashed API Key Management: Scopes, Expiration & Revocation", () => {
    // 1. Generate API Key with live prefix
    const { rawKey, keyRecord } = generateApiKey({
      tenantId: "acme-tenant",
      name: "SIEM Ingestion Connector",
      scopes: ["incident.read", "incident.investigate"],
      mode: "live",
      expiresInDays: 30,
    });

    assert.ok(rawKey.startsWith("sdk_live_"), "Key must have sdk_live_ prefix");
    assert.notEqual(keyRecord.key_hash, rawKey, "Raw key must NEVER be stored; only SHA-256 hash");
    assert.equal(keyRecord.key_hash.length, 64, "Key hash must be 64-char SHA-256 hex string");

    // 2. Verification with valid key and allowed scope
    const verifySuccess = verifyApiKey(rawKey, "incident.read");
    assert.equal(verifySuccess.valid, true);
    assert.equal(verifySuccess.tenantId, "acme-tenant");

    // 3. Verification failure with missing/unauthorized scope
    const verifyScopeFail = verifyApiKey(rawKey, "cve.mitigate" as any);
    assert.equal(verifyScopeFail.valid, false);
    assert.match(verifyScopeFail.reason || "", /Insufficient API key scope/);

    // 4. Invalid prefix rejection
    const invalidPrefix = verifyApiKey("invalid_prefix_secret_token", "incident.read");
    assert.equal(invalidPrefix.valid, false);
    assert.match(invalidPrefix.reason || "", /Invalid API key prefix/);

    // 5. Key Revocation
    const revoked = revokeApiKey(keyRecord.id, "acme-tenant");
    assert.equal(revoked, true);

    const verifyRevoked = verifyApiKey(rawKey, "incident.read");
    assert.equal(verifyRevoked.valid, false);
    assert.match(verifyRevoked.reason || "", /revoked/);
  });

  await t.test("Enterprise SSO Configuration & Claims Mapping", () => {
    // 1. Resolve SSO by tenant ID
    const acmeSso = resolveTenantSsoConfig("acme-tenant");
    assert.ok(acmeSso);
    assert.equal(acmeSso?.provider, "okta");
    assert.equal(acmeSso?.enabled, true);

    // 2. Resolve SSO by email domain
    const emailDomainSso = resolveTenantSsoConfig("security.lead@acme.com");
    assert.ok(emailDomainSso);
    assert.equal(emailDomainSso?.tenantId, "acme-tenant");

    // 3. Claims mapping with IdP security groups
    const ssoResult = processSsoCallback({
      tenantId: "acme-tenant",
      email: "security.lead@acme.com",
      externalGroups: ["SecOps-Lead"],
    });

    assert.equal(ssoResult.valid, true);
    assert.equal(ssoResult.role, "super_admin", "SecOps-Lead IdP group should elevate to super_admin");

    // Compliance / Auditor mapping
    const auditorResult = processSsoCallback({
      tenantId: "acme-tenant",
      email: "compliance.officer@acme.com",
      externalGroups: ["Compliance"],
    });
    assert.equal(auditorResult.role, "auditor", "Compliance group should map to auditor role");
  });

  await t.test("SCIM 2.0 User Provisioning & Deprovisioning", () => {
    // 1. Provision user via SCIM
    const newUser = scimCreateUser("acme-tenant", {
      userName: "john.doe@acme.com",
      email: "john.doe@acme.com",
      displayName: "John Doe",
      role: "analyst",
      active: true,
    });

    assert.ok(newUser.id);
    assert.equal(newUser.schemas[0], "urn:ietf:params:scim:schemas:core:2.0:User");
    assert.equal(newUser.active, true);
    assert.equal(newUser.roles?.[0].value, "analyst");

    // 2. Retrieve user
    const retrieved = scimGetUser("acme-tenant", newUser.id);
    assert.equal(retrieved?.userName, "john.doe@acme.com");

    // 3. Update user role
    const updated = scimUpdateUser("acme-tenant", newUser.id, { role: "responder" });
    assert.equal(updated?.roles?.[0].value, "responder");

    // 4. Deprovision user (IdP employee offboarding)
    const deprovisioned = scimDeprovisionUser("acme-tenant", newUser.id);
    assert.equal(deprovisioned, true);

    const postDeprovision = scimGetUser("acme-tenant", newUser.id);
    assert.equal(postDeprovision?.active, false, "Deprovisioned user must have active=false");
  });

  await t.test("Canonical RBAC: Auditor Role Permissions Gate", () => {
    // Auditor can inspect incidents and CVEs
    assert.equal(canAccess("auditor", "incident.read"), true);
    assert.equal(canAccess("auditor", "cve.read"), true);

    // Auditor CANNOT approve remediation tiers
    assert.equal(canAccess("auditor", "approve.tier1"), false);
    assert.equal(canAccess("auditor", "approve.tier2"), false);
    assert.equal(canAccess("auditor", "approve.tier3"), false);

    // Auditor CANNOT manage users
    assert.equal(canAccess("auditor", "MANAGE_USERS"), false);
  });
});
