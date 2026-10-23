import "./setup";
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  getInternalServiceKey,
  getAdminAssertionSecret,
  resetCachedKeysForTesting,
  createAdminAssertionToken,
  INSECURE_DEV_DEFAULTS,
} from "@/lib/auth/internalKeys";
import { validateEnvironment } from "@/config/schema";

describe("Internal Service Authentication & Administrator Assertion Key Separation Suite", () => {
  const origEnv = { ...process.env };

  beforeEach(() => {
    resetCachedKeysForTesting();
  });

  afterEach(() => {
    process.env = { ...origEnv };
    resetCachedKeysForTesting();
  });

  describe("1. Internal Service Key Validation", () => {
    it("Production: Fails closed when SHIELDDESK_INTERNAL_KEY is missing", () => {
      (process.env as any).NODE_ENV = "production";
      delete process.env.SHIELDDESK_INTERNAL_KEY;

      assert.throws(
        () => getInternalServiceKey(),
        /SHIELDDESK_INTERNAL_KEY must be configured in production/
      );
    });

    it("Production: Fails closed when SHIELDDESK_INTERNAL_KEY is too short (< 32 chars)", () => {
      (process.env as any).NODE_ENV = "production";
      process.env.SHIELDDESK_INTERNAL_KEY = "short_secret_24_chars_only";

      assert.throws(
        () => getInternalServiceKey(),
        /too weak \(minimum 32 characters required in production\)/
      );
    });

    it("Production: Fails closed when SHIELDDESK_INTERNAL_KEY matches known dev defaults", () => {
      (process.env as any).NODE_ENV = "production";
      for (const badSecret of INSECURE_DEV_DEFAULTS) {
        if (!badSecret) continue;
        resetCachedKeysForTesting();
        process.env.SHIELDDESK_INTERNAL_KEY = badSecret;
        assert.throws(
          () => getInternalServiceKey(),
          /Insecure default SHIELDDESK_INTERNAL_KEY detected in production/
        );
      }
    });

    it("Production: Succeeds with high-entropy 32+ char key", () => {
      (process.env as any).NODE_ENV = "production";
      const validKey = "a".repeat(32);
      process.env.SHIELDDESK_INTERNAL_KEY = validKey;

      const key = getInternalServiceKey();
      assert.strictEqual(key, validKey);
    });
  });

  describe("2. Cryptographic Administrator Assertion Secret Separation", () => {
    it("Production: Fails closed when SHIELDDESK_ADMIN_ASSERTION_SECRET is missing", () => {
      (process.env as any).NODE_ENV = "production";
      delete process.env.SHIELDDESK_ADMIN_ASSERTION_SECRET;

      assert.throws(
        () => getAdminAssertionSecret(),
        /SHIELDDESK_ADMIN_ASSERTION_SECRET must be configured in production/
      );
    });

    it("Production: Fails closed when SHIELDDESK_ADMIN_ASSERTION_SECRET is too short (< 32 chars)", () => {
      (process.env as any).NODE_ENV = "production";
      process.env.SHIELDDESK_ADMIN_ASSERTION_SECRET = "short_secret_24_chars_only";

      assert.throws(
        () => getAdminAssertionSecret(),
        /too weak \(minimum 32 characters required in production\)/
      );
    });

    it("Production: Fails closed when SHIELDDESK_ADMIN_ASSERTION_SECRET is identical to SHIELDDESK_INTERNAL_KEY", () => {
      (process.env as any).NODE_ENV = "production";
      const sharedSecret = "x".repeat(40);
      process.env.SHIELDDESK_INTERNAL_KEY = sharedSecret;
      process.env.SHIELDDESK_ADMIN_ASSERTION_SECRET = sharedSecret;

      assert.throws(
        () => getAdminAssertionSecret(),
        /Separate keys are required/
      );
    });

    it("Development: Generates ephemeral secrets dynamically when unset, without shared defaults", () => {
      (process.env as any).NODE_ENV = "development";
      delete process.env.SHIELDDESK_INTERNAL_KEY;
      delete process.env.SHIELDDESK_ADMIN_ASSERTION_SECRET;
      delete process.env.SHIELDDESK_SESSION_SECRET;

      const key = getInternalServiceKey();
      const sec = getAdminAssertionSecret();

      assert.ok(key.length >= 32, "Service key must be at least 32 chars");
      assert.ok(sec.length >= 32, "Assertion secret must be at least 32 chars");
      assert.notStrictEqual(key, sec, "Keys must be distinct");
      assert.strictEqual(INSECURE_DEV_DEFAULTS.has(key), false, "Must not be dev default");
      assert.strictEqual(INSECURE_DEV_DEFAULTS.has(sec), false, "Must not be dev default");
    });
  });

  describe("3. Administrator Assertion Token Generation & Role Gating", () => {
    it("Rejects assertion token creation for non-admin roles", () => {
      assert.throws(
        () =>
          createAdminAssertionToken({
            operatorId: "user-1",
            role: "analyst",
            operation: "intel_sync",
          }),
        /Unauthorized role for administrative assertion: analyst/
      );

      assert.throws(
        () =>
          createAdminAssertionToken({
            operatorId: "user-2",
            role: "responder",
            operation: "intel_sync",
          }),
        /Unauthorized role for administrative assertion: responder/
      );
    });

    it("Generates valid HMAC-SHA256 signed token for system_admin and super_admin", () => {
      const secret = "sd_test_custom_assertion_secret_key_32_chars!";
      const token = createAdminAssertionToken({
        operatorId: "admin-42",
        role: "super_admin",
        operation: "intel_sync",
        targetId: "target-cve-candidate-v1",
        ttlSeconds: 300,
        secret,
      });

      const parts = token.split(".");
      assert.strictEqual(parts.length, 2, "Token must be payload.signature format");

      const [encodedPayload, receivedSig] = parts;
      const expectedSig = crypto
        .createHmac("sha256", secret)
        .update(encodedPayload)
        .digest("base64url");
      assert.strictEqual(receivedSig, expectedSig, "HMAC signature must verify");

      const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf-8"));
      assert.strictEqual(payload.operator_id, "admin-42");
      assert.strictEqual(payload.role, "super_admin");
      assert.strictEqual(payload.operation, "intel_sync");
      assert.strictEqual(payload.target_id, "target-cve-candidate-v1");
      assert.ok(payload.nonce && payload.nonce.length > 10, "Nonce must be present");
      assert.ok(payload.exp > payload.iat, "exp must exceed iat");
    });
  });

  describe("4. Production Schema Consistency (validateEnvironment)", () => {
    it("validateEnvironment enforces key requirements in production", () => {
      const prodEnv = {
        NODE_ENV: "production",
        DATABASE_URL: "postgresql://user:pass@localhost:5432/db",
        SHIELDDESK_SESSION_SECRET: "s".repeat(32),
        SHIELDDESK_INGEST_API_KEY: "i".repeat(20),
        // Missing internal key and assertion secret
      };

      const config = validateEnvironment(prodEnv);
      const errors = config.validationErrors.join("\n");
      assert.ok(
        errors.includes("SHIELDDESK_INTERNAL_KEY must be configured in production"),
        `Expected SHIELDDESK_INTERNAL_KEY error in:\n${errors}`
      );
      assert.ok(
        errors.includes("SHIELDDESK_ADMIN_ASSERTION_SECRET must be configured in production"),
        `Expected SHIELDDESK_ADMIN_ASSERTION_SECRET error in:\n${errors}`
      );
    });

    it("validateEnvironment rejects identical keys in production", () => {
      const sameKey = "k".repeat(36);
      const prodEnv = {
        NODE_ENV: "production",
        DATABASE_URL: "postgresql://user:pass@localhost:5432/db",
        SHIELDDESK_SESSION_SECRET: "s".repeat(32),
        SHIELDDESK_INGEST_API_KEY: "i".repeat(20),
        SHIELDDESK_INTERNAL_KEY: sameKey,
        SHIELDDESK_ADMIN_ASSERTION_SECRET: sameKey,
      };

      const config = validateEnvironment(prodEnv);
      const errors = config.validationErrors.join("\n");
      assert.ok(
        errors.includes("Separate keys are required"),
        `Expected separate keys error in:\n${errors}`
      );
    });
  });
});
