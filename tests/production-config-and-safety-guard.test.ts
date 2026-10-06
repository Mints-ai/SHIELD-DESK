import "./setup";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  validateEnvironment,
  assertValidConfiguration,
  ConfigurationValidationError,
  ProductionSafetyGuard,
  SecuritySafetyViolationError,
  reloadConfig,
} from "../src/config";

describe("Phase 1: Production Configuration & Safety Guard Suite", () => {
  it("Config: Validates development environment with safe defaults", () => {
    const config = validateEnvironment({
      APP_ENV: "development",
    });

    assert.equal(config.environment, "development");
    assert.equal(config.isProduction, false);
    assert.equal(config.isDevelopment, true);
    assert.equal(config.demoMode, true);
    assert.equal(config.failClosed, false);
    assert.equal(config.devPersonasAllowed, true);
    assert.equal(config.simulationAllowed, true);
    assert.equal(config.port, 3000);
  });

  it("Config: Validates test environment with explicit overrides", () => {
    const config = validateEnvironment({
      APP_ENV: "test",
      DEMO_MODE: "false",
      FAIL_CLOSED: "true",
      PORT: "4000",
    });

    assert.equal(config.environment, "test");
    assert.equal(config.isTest, true);
    assert.equal(config.demoMode, false);
    assert.equal(config.failClosed, true);
    assert.equal(config.port, 4000);
  });

  it("Config: Production strictly rejects DEMO_MODE=true", () => {
    assert.throws(
      () => {
        assertValidConfiguration({
          APP_ENV: "production",
          DEMO_MODE: "true",
          DATABASE_URL: "postgresql://user:pass@localhost:5432/shielddesk",
          SHIELDDESK_SESSION_SECRET: "a-secure-production-secret-of-at-least-32-chars",
          SHIELDDESK_INGEST_API_KEY: "prod-ingest-api-key-16-chars",
        });
      },
      (err: Error) => {
        assert.ok(err instanceof ConfigurationValidationError);
        assert.match(err.message, /DEMO_MODE=true is strictly forbidden/);
        return true;
      }
    );
  });

  it("Config: Production strictly requires DATABASE_URL", () => {
    assert.throws(
      () => {
        assertValidConfiguration({
          APP_ENV: "production",
          SHIELDDESK_SESSION_SECRET: "a-secure-production-secret-of-at-least-32-chars",
          SHIELDDESK_INGEST_API_KEY: "prod-ingest-api-key-16-chars",
        });
      },
      (err: Error) => {
        assert.ok(err instanceof ConfigurationValidationError);
        assert.match(err.message, /DATABASE_URL is mandatory/);
        return true;
      }
    );
  });

  it("Config: Production strictly requires SHIELDDESK_SESSION_SECRET >= 32 chars", () => {
    assert.throws(
      () => {
        assertValidConfiguration({
          APP_ENV: "production",
          DATABASE_URL: "postgresql://user:pass@localhost:5432/shielddesk",
          SHIELDDESK_SESSION_SECRET: "too-short",
          SHIELDDESK_INGEST_API_KEY: "prod-ingest-api-key-16-chars",
        });
      },
      (err: Error) => {
        assert.ok(err instanceof ConfigurationValidationError);
        assert.match(err.message, /SHIELDDESK_SESSION_SECRET must be at least 32 characters/);
        return true;
      }
    );
  });

  it("Config: Production strictly requires SHIELDDESK_INGEST_API_KEY >= 16 chars", () => {
    assert.throws(
      () => {
        assertValidConfiguration({
          APP_ENV: "production",
          DATABASE_URL: "postgresql://user:pass@localhost:5432/shielddesk",
          SHIELDDESK_SESSION_SECRET: "a-secure-production-secret-of-at-least-32-chars",
          SHIELDDESK_INGEST_API_KEY: "short",
        });
      },
      (err: Error) => {
        assert.ok(err instanceof ConfigurationValidationError);
        assert.match(err.message, /SHIELDDESK_INGEST_API_KEY must be at least 16 characters/);
        return true;
      }
    );
  });

  it("Config: Valid production configuration enforces fail-closed and disables demo/simulation", () => {
    const config = validateEnvironment({
      APP_ENV: "production",
      DATABASE_URL: "postgresql://user:pass@db.internal:5432/shielddesk_prod?sslmode=require",
      SHIELDDESK_SESSION_SECRET: "a-secure-production-secret-of-at-least-32-chars",
      SHIELDDESK_INGEST_API_KEY: "prod-ingest-api-key-16-chars",
    });

    assert.equal(config.isProduction, true);
    assert.equal(config.demoMode, false);
    assert.equal(config.failClosed, true);
    assert.equal(config.simulationAllowed, false);
    assert.equal(config.devPersonasAllowed, false);
    assert.equal(config.database.isConfigured, true);
    assert.equal(config.database.ssl, true);
    assert.equal(config.database.poolMax, 50);
  });

  it("ProductionSafetyGuard: Enforces safety checks and throws SecuritySafetyViolationError in production", () => {
    // Simulate production environment
    reloadConfig({
      APP_ENV: "production",
      DATABASE_URL: "postgresql://user:pass@db.internal:5432/shielddesk_prod",
      SHIELDDESK_SESSION_SECRET: "a-secure-production-secret-of-at-least-32-chars",
      SHIELDDESK_INGEST_API_KEY: "prod-ingest-api-key-16-chars",
    });

    assert.throws(
      () => ProductionSafetyGuard.guardFakeScan("cve_quick_scan"),
      SecuritySafetyViolationError
    );

    assert.throws(
      () => ProductionSafetyGuard.guardSimulatedCommand("network.isolate"),
      SecuritySafetyViolationError
    );

    assert.throws(
      () => ProductionSafetyGuard.guardFakePatch("CVE-2024-1234"),
      SecuritySafetyViolationError
    );

    assert.throws(
      () => ProductionSafetyGuard.guardFakeBilling("acme-tenant"),
      SecuritySafetyViolationError
    );

    assert.throws(
      () => ProductionSafetyGuard.guardFakeLicense("SD-PRO-MOCK-LICENSE"),
      SecuritySafetyViolationError
    );

    assert.throws(
      () => ProductionSafetyGuard.guardDevPersona("dev-admin"),
      SecuritySafetyViolationError
    );

    assert.throws(
      () => ProductionSafetyGuard.assertProductionSafe("sim_isolate_host"),
      SecuritySafetyViolationError
    );

    // Reset back to test environment
    reloadConfig({ APP_ENV: "test" });
  });
});
