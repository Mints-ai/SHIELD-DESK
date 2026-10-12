import "./setup";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import {
  isProduction,
  isDemoMode,
  shouldFailClosed,
  isDevPersonaAllowed,
  getAppEnvironment,
} from "../src/lib/config/environment";
import { GET as scansGET, POST as scansPOST } from "../src/app/api/scans/route";
import { GET as threatsGET, POST as threatsPOST } from "../src/app/api/threats/route";
import { POST as loginPOST } from "../src/app/api/auth/login/route";
import { createSessionToken } from "../src/lib/auth/token";

describe("Sprint 1: Environment Safety Boundary & Fail-Closed Suite", () => {
  it("Environment: Correctly determines default demo mode in dev/test", () => {
    assert.equal(isProduction(), false);
    assert.equal(isDemoMode(), true);
    assert.equal(shouldFailClosed(), false);
    assert.equal(isDevPersonaAllowed(), true);
  });

  it("Environment: Strict fail-closed policy when APP_ENV=production and DEMO_MODE=false", () => {
    const origAppEnv = process.env.APP_ENV;
    const origDemoMode = process.env.DEMO_MODE;

    try {
      process.env.APP_ENV = "production";
      process.env.DEMO_MODE = "false";

      assert.equal(isProduction(), true);
      assert.equal(isDemoMode(), false);
      assert.equal(shouldFailClosed(), true);
      assert.equal(isDevPersonaAllowed(), false);
      assert.equal(getAppEnvironment(), "production");
    } finally {
      process.env.APP_ENV = origAppEnv;
      process.env.DEMO_MODE = origDemoMode;
    }
  });

  it("Scans API: Fails closed with 503 in production when scan service is offline", async () => {
    const origAppEnv = process.env.APP_ENV;
    const origDemoMode = process.env.DEMO_MODE;

    try {
      process.env.APP_ENV = "production";
      process.env.DEMO_MODE = "false";

      const token = createSessionToken({
        uid: "usr-admin-01",
        tenantId: "acme-tenant",
        role: "system_admin",
      });

      const req = new NextRequest("http://localhost:3000/api/scans", {
        headers: {
          authorization: `Bearer ${token}`,
        },
      });

      const res = await scansGET(req);
      assert.equal(res.status, 503, "Must return 503 Service Unavailable when scanner is offline in prod");
      const data = await res.json();
      assert.equal(data.code, "FAIL_CLOSED_DEPENDENCY_OFFLINE");
      assert.equal(data.metrics.totalVulnerabilities, 0, "Must not return fake demo counts in production offline state");
    } finally {
      process.env.APP_ENV = origAppEnv;
      process.env.DEMO_MODE = origDemoMode;
    }
  });

  it("Scans API: Rejects apply_patch in production with 503 when remote daemon is offline", async () => {
    const origAppEnv = process.env.APP_ENV;
    const origDemoMode = process.env.DEMO_MODE;

    try {
      process.env.APP_ENV = "production";
      process.env.DEMO_MODE = "false";

      const token = createSessionToken({
        uid: "usr-admin-01",
        tenantId: "acme-tenant",
        role: "system_admin",
      });

      const req = new NextRequest("http://localhost:3000/api/scans", {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          action: "apply_patch",
          asset_ip: "10.0.4.12",
        }),
      });

      const res = await scansPOST(req);
      assert.equal(res.status, 503, "Patching must fail closed when daemon is offline");
      const data = await res.json();
      assert.equal(data.code, "FAIL_CLOSED_DEPENDENCY_OFFLINE");
      assert.notEqual(data.status, "PATCH_APPLIED_AND_VERIFIED", "Must never claim patch applied without live daemon");
    } finally {
      process.env.APP_ENV = origAppEnv;
      process.env.DEMO_MODE = origDemoMode;
    }
  });

  it("Threats API: Blocks synthetic anomaly burst simulation in production mode", async () => {
    const origAppEnv = process.env.APP_ENV;
    const origDemoMode = process.env.DEMO_MODE;

    try {
      process.env.APP_ENV = "production";
      process.env.DEMO_MODE = "false";

      const token = createSessionToken({
        uid: "usr-admin-01",
        tenantId: "acme-tenant",
        role: "system_admin",
      });

      const req = new NextRequest("http://localhost:3000/api/threats", {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ action: "simulate_burst" }),
      });

      const res = await threatsPOST(req);
      assert.equal(res.status, 403, "Burst simulation must be prohibited in production");
    } finally {
      process.env.APP_ENV = origAppEnv;
      process.env.DEMO_MODE = origDemoMode;
    }
  });

  it("Login API: Strictly rejects dev-persona switching when APP_ENV=production", async () => {
    const origAppEnv = process.env.APP_ENV;
    const origDemoMode = process.env.DEMO_MODE;

    try {
      process.env.APP_ENV = "production";
      process.env.DEMO_MODE = "false";

      const req = new NextRequest("http://localhost:3000/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ userId: "dev-admin" }),
      });

      const res = await loginPOST(req);
      assert.equal(res.status, 401, "Dev personas must be strictly rejected in production");
      const data = await res.json();
      assert.match(data.error, /disabled in production/i);
    } finally {
      process.env.APP_ENV = origAppEnv;
      process.env.DEMO_MODE = origDemoMode;
    }
  });

  it("ClosedLoop: Rejects mock evidence overrides when running in production mode", async () => {
    const origAppEnv = process.env.APP_ENV;
    const origDemoMode = process.env.DEMO_MODE;
    const { resetConfig } = await import("../src/config");

    try {
      process.env.APP_ENV = "production";
      process.env.DEMO_MODE = "false";
      resetConfig();

      const { ClosedLoopOrchestrator } = await import("../src/lib/orchestration/closedLoopPipeline");

      await assert.rejects(
        async () => {
          await ClosedLoopOrchestrator.execute({
            tenantId: "acme-tenant",
            incidentId: "inc-prod-safety",
            agentId: "ea111111-1111-1111-1111-111111111111",
            action: "block_ip 198.51.100.4",
            caller: { id: "usr-admin-01", tenant_id: "acme-tenant", role: "super_admin" },
            parameters: {
              evidenceOverride: { networkIsolated: true },
            },
          });
        },
        /Mock evidence overrides are strictly prohibited in production execution/
      );
    } finally {
      process.env.APP_ENV = origAppEnv;
      process.env.DEMO_MODE = origDemoMode;
      resetConfig();
    }
  });

  it("RollbackEngine: Returns ROLLBACK_BLOCKED when agent kill switch is active", async () => {
    const { RollbackEngine } = await import("../src/lib/rollback-engine");
    const { MOCK_ENDPOINT_AGENTS } = await import("../src/lib/fleet/fleet");

    const targetAgent = MOCK_ENDPOINT_AGENTS.find((a) => a.id === "ea111111-1111-1111-1111-111111111111");
    if (targetAgent) targetAgent.kill_switch_active = true;

    try {
      const res = await RollbackEngine.executeRollback({
        tenantId: "acme-tenant",
        agentId: "ea111111-1111-1111-1111-111111111111",
        commandId: "cmd-test-kill",
        snapshotId: "snap-test-kill",
        rollbackType: "network_rollback",
        reason: "Test kill switch blockage",
        actorId: "usr-admin-01",
      });

      assert.equal(res.success, false);
      assert.equal(res.status, "ROLLBACK_BLOCKED");
      assert.equal(res.error, "KILL_SWITCH_ACTIVE");
    } finally {
      if (targetAgent) targetAgent.kill_switch_active = false;
    }
  });
});

