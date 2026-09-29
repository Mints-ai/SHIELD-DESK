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
});
