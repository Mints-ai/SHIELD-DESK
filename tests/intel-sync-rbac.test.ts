import "./setup";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { canAccess } from "@/lib/permissions";
import { POST as intelSyncHandler } from "@/app/api/intel/sync/route";

describe("Live Threat Intelligence Synchronization RBAC Suite", () => {
  it("Permission Matrix: intel.sync is strictly granted to system_admin and super_admin", () => {
    assert.strictEqual(canAccess("system_admin", "intel.sync"), true, "system_admin must hold intel.sync");
    assert.strictEqual(canAccess("super_admin", "intel.sync"), true, "super_admin must hold intel.sync");
    assert.strictEqual(canAccess("responder", "intel.sync"), false, "responder must not hold intel.sync");
    assert.strictEqual(canAccess("analyst", "intel.sync"), false, "analyst must not hold intel.sync");
  });

  it("POST /api/intel/sync: Analyst role is rejected with 403 Forbidden", async () => {
    const req = new NextRequest("http://localhost:3000/api/intel/sync", {
      method: "POST",
      headers: {
        "x-shielddesk-user": "dev-analyst",
      },
    });

    const res = await intelSyncHandler(req);
    assert.strictEqual(res.status, 403, "Analyst must receive 403 Forbidden");
    const body = await res.json();
    assert.strictEqual(body.error, "Forbidden");
    assert.ok(body.message.includes("intel.sync"));
  });

  it("POST /api/intel/sync: Responder role is rejected with 403 Forbidden", async () => {
    const req = new NextRequest("http://localhost:3000/api/intel/sync", {
      method: "POST",
      headers: {
        "x-shielddesk-user": "dev-responder",
      },
    });

    const res = await intelSyncHandler(req);
    assert.strictEqual(res.status, 403, "Responder must receive 403 Forbidden");
    const body = await res.json();
    assert.strictEqual(body.error, "Forbidden");
    assert.ok(body.message.includes("intel.sync"));
  });

  it("POST /api/intel/sync: Super Admin passes RBAC authorization gate", async () => {
    const req = new NextRequest("http://localhost:3000/api/intel/sync", {
      method: "POST",
      headers: {
        "x-shielddesk-user": "dev-super-admin",
      },
    });

    const res = await intelSyncHandler(req);
    // Should NOT be 403 Forbidden or 401 Unauthorized — RBAC gate passed
    assert.notStrictEqual(res.status, 403, "Super Admin must not be forbidden (RBAC check passed)");
    assert.notStrictEqual(res.status, 401, "Super Admin must not be unauthorized");
  });

  it("POST /api/intel/sync: System Admin passes RBAC authorization gate", async () => {
    const req = new NextRequest("http://localhost:3000/api/intel/sync", {
      method: "POST",
      headers: {
        "x-shielddesk-user": "dev-system-admin",
      },
    });

    const res = await intelSyncHandler(req);
    // Should NOT be 403 Forbidden or 401 Unauthorized — RBAC gate passed
    assert.notStrictEqual(res.status, 403, "System Admin must not be forbidden (RBAC check passed)");
    assert.notStrictEqual(res.status, 401, "System Admin must not be unauthorized");
  });
});
