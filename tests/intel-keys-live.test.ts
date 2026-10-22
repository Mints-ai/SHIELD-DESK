import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { GET as shodanGetHandler } from "@/app/api/intel/shodan/route";
import { GET as hibpGetHandler } from "@/app/api/intel/hibp/route";
import {
  GET as keysGetHandler,
  POST as keysPostHandler,
  DELETE as keysDeleteHandler,
} from "@/app/api/integrations/keys/route";
import { getShodanApiKey } from "@/lib/shodan";
import { getHibpApiKey } from "@/lib/hibp";

describe("External Intel Keys & Attack Surface RBAC Suite", () => {
  describe("Authentication Gate", () => {
    test("Unauthenticated requests to intel endpoints reject with 401", async () => {
      const unauthShodan = await shodanGetHandler(new NextRequest("http://localhost:3000/api/intel/shodan"));
      assert.equal(unauthShodan.status, 401);

      const unauthHibp = await hibpGetHandler(new NextRequest("http://localhost:3000/api/intel/hibp"));
      assert.equal(unauthHibp.status, 401);

      const unauthKeys = await keysGetHandler(new NextRequest("http://localhost:3000/api/integrations/keys"));
      assert.equal(unauthKeys.status, 401);

      const unauthKeysPost = await keysPostHandler(new NextRequest("http://localhost:3000/api/integrations/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: "shodan", key: "12345678" }),
      }));
      assert.equal(unauthKeysPost.status, 401);
    });
  });

  describe("RBAC Authorization for External Intel Keys", () => {
    test("GET /api/integrations/keys reports canManage: false for non-admin analysts", async () => {
      const req = new NextRequest("http://localhost:3000/api/integrations/keys", {
        headers: { "X-ShieldDesk-User": "dev-analyst" },
      });
      const res = await keysGetHandler(req);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.canManage, false);
      assert.equal(json.role, "analyst");
    });

    test("GET /api/integrations/keys reports canManage: true for administrators", async () => {
      const req = new NextRequest("http://localhost:3000/api/integrations/keys", {
        headers: { "X-ShieldDesk-User": "dev-admin" },
      });
      const res = await keysGetHandler(req);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.canManage, true);
      assert.equal(json.role, "system_admin");
    });

    test("POST /api/integrations/keys rejects analyst with 403 Forbidden", async () => {
      const req = new NextRequest("http://localhost:3000/api/integrations/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-ShieldDesk-User": "dev-analyst" },
        body: JSON.stringify({
          provider: "shodan",
          key: "test_shodan_key_analyst_attempt",
        }),
      });
      const res = await keysPostHandler(req);
      assert.equal(res.status, 403);
      const json = await res.json();
      assert.ok(json.error.includes("Forbidden"));
      assert.ok(json.error.includes("administrators"));
    });

    test("POST /api/integrations/keys rejects responder with 403 Forbidden", async () => {
      const req = new NextRequest("http://localhost:3000/api/integrations/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-ShieldDesk-User": "dev-responder" },
        body: JSON.stringify({
          provider: "hibp",
          key: "0123456789abcdef0123456789abcdef",
        }),
      });
      const res = await keysPostHandler(req);
      assert.equal(res.status, 403);
      const json = await res.json();
      assert.ok(json.error.includes("Forbidden"));
    });

    test("DELETE /api/integrations/keys rejects analyst with 403 Forbidden", async () => {
      const req = new NextRequest("http://localhost:3000/api/integrations/keys?provider=shodan", {
        method: "DELETE",
        headers: { "X-ShieldDesk-User": "dev-analyst" },
      });
      const res = await keysDeleteHandler(req);
      assert.equal(res.status, 403);
      const json = await res.json();
      assert.ok(json.error.includes("Forbidden"));
    });

    test("POST /api/integrations/keys permits super_admin to configure keys", async () => {
      const req = new NextRequest("http://localhost:3000/api/integrations/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-ShieldDesk-User": "dev-super" },
        body: JSON.stringify({
          provider: "hibp",
          key: "0123456789abcdef0123456789abcdef",
        }),
      });
      const res = await keysPostHandler(req);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.success, true);
      assert.equal(getHibpApiKey(), "0123456789abcdef0123456789abcdef");
    });
  });

  describe("End-to-End Administrator Lifecycle & Live Synchronization", () => {
    test("System Admin configures Shodan key -> reflects immediately in scanner", async () => {
      const saveReq = new NextRequest("http://localhost:3000/api/integrations/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-ShieldDesk-User": "dev-admin" },
        body: JSON.stringify({
          provider: "shodan",
          key: "test_shodan_key_abcdef123456",
        }),
      });
      const saveRes = await keysPostHandler(saveReq);
      assert.equal(saveRes.status, 200);
      const saveJson = await saveRes.json();
      assert.equal(saveJson.success, true);

      // Verify key in lib/shodan
      assert.equal(getShodanApiKey(), "test_shodan_key_abcdef123456");

      // Query /api/intel/shodan
      const intelReq = new NextRequest("http://localhost:3000/api/intel/shodan", {
        headers: { "X-ShieldDesk-User": "dev-admin" },
      });
      const intelRes = await shodanGetHandler(intelReq);
      assert.equal(intelRes.status, 200);
      const intelJson = await intelRes.json();
      assert.equal(intelJson.configured, true);
    });

    test("System Admin removes Shodan key -> reflects immediately in scanner", async () => {
      const delReq = new NextRequest("http://localhost:3000/api/integrations/keys?provider=shodan", {
        method: "DELETE",
        headers: { "X-ShieldDesk-User": "dev-admin" },
      });
      const delRes = await keysDeleteHandler(delReq);
      assert.equal(delRes.status, 200);

      const intelReq = new NextRequest("http://localhost:3000/api/intel/shodan", {
        headers: { "X-ShieldDesk-User": "dev-admin" },
      });
      const intelRes = await shodanGetHandler(intelReq);
      assert.equal(intelRes.status, 200);
      const intelJson = await intelRes.json();
      assert.equal(intelJson.configured, false);
    });
  });
});
