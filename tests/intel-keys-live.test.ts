import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { GET as shodanGetHandler } from "@/app/api/intel/shodan/route";
import { GET as hibpGetHandler } from "@/app/api/intel/hibp/route";
import { POST as keysPostHandler, DELETE as keysDeleteHandler } from "@/app/api/integrations/keys/route";
import { getShodanApiKey } from "@/lib/shodan";
import { getHibpApiKey } from "@/lib/hibp";

describe("External Intel Keys & Attack Surface Synchronization", () => {
  test("Unauthenticated requests to intel endpoints reject with 401", async () => {
    const unauthShodan = await shodanGetHandler(new NextRequest("http://localhost:3000/api/intel/shodan"));
    assert.equal(unauthShodan.status, 401);

    const unauthHibp = await hibpGetHandler(new NextRequest("http://localhost:3000/api/intel/hibp"));
    assert.equal(unauthHibp.status, 401);
  });

  test("Saving Shodan API key via /api/integrations/keys immediately activates Shodan in scanner intel", async () => {
    const saveReq = new NextRequest("http://localhost:3000/api/integrations/keys", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-ShieldDesk-User": "admin" },
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

    // Query /api/intel/shodan from scanner dashboard perspective
    const intelReq = new NextRequest("http://localhost:3000/api/intel/shodan", {
      headers: { "X-ShieldDesk-User": "admin" },
    });
    const intelRes = await shodanGetHandler(intelReq);
    assert.equal(intelRes.status, 200);
    const intelJson = await intelRes.json();
    assert.equal(intelJson.configured, true);
    assert.ok(intelJson.apiInfo);
  });

  test("Saving HIBP API key via /api/integrations/keys immediately activates HIBP in scanner intel", async () => {
    const saveReq = new NextRequest("http://localhost:3000/api/integrations/keys", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-ShieldDesk-User": "admin" },
      body: JSON.stringify({
        provider: "hibp",
        key: "0123456789abcdef0123456789abcdef",
      }),
    });
    const saveRes = await keysPostHandler(saveReq);
    assert.equal(saveRes.status, 200);
    const saveJson = await saveRes.json();
    assert.equal(saveJson.success, true);

    // Verify key in lib/hibp
    assert.equal(getHibpApiKey(), "0123456789abcdef0123456789abcdef");

    // Query /api/intel/hibp from scanner dashboard perspective
    const hibpReq = new NextRequest("http://localhost:3000/api/intel/hibp", {
      headers: { "X-ShieldDesk-User": "admin" },
    });
    const hibpRes = await hibpGetHandler(hibpReq);
    assert.equal(hibpRes.status, 200);
    const hibpJson = await hibpRes.json();
    assert.equal(hibpJson.configured, true);
  });

  test("Deleting Shodan key resets configured state immediately", async () => {
    const delReq = new NextRequest("http://localhost:3000/api/integrations/keys?provider=shodan", {
      method: "DELETE",
      headers: { "X-ShieldDesk-User": "admin" },
    });
    const delRes = await keysDeleteHandler(delReq);
    assert.equal(delRes.status, 200);

    // Query /api/intel/shodan
    const intelReq = new NextRequest("http://localhost:3000/api/intel/shodan", {
      headers: { "X-ShieldDesk-User": "admin" },
    });
    const intelRes = await shodanGetHandler(intelReq);
    assert.equal(intelRes.status, 200);
    const intelJson = await intelRes.json();
    assert.equal(intelJson.configured, false);
  });
});
