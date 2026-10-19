import "./setup";
import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { GET as sessionGET } from "@/app/api/auth/session/route";
import { POST as rollbackPOST } from "@/app/api/patch/jobs/[id]/rollback/route";
import { createSessionToken } from "@/lib/auth/token";
import { operatorFromSession, SIGNED_OUT_OPERATOR } from "@/lib/auth/operatorIdentity";

describe("Verified operator identity and explicit rollback routing", () => {
  const originalFetch = global.fetch;
  const originalServiceToken = process.env.PATCH_ORCHESTRATOR_API_TOKEN;
  afterEach(() => {
    global.fetch = originalFetch;
    if (originalServiceToken === undefined) delete process.env.PATCH_ORCHESTRATOR_API_TOKEN;
    else process.env.PATCH_ORCHESTRATOR_API_TOKEN = originalServiceToken;
  });
  const cookie = (role: "system_admin" | "analyst" | "responder") => `shielddesk_session=${createSessionToken({ uid: "real-operator-01", tenantId: "real-tenant-01", role })}`;

  it("restores the real administrator role instead of a stale demo Analyst", async () => {
    const response = await sessionGET(new NextRequest("http://localhost/api/auth/session", { headers: { cookie: cookie("system_admin"), "x-shielddesk-user": "dev-analyst" } }));
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.user.id, "real-operator-01");
    assert.equal(body.user.role, "system_admin");
    assert.equal(body.user.tenantId, "real-tenant-01");
    assert.equal(body.devPersonasAllowed, false);
    assert.match(response.headers.get("cache-control") || "", /no-store/);
    assert.equal(body.token, undefined);
  });
  it("does not let a forged demo Admin header elevate a signed-in Analyst", async () => {
    const response = await sessionGET(new NextRequest("http://localhost/api/auth/session", { headers: { cookie: cookie("analyst"), "x-shielddesk-user": "dev-admin" } }));
    assert.equal((await response.json()).user.role, "analyst");
  });
  it("does not treat an unauthenticated persona header as a signed-in user", async () => {
    const response = await sessionGET(new NextRequest("http://localhost/api/auth/session", { headers: { "x-shielddesk-user": "dev-admin" } }));
    assert.equal(response.status, 401);
    assert.equal((await response.json()).user, null);
  });
  it("defaults signed-out or unrecognized roles to read-only presentation", () => {
    assert.equal(SIGNED_OUT_OPERATOR.role, "analyst");
    assert.equal(SIGNED_OUT_OPERATOR.id, "");
    assert.equal(operatorFromSession({ uid: "u", tenantId: "t", role: "__proto__" as "analyst" }).role, "analyst");
  });
  it("forwards a specific rollback job and service token, preserving asynchronous acceptance", async () => {
    process.env.PATCH_ORCHESTRATOR_API_TOKEN = "test-service-token";
    let forwarded = "";
    global.fetch = async (input, init) => {
      forwarded = String(input);
      assert.equal(new Headers(init?.headers).get("authorization"), "Bearer test-service-token");
      assert.equal(init?.method, "POST");
      return new Response(JSON.stringify({ job_id: "job-123", state: "ROLLING_BACK" }), { status: 202 });
    };
    const response = await rollbackPOST(new NextRequest("http://localhost/api/patch/jobs/job-123/rollback", { method: "POST", headers: { cookie: cookie("system_admin") } }), { params: Promise.resolve({ id: "job-123" }) });
    assert.equal(response.status, 202);
    assert.match(forwarded, /\/api\/v1\/jobs\/job-123\/rollback$/);
    assert.equal((await response.json()).state, "ROLLING_BACK");
  });
  it("rejects unauthenticated and tenant-scoped callers without touching the orchestrator", async () => {
    global.fetch = async () => { throw new Error("Orchestrator must not be contacted"); };
    for (const role of [undefined, "analyst", "responder"] as const) {
      const response = await rollbackPOST(new NextRequest("http://localhost/api/patch/jobs/job-123/rollback", { method: "POST", headers: role ? { cookie: cookie(role) } : {} }), { params: Promise.resolve({ id: "job-123" }) });
      assert.equal(response.status, role ? 403 : 401);
    }
  });
  it("rejects the ambiguous latest alias and reports offline services honestly", async () => {
    const request = () => new NextRequest("http://localhost/api/patch/jobs/latest/rollback", { method: "POST", headers: { cookie: cookie("system_admin") } });
    assert.equal((await rollbackPOST(request(), { params: Promise.resolve({ id: "latest" }) })).status, 400);
    global.fetch = async () => { throw new Error("offline"); };
    assert.equal((await rollbackPOST(request(), { params: Promise.resolve({ id: "job-123" }) })).status, 503);
  });
});
