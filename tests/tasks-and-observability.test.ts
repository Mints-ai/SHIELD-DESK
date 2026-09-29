import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { GET as getTasks, POST as postTasks } from "@/app/api/tasks/route";
import { GET as getPlans } from "@/app/api/plans/route";
import { trackError } from "@/lib/observability/errorTracker";
import { createSessionToken } from "@/lib/auth/token";

test("Tasks & Observability Integration Suite", async (t) => {
  await t.test("GET /api/tasks: Returns 401 when unauthenticated", async () => {
    const req = new NextRequest("http://localhost:3000/api/tasks");
    const res = await getTasks(req);
    assert.equal(res.status, 401);
    const body = await res.json();
    assert.equal(body.error, "Unauthorized");
  });

  await t.test("GET /api/tasks: Returns Acme tenant tasks for authenticated analyst", async () => {
    const req = new NextRequest("http://localhost:3000/api/tasks", {
      headers: { "X-ShieldDesk-User": "dev-analyst" },
    });
    const res = await getTasks(req);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(Array.isArray(body.tasks));
    assert.equal(body.tenantId, "acme-tenant");
  });

  await t.test("GET /api/tasks: Cross-tenant isolation returns empty board for Globex tenant", async () => {
    const req = new NextRequest("http://localhost:3000/api/tasks", {
      headers: { "X-ShieldDesk-User": "dev-other" },
    });
    const res = await getTasks(req);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.tenantId, "globex-tenant");
    assert.equal(body.tasks.length, 0);
  });

  await t.test("POST /api/tasks: Blocks viewer role with 403 Forbidden", async () => {
    const viewerToken = createSessionToken({
      uid: "usr-viewer-01",
      tenantId: "acme-tenant",
      role: "viewer",
    });
    const req = new NextRequest("http://localhost:3000/api/tasks", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${viewerToken}`,
      },
      body: JSON.stringify({
        title: "Unauthorized firewall change",
        tier: "Tier 2",
      }),
    });
    const res = await postTasks(req);
    assert.equal(res.status, 403);
    const body = await res.json();
    assert.ok(body.error.includes("Insufficient permissions"));
  });

  await t.test("POST /api/tasks: Analyst successfully drafts a new Tier 2 task", async () => {
    const req = new NextRequest("http://localhost:3000/api/tasks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-analyst",
      },
      body: JSON.stringify({
        title: "Quarantine suspicious endpoint MAC",
        tier: "Tier 2",
        horizon: "immediate",
        blastRadius: "Host Scope",
      }),
    });
    const res = await postTasks(req);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.success);
    assert.equal(body.task.title, "Quarantine suspicious endpoint MAC");
    assert.equal(body.task.tier, "Tier 2");
  });

  await t.test("GET /api/plans: Returns 401 when unauthenticated", async () => {
    const req = new NextRequest("http://localhost:3000/api/plans");
    const res = await getPlans(req);
    assert.equal(res.status, 401);
  });

  await t.test("GET /api/plans: Returns tenant mitigation plans for authenticated user", async () => {
    const req = new NextRequest("http://localhost:3000/api/plans", {
      headers: { "X-ShieldDesk-User": "dev-analyst" },
    });
    const res = await getPlans(req);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(Array.isArray(body.plans));
    assert.equal(body.tenantId, "acme-tenant");
  });

  await t.test("trackError: Emits error ID and captures exception without throwing", () => {
    const testError = new Error("Simulated production runtime exception");
    const errorId = trackError(testError, {
      endpoint: "/api/test",
      tenantId: "acme-tenant",
      userId: "usr-test-123",
      extra: { testPayload: true },
    });
    assert.ok(errorId.startsWith("err_"));
  });
});
