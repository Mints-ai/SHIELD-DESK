import "./setup";
import { useTaskFixture } from "./fixtures/tasks";
useTaskFixture();
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

  await t.test("GET /api/tasks: Returns Mints Global tenant tasks for authenticated analyst", async () => {
    const req = new NextRequest("http://localhost:3000/api/tasks", {
      headers: { "X-ShieldDesk-User": "dev-analyst" },
    });
    const res = await getTasks(req);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(Array.isArray(body.tasks));
    assert.ok(body.tasks.length > 0);
    assert.ok(body.tasks.every((task: {tenant_id:string}) => task.tenant_id === "mints-global"));
    assert.equal(body.tenantId, "mints-global");
  });

  await t.test("GET /api/tasks: Analyst sees only their own tenant tasks", async () => {
    const req = new NextRequest("http://localhost:3000/api/tasks", {
      headers: { "X-ShieldDesk-User": "dev-analyst" },
    });
    const res = await getTasks(req);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.tenantId, "mints-global");
  });

  await t.test("POST /api/tasks: Blocks viewer role with 403 Forbidden", async () => {
    const viewerToken = createSessionToken({
      uid: "usr-viewer-01",
      tenantId: "acme-tenant",
      role: "analyst",
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

  await t.test("POST /api/tasks: Responder successfully drafts a new Tier 2 task", async () => {
    const req = new NextRequest("http://localhost:3000/api/tasks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-responder",
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

  await t.test("POST /api/tasks: Lower tier employee (responder) CANNOT assign task to higher tier employee (dev-admin)", async () => {
    const req = new NextRequest("http://localhost:3000/api/tasks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-responder",
      },
      body: JSON.stringify({
        title: "Unauthorized assignment to administrator",
        tier: "Tier 2",
        assignedTo: "dev-admin",
      }),
    });
    const res = await postTasks(req);
    assert.equal(res.status, 403);
    const body = await res.json();
    assert.ok(body.error.includes("HIERARCHY_VIOLATION"));
    assert.ok(body.error.includes("Lower tier employee"));
  });

  await t.test("POST /api/tasks: Lower tier employee (responder) CANNOT assign task to higher tier employee (dev-super)", async () => {
    const req = new NextRequest("http://localhost:3000/api/tasks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-responder",
      },
      body: JSON.stringify({
        title: "Unauthorized assignment to super admin",
        tier: "Tier 2",
        assignedTo: "dev-super",
      }),
    });
    const res = await postTasks(req);
    assert.equal(res.status, 403);
    const body = await res.json();
    assert.ok(body.error.includes("HIERARCHY_VIOLATION"));
  });

  await t.test("POST /api/tasks: Employee (responder) CAN assign task to equal or lower tier employee", async () => {
    // 1. Assign to peer responder (same tier)
    const reqPeer = new NextRequest("http://localhost:3000/api/tasks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-responder",
      },
      body: JSON.stringify({
        title: "Peer task assignment",
        tier: "Tier 1",
        assignedTo: "dev-responder",
      }),
    });
    const resPeer = await postTasks(reqPeer);
    assert.equal(resPeer.status, 200);
    const bodyPeer = await resPeer.json();
    assert.equal(bodyPeer.task.assigned_to, "dev-responder");

    // 2. Assign to analyst (lower tier)
    const reqAnalyst = new NextRequest("http://localhost:3000/api/tasks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-responder",
      },
      body: JSON.stringify({
        title: "Delegated triage task",
        tier: "Tier 1",
        assignedTo: "dev-analyst",
      }),
    });
    const resAnalyst = await postTasks(reqAnalyst);
    assert.equal(resAnalyst.status, 200);
    const bodyAnalyst = await resAnalyst.json();
    assert.equal(bodyAnalyst.task.assigned_to, "dev-analyst");
  });

  await t.test("POST /api/tasks: System Admin (highest tier) can assign task to any employee", async () => {
    const req = new NextRequest("http://localhost:3000/api/tasks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-admin",
      },
      body: JSON.stringify({
        title: "Admin dispatched remediation",
        tier: "Tier 3",
        assignedTo: "dev-admin",
      }),
    });
    const res = await postTasks(req);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.task.assigned_to, "dev-admin");
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
    assert.ok(body.plans.length > 0);
    assert.ok(body.plans.every((plan: {tenant_id:string}) => plan.tenant_id === "mints-global"));
    assert.equal(body.tenantId, "mints-global");
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
