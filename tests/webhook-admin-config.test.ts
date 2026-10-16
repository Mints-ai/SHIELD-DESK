import { describe, it } from "node:test";
import assert from "node:assert";
import { NextRequest } from "next/server";
import { GET, POST, PATCH, DELETE } from "@/app/api/webhooks/route";

describe("Dynamic Webhook Endpoints & Admin RBAC Configuration Suite", () => {
  let createdEndpointId = "";

  it("Step 1: Rejects endpoint creation from Analyst persona with 403 Forbidden", async () => {
    const req = new NextRequest("http://localhost:3000/api/webhooks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-analyst",
      },
      body: JSON.stringify({
        action: "create_endpoint",
        name: "Unauthorized Analyst Webhook",
        type: "generic",
        destination: "https://siem.enterprise.corp/events",
      }),
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.match(body.error, /Forbidden/i);
  });

  it("Step 2: Rejects endpoint creation from Responder persona with 403 Forbidden", async () => {
    const req = new NextRequest("http://localhost:3000/api/webhooks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-responder",
      },
      body: JSON.stringify({
        action: "create_endpoint",
        name: "Unauthorized Responder Webhook",
        type: "slack",
        destination: "https://hooks.slack.com/services/T00/B00/X00",
      }),
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 403);
    const body = await res.json();
    assert.match(body.error, /Forbidden/i);
  });

  it("Step 3: Rejects destination with cloud metadata service (SSRF Protection)", async () => {
    const req = new NextRequest("http://localhost:3000/api/webhooks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-admin",
      },
      body: JSON.stringify({
        action: "create_endpoint",
        name: "SSRF Attack Simulation",
        type: "generic",
        destination: "http://169.254.169.254/latest/meta-data",
      }),
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.match(body.error, /metadata|SSRF/i);
  });

  it("Step 4: System Admin successfully creates dynamic custom webhook endpoint", async () => {
    const req = new NextRequest("http://localhost:3000/api/webhooks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-admin",
      },
      body: JSON.stringify({
        action: "create_endpoint",
        name: "SOC PagerDuty Escalation",
        type: "generic",
        destination: "https://events.pagerduty.com/v2/enqueue",
        events: ["threat_detected", "lockdown.activated"],
        min_severity: "critical",
      }),
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.success, true);
    assert.ok(body.endpoint.id.startsWith("wh_"));
    assert.strictEqual(body.endpoint.name, "SOC PagerDuty Escalation");
    assert.strictEqual(body.endpoint.min_severity, "critical");
    assert.strictEqual(body.endpoint.enabled, true);
    // Destination URL must be masked in response
    assert.ok(body.endpoint.destination.includes("***"));

    createdEndpointId = body.endpoint.id;
  });

  it("Step 5: Super Admin successfully creates a second custom Slack endpoint", async () => {
    const req = new NextRequest("http://localhost:3000/api/webhooks", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-super",
      },
      body: JSON.stringify({
        action: "create_endpoint",
        name: "Enterprise SecOps Slack Bridge",
        type: "slack",
        destination: "https://hooks.slack.com/services/T111/B222/Z333",
        events: ["approval_required"],
        min_severity: "high",
      }),
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.success, true);
  });

  it("Step 6: GET /api/webhooks reflects custom endpoints with masked destinations and RBAC flags", async () => {
    // Admin request
    const adminReq = new NextRequest("http://localhost:3000/api/webhooks", {
      headers: { "X-ShieldDesk-User": "dev-admin" },
    });
    const adminRes = await GET(adminReq);
    assert.strictEqual(adminRes.status, 200);
    const adminBody = await adminRes.json();
    assert.strictEqual(adminBody.can_manage_webhooks, true);
    const customEp = adminBody.endpoints.find((ep: { id: string }) => ep.id === createdEndpointId);
    assert.ok(customEp, "Created endpoint must appear in GET listing");
    assert.strictEqual(customEp.name, "SOC PagerDuty Escalation");

    // Analyst request
    const analystReq = new NextRequest("http://localhost:3000/api/webhooks", {
      headers: { "X-ShieldDesk-User": "dev-analyst" },
    });
    const analystRes = await GET(analystReq);
    assert.strictEqual(analystRes.status, 200);
    const analystBody = await analystRes.json();
    assert.strictEqual(analystBody.can_manage_webhooks, false, "Analyst should not have management permission");
  });

  it("Step 7: PATCH /api/webhooks toggles endpoint enabled state (Admin only)", async () => {
    // Analyst tries to toggle (should fail)
    const unauthorizedReq = new NextRequest("http://localhost:3000/api/webhooks", {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-analyst",
      },
      body: JSON.stringify({ id: createdEndpointId, enabled: false }),
    });
    const unauthRes = await PATCH(unauthorizedReq);
    assert.strictEqual(unauthRes.status, 403);

    // Admin toggles (should succeed)
    const adminReq = new NextRequest("http://localhost:3000/api/webhooks", {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "X-ShieldDesk-User": "dev-admin",
      },
      body: JSON.stringify({ id: createdEndpointId, enabled: false }),
    });
    const adminRes = await PATCH(adminReq);
    assert.strictEqual(adminRes.status, 200);
    const adminBody = await adminRes.json();
    assert.strictEqual(adminBody.success, true);
    assert.strictEqual(adminBody.endpoint.enabled, false);
  });

  it("Step 8: DELETE /api/webhooks removes custom endpoint (Admin only)", async () => {
    // Analyst tries to delete
    const unauthReq = new NextRequest(`http://localhost:3000/api/webhooks?id=${createdEndpointId}`, {
      method: "DELETE",
      headers: { "X-ShieldDesk-User": "dev-analyst" },
    });
    const unauthRes = await DELETE(unauthReq);
    assert.strictEqual(unauthRes.status, 403);

    // Admin deletes
    const adminReq = new NextRequest(`http://localhost:3000/api/webhooks?id=${createdEndpointId}`, {
      method: "DELETE",
      headers: { "X-ShieldDesk-User": "dev-admin" },
    });
    const adminRes = await DELETE(adminReq);
    assert.strictEqual(adminRes.status, 200);
    const adminBody = await adminRes.json();
    assert.strictEqual(adminBody.success, true);

    // Verify it is gone
    const checkReq = new NextRequest("http://localhost:3000/api/webhooks", {
      headers: { "X-ShieldDesk-User": "dev-admin" },
    });
    const checkRes = await GET(checkReq);
    const checkBody = await checkRes.json();
    const stillExists = checkBody.endpoints.some((ep: { id: string }) => ep.id === createdEndpointId);
    assert.strictEqual(stillExists, false, "Endpoint must no longer exist after deletion");
  });
});
