import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { createSessionToken } from "@/lib/auth/token";
import { POST as enrollmentTokensPOST } from "@/app/api/fleet/enrollment-tokens/route";
import { POST as enrollPOST } from "@/app/api/agent/enroll/route";
import { POST as heartbeatPOST } from "@/app/api/agent/heartbeat/route";
import { POST as telemetryPOST } from "@/app/api/agent/telemetry/route";
import { triggerKillSwitch } from "@/lib/fleet/fleet";

test("ShieldDesk Phase 2: Endpoint Enrollment, Identity, Heartbeat & Telemetry Suite", async (t) => {
  const adminToken = createSessionToken({
    uid: "usr-admin-01",
    email: "admin@acme.corp",
    tenantId: "acme-tenant",
    role: "system_admin",
  });

  const analystToken = createSessionToken({
    uid: "usr-analyst-01",
    email: "analyst@acme.corp",
    tenantId: "acme-tenant",
    role: "user",
  });

  let validRawToken = "";

  await t.test("SD-006: Non-admin cannot generate enrollment tokens (403 Forbidden)", async () => {
    const req = new NextRequest("http://localhost:3000/api/fleet/enrollment-tokens", {
      method: "POST",
      headers: {
        authorization: `Bearer ${analystToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ label: "Analyst unauthorized attempt" }),
    });

    const res = await enrollmentTokensPOST(req);
    assert.equal(res.status, 403, "Non-admin role must be rejected with 403");
  });

  await t.test("SD-006: System Admin generates valid short-lived enrollment token", async () => {
    const req = new NextRequest("http://localhost:3000/api/fleet/enrollment-tokens", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        label: "Linux Workstation Deployment Batch",
        expiresInHours: 12,
        maxUses: 1,
      }),
    });

    const res = await enrollmentTokensPOST(req);
    assert.equal(res.status, 200, "Admin must generate token successfully");
    const data = await res.json();
    assert.equal(data.success, true);
    assert.ok(data.token.startsWith("sdt_"), "Token must start with sdt_ prefix");
    assert.equal(data.tenantId, "acme-tenant");
    validRawToken = data.token;
  });

  let enrolledAgentId = "";

  await t.test("SD-007: Endpoint rejects forged or invalid enrollment token (401)", async () => {
    const req = new NextRequest("http://localhost:3000/api/agent/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        token: "sdt_invalid_or_forged_token_payload",
        hostname: "SRV-TEST-01",
        osType: "linux",
      }),
    });

    const res = await enrollPOST(req);
    assert.equal(res.status, 401, "Invalid token must return 401");
  });

  await t.test("SD-007: Endpoint successfully enrolls and binds to tenant using valid token", async () => {
    const req = new NextRequest("http://localhost:3000/api/agent/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        token: validRawToken,
        hostname: "SRV-PROD-WORKER-09",
        ipAddress: "10.0.15.99",
        osType: "linux",
        agentVersion: "0.4.2",
      }),
    });

    const res = await enrollPOST(req);
    assert.equal(res.status, 200, "Valid token must enroll successfully");
    const data = await res.json();
    assert.equal(data.success, true);
    assert.equal(data.tenantId, "acme-tenant");
    assert.ok(data.agentId, "Must return unique agentId");
    enrolledAgentId = data.agentId;
  });

  await t.test("SD-006: Reused single-use enrollment token is strictly rejected (Anti-replay)", async () => {
    const req = new NextRequest("http://localhost:3000/api/agent/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        token: validRawToken,
        hostname: "SRV-ROGUE-02",
        osType: "linux",
      }),
    });

    const res = await enrollPOST(req);
    assert.equal(res.status, 401, "Reused single-use token must be rejected");
  });

  await t.test("SD-011: Enrolled agent reports live heartbeat and telemetry statistics", async () => {
    const req = new NextRequest("http://localhost:3000/api/agent/heartbeat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId: enrolledAgentId,
        cpuUsage: 14.8,
        memoryUsage: 52.3,
        eps: 120,
      }),
    });

    const res = await heartbeatPOST(req);
    assert.equal(res.status, 200, "Heartbeat must be accepted");
    const data = await res.json();
    assert.equal(data.success, true);
    assert.equal(data.killSwitchActive, false);
  });

  await t.test("SD-014 / SD-016: Enrolled agent streams batch telemetry events to control plane", async () => {
    const req = new NextRequest("http://localhost:3000/api/agent/telemetry", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId: enrolledAgentId,
        events: [
          {
            eventType: "PROCESS_START",
            payload: { pid: 4921, name: "nginx", user: "www-data" },
            timestamp: new Date().toISOString(),
          },
          {
            eventType: "NETWORK_CONNECT",
            payload: { dest_ip: "10.0.4.10", dest_port: 5432, protocol: "tcp" },
            timestamp: new Date().toISOString(),
          },
        ],
      }),
    });

    const res = await telemetryPOST(req);
    assert.equal(res.status, 200, "Telemetry batch must be ingested");
    const data = await res.json();
    assert.equal(data.success, true);
    assert.equal(data.ingested, 2);
    assert.equal(data.tenantId, "acme-tenant");
  });

  await t.test("SD-025: Heartbeat reflects Emergency Admin Kill Switch (423 Locked)", async () => {
    // Engage kill switch for the enrolled agent
    await triggerKillSwitch({
      agentId: enrolledAgentId,
      active: true,
      caller: {
        id: "usr-admin-01",
        tenant_id: "acme-tenant",
        role: "system_admin",
      },
    });

    const req = new NextRequest("http://localhost:3000/api/agent/heartbeat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId: enrolledAgentId,
        cpuUsage: 12.0,
        memoryUsage: 45.0,
        eps: 0,
      }),
    });

    const res = await heartbeatPOST(req);
    assert.equal(res.status, 423, "Heartbeat for kill-switched agent must return 423 Locked");
    const data = await res.json();
    assert.equal(data.killSwitchActive, true);
  });
});
