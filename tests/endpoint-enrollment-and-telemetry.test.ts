import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { createSessionToken } from "@/lib/auth/token";
import { POST as enrollmentTokensPOST } from "@/app/api/fleet/enrollment-tokens/route";
import { POST as enrollPOST } from "@/app/api/agent/enroll/route";
import { POST as heartbeatPOST } from "@/app/api/agent/heartbeat/route";
import { POST as telemetryPOST } from "@/app/api/agent/telemetry/route";
import { POST as executePOST } from "@/app/api/fleet/execute/route";
import { triggerKillSwitch } from "@/lib/fleet/fleet";
import { issueCommercialLicense } from "@/lib/billing/licenses";
import { isIpBlocked } from "@/lib/alerts/threatAlertStore";

test("ShieldDesk Phase 2: Endpoint Enrollment, Identity, Heartbeat & Telemetry Suite", async (t) => {
  const licenseKey = issueCommercialLicense({ tenantId: "acme-tenant", tier: "professional", maxEndpoints: 100, maxUsers: 20, features: ["endpointFleet"], expiresAt: new Date(Date.now() + 86400000).toISOString() }).rawLicense;
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
    role: "analyst",
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
        installationId: "install-enrollment-test-001",
        licenseKey,
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

  await t.test("SD-026: Disconnected endpoint stays disconnected across incoming heartbeats until explicitly reconnected", async () => {
    // Release kill switch first
    await triggerKillSwitch({
      agentId: enrolledAgentId,
      active: false,
      caller: {
        id: "usr-admin-01",
        tenant_id: "acme-tenant",
        role: "system_admin",
      },
    });

    // Import PATCH from fleet route dynamically
    const { PATCH: fleetPATCH } = await import("@/app/api/fleet/[id]/route");

    // Admin disconnects endpoint
    const disconnectReq = new NextRequest(`http://localhost:3000/api/fleet/${enrolledAgentId}`, {
      method: "PATCH",
      headers: {
        authorization: `Bearer ${adminToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ action: "disconnect" }),
    });
    const disconnectRes = await fleetPATCH(disconnectReq, {
      params: Promise.resolve({ id: enrolledAgentId }),
    });
    assert.equal(disconnectRes.status, 200);

    // Heartbeat comes in from still-running daemon
    const hbReq = new NextRequest("http://localhost:3000/api/agent/heartbeat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId: enrolledAgentId,
        cpuUsage: 25.0,
        memoryUsage: 60.0,
        eps: 50,
      }),
    });
    const hbRes = await heartbeatPOST(hbReq);
    assert.equal(hbRes.status, 200);
    const hbData = await hbRes.json();
    assert.equal(hbData.status, "disconnected", "Endpoint must remain disconnected despite active heartbeat");

    // Admin reconnects endpoint
    const reconnectReq = new NextRequest(`http://localhost:3000/api/fleet/${enrolledAgentId}`, {
      method: "PATCH",
      headers: {
        authorization: `Bearer ${adminToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ action: "reconnect" }),
    });
    const reconnectRes = await fleetPATCH(reconnectReq, {
      params: Promise.resolve({ id: enrolledAgentId }),
    });
    assert.equal(reconnectRes.status, 200);

    // Next heartbeat should now be accepted as connected
    const hbReq2 = new NextRequest("http://localhost:3000/api/agent/heartbeat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId: enrolledAgentId,
        cpuUsage: 18.0,
        memoryUsage: 50.0,
        eps: 30,
      }),
    });
    const hbRes2 = await heartbeatPOST(hbReq2);
    assert.equal(hbRes2.status, 200);
    const hbData2 = await hbRes2.json();
    assert.equal(hbData2.status, "connected", "Endpoint should be connected after explicit reconnect");
  });

  await t.test("SD-030: Single-endpoint-per-IP policy rejects duplicate enrollment on same IP (409 Conflict)", async () => {
    // Generate a new token
    const tokReq = new NextRequest("http://localhost:3000/api/fleet/enrollment-tokens", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        label: "Duplicate IP test token",
        expiresInHours: 1,
        maxUses: 1,
      }),
    });
    const tokRes = await enrollmentTokensPOST(tokReq);
    assert.equal(tokRes.status, 200);
    const { token: secondToken } = await tokRes.json();

    // Attempt to enroll second agent using the same IP address ("10.0.15.99")
    const dupEnrollReq = new NextRequest("http://localhost:3000/api/agent/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        token: secondToken,
        hostname: "SRV-PROD-WORKER-DUP",
        ipAddress: "10.0.15.99", // Same IP as enrolledAgentId
        osType: "linux",
      }),
    });

    const dupEnrollRes = await enrollPOST(dupEnrollReq);
    assert.equal(dupEnrollRes.status, 409, "Enrollment from already-connected IP must be rejected with 409 Conflict");
    const dupEnrollData = await dupEnrollRes.json();
    assert.ok(dupEnrollData.error.includes("already connected"), "Error must clearly cite active IP conflict");
  });

  await t.test("SD-031: Heartbeat from duplicate endpoint on same IP is rejected (409 Conflict)", async () => {
    // Register another agent directly into mock store with same IP
    const { MOCK_ENDPOINT_AGENTS } = await import("@/lib/fleet/fleet");
    const dupAgentId = "dup-agent-test-id-002";
    MOCK_ENDPOINT_AGENTS.push({
      id: dupAgentId,
      tenant_id: "acme-tenant",
      hostname: "SRV-ROGUE-DUP-HB",
      ip_address: "10.0.15.99", // Same IP as enrolledAgentId
      os_type: "linux",
      agent_version: "0.4.2",
      status: "disconnected",
      cpu_usage: 0,
      memory_usage: 0,
      eps: 0,
      kill_switch_active: false,
      safety_snapshot_id: null,
      last_heartbeat: new Date().toISOString(),
      created_at: new Date().toISOString(),
    });

    // Send heartbeat from dupAgentId while enrolledAgentId is actively connected on 10.0.15.99
    const dupHbReq = new NextRequest("http://localhost:3000/api/agent/heartbeat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId: dupAgentId,
        ipAddress: "10.0.15.99",
        cpuUsage: 10.0,
        memoryUsage: 30.0,
        eps: 25,
      }),
    });

    const dupHbRes = await heartbeatPOST(dupHbReq);
    assert.equal(dupHbRes.status, 409, "Heartbeat from duplicate IP must return 409 Conflict");
    const dupHbData = await dupHbRes.json();
    assert.equal(dupHbData.status, "disconnected");
  });

  await t.test("SD-032: block_ip immediately disconnects endpoint, rejects subsequent heartbeats (403), and returns next-step guidance", async () => {
    // Execute block_ip on enrolledAgentId's IP (10.0.15.99)
    const blockReq = new NextRequest("http://localhost:3000/api/fleet/execute", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        agentId: enrolledAgentId,
        command: "block_ip 10.0.15.99",
        tier: "Tier 1",
      }),
    });

    const blockRes = await executePOST(blockReq);
    assert.equal(blockRes.status, 200, "block_ip should execute successfully");
    const blockData = await blockRes.json();
    assert.equal(blockData.success, true);
    assert.match(blockData.output, /CONTAINMENT ACTIVE/, "Output must state containment is active");
    assert.match(blockData.output, /DISCONNECTED/, "Output must state endpoint is disconnected");
    assert.match(blockData.output, /unblock_ip 10\.0\.15\.99/, "Output must provide unblock instructions");

    // Verify IP is marked blocked in threatAlertStore
    assert.equal(isIpBlocked("10.0.15.99"), true, "Target IP must be in blocked store");

    // Subsequent heartbeat from that IP must be rejected with 403 Forbidden
    const blockedHbReq = new NextRequest("http://localhost:3000/api/agent/heartbeat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId: enrolledAgentId,
        ipAddress: "10.0.15.99",
        cpuUsage: 25.0,
        memoryUsage: 55.0,
        eps: 40,
      }),
    });

    const blockedHbRes = await heartbeatPOST(blockedHbReq);
    assert.equal(blockedHbRes.status, 403, "Heartbeat from blocked IP must be rejected with 403");
    const blockedHbData = await blockedHbRes.json();
    assert.equal(blockedHbData.status, "disconnected");
    assert.equal(blockedHbData.error, "IP_BLOCKED");

    // Enrollment attempt from blocked IP must also be rejected with 403
    const blockedEnrollReq = new NextRequest("http://localhost:3000/api/agent/enroll", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        token: "sdt_dummy_token_12345",
        hostname: "SRV-BLOCKED-ENROLL",
        ipAddress: "10.0.15.99",
        osType: "linux",
      }),
    });
    const blockedEnrollRes = await enrollPOST(blockedEnrollReq);
    assert.equal(blockedEnrollRes.status, 403, "Enrollment from blocked IP must be rejected with 403");
  });

  await t.test("SD-033: unblock_ip lifts containment and allows endpoint heartbeats to resume", async () => {
    // Execute unblock_ip on 10.0.15.99
    const unblockReq = new NextRequest("http://localhost:3000/api/fleet/execute", {
      method: "POST",
      headers: {
        authorization: `Bearer ${adminToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        agentId: enrolledAgentId,
        command: "unblock_ip 10.0.15.99",
        tier: "Tier 1",
      }),
    });

    const unblockRes = await executePOST(unblockReq);
    assert.equal(unblockRes.status, 200, "unblock_ip should execute successfully");
    const unblockData = await unblockRes.json();
    assert.equal(unblockData.success, true);
    assert.match(unblockData.output, /CONTAINMENT LIFTED/, "Output must state containment is lifted");

    // Verify IP is no longer blocked
    assert.equal(isIpBlocked("10.0.15.99"), false, "Target IP must be removed from blocked store");

    // Heartbeats should now be accepted again
    const resumedHbReq = new NextRequest("http://localhost:3000/api/agent/heartbeat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId: enrolledAgentId,
        ipAddress: "10.0.15.99",
        cpuUsage: 14.5,
        memoryUsage: 45.0,
        eps: 28,
        status: "connected",
      }),
    });

    const resumedHbRes = await heartbeatPOST(resumedHbReq);
    assert.equal(resumedHbRes.status, 200, "Heartbeat should be accepted after unblocking");
    const resumedHbData = await resumedHbRes.json();
    assert.equal(resumedHbData.status, "connected");
  });
});
