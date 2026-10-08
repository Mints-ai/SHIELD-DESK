import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { GET as agentCommandsGET } from "../src/app/api/agent/commands/route";
import { POST as agentResultPOST } from "../src/app/api/agent/commands/[id]/result/route";
import { POST as fleetCommandPOST } from "../src/app/api/fleet/[id]/command/route";
import {
  executeAgentCommand,
  triggerKillSwitch,
  MOCK_AGENT_COMMANDS,
  MOCK_HASH_CHAINS,
} from "../src/lib/fleet/fleet";
import { resetMockThrottle } from "../src/lib/governance/blastRadiusThrottle";
import { createSessionToken } from "../src/lib/auth/token";
import type { SessionUser } from "../src/lib/auth/session";

test("ShieldDesk Automated Remediation & Agent Queue API Suite", async (t) => {
  const acmeAnalyst: SessionUser = {
    id: "dev-analyst",
    tenant_id: "acme-tenant",
    role: "analyst",
  };

  const acmeAdmin: SessionUser = {
    id: "dev-admin",
    tenant_id: "acme-tenant",
    role: "system_admin",
  };

  const analystToken = createSessionToken({
    uid: acmeAnalyst.id,
    role: acmeAnalyst.role,
    tenantId: acmeAnalyst.tenant_id,
  });

  await t.test("API: GET /api/agent/commands rejects request without agent_id", async () => {
    const req = new NextRequest("http://localhost:3000/api/agent/commands");
    const res = await agentCommandsGET(req);
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.match(body.error, /agent_id query parameter is required/);
  });

  await t.test("API: GET /api/agent/commands delivers queued commands and transitions status", async () => {
    resetMockThrottle();

    // Enqueue a command
    const cmdRes = await executeAgentCommand({
      agentId: "FIN-WS-042",
      command: "take_safety_snapshot",
      tier: "Tier 1",
      caller: acmeAnalyst,
    });
    assert.ok(cmdRes.commandId);

    // Agent polls
    const req = new NextRequest(
      "http://localhost:3000/api/agent/commands?agent_id=ea111111-1111-1111-1111-111111111111"
    );
    const res = await agentCommandsGET(req);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(Array.isArray(body.commands));

    const queued = body.commands.find((c: any) => c.id === cmdRes.commandId);
    assert.ok(queued, "Queued command must be returned to agent");
    assert.equal(queued.status, "delivered");
  });

  await t.test("API: POST /api/agent/commands/[id]/result logs execution and hash-chain event", async () => {
    const cmdId = "test-cmd-" + Date.now();
    MOCK_AGENT_COMMANDS.push({
      id: cmdId,
      agent_id: "ea111111-1111-1111-1111-111111111111",
      tenant_id: "acme-tenant",
      command: "isolate_host",
      tier: "Tier 2",
      token_id: null,
      signature: "test-sig",
      status: "delivered",
      created_at: new Date().toISOString(),
    });

    const req = new NextRequest(`http://localhost:3000/api/agent/commands/${cmdId}/result`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        status: "executed",
        output: "Host FIN-WS-042 isolated successfully.",
        snapshotId: "snap-test-01",
      }),
    });

    const res = await agentResultPOST(req, { params: Promise.resolve({ id: cmdId }) });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);

    const executedRecord = MOCK_HASH_CHAINS.find(
      (e) => e.event_type === "AGENT_COMMAND_EXECUTED" && (e.payload as any)?.commandId === cmdId
    );
    assert.ok(executedRecord, "AGENT_COMMAND_EXECUTED hash-chain record must be appended");
  });

  await t.test("API: GET /api/agent/commands returns 423 Locked when kill switch is engaged", async () => {
    // Engage kill switch
    await triggerKillSwitch({
      agentId: "FIN-WS-042",
      active: true,
      caller: acmeAdmin,
    });

    const req = new NextRequest(
      "http://localhost:3000/api/agent/commands?agent_id=ea111111-1111-1111-1111-111111111111"
    );
    const res = await agentCommandsGET(req);
    assert.equal(res.status, 423);
    const body = await res.json();
    assert.match(body.error, /KILL_SWITCH_ACTIVE/);

    // Disengage kill switch
    await triggerKillSwitch({
      agentId: "FIN-WS-042",
      active: false,
      caller: acmeAdmin,
    });
  });

  await t.test("API: POST /api/fleet/[id]/command returns 429 when throttled with downgrade flag", async () => {
    resetMockThrottle();

    // Exhaust throttle with 5 Tier 1 commands
    for (let i = 0; i < 5; i++) {
      await executeAgentCommand({
        agentId: "FIN-WS-042",
        command: `block_ip 198.51.100.${20 + i}`,
        tier: "Tier 1",
        caller: acmeAnalyst,
      });
    }

    // 6th command via API route
    const req = new NextRequest("http://localhost:3000/api/fleet/FIN-WS-042/command", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${analystToken}`,
      },
      body: JSON.stringify({
        command: "block_ip 198.51.100.99",
        tier: "Tier 1",
      }),
    });

    const res = await fleetCommandPOST(req, {
      params: Promise.resolve({ id: "FIN-WS-042" }),
    });

    assert.equal(res.status, 429);
    const data = await res.json();
    assert.equal(data.code, "BLAST_RADIUS_EXCEEDED");
    assert.equal(data.downgraded_tier, "Tier 2");
    assert.equal(data.requires_approval, true);
  });
});
