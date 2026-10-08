import "./setup";
import test, { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { POST as ingestTelemetry } from "@/app/api/agent/telemetry/route";
import { POST as createIncident, PATCH as updateIncident } from "@/app/api/incidents/route";
import { GET as getThreats, POST as postThreats } from "@/app/api/threats/route";
import { requestApprovalToken, approveActionToken } from "@/lib/governance/approvalTokens";
import {
  executeAgentCommand,
  getQueuedCommandsForAgent,
  recordCommandResult,
  MOCK_AGENT_COMMANDS,
  MOCK_HASH_CHAINS,
} from "@/lib/fleet/fleet";
import { evaluateTelemetryBatch, toggleDetectionRule } from "@/lib/detection/engine";
import { createSessionToken } from "@/lib/auth/token";
import type { SessionUser } from "@/lib/auth/session";

const TEST_ANALYST: SessionUser = {
  id: "usr-analyst-1",
  tenant_id: "acme-tenant",
  role: "system_admin",
};

const TEST_APPROVER: SessionUser = {
  id: "usr-soc-lead-2",
  tenant_id: "acme-tenant",
  role: "super_admin",
};

const analystToken = createSessionToken({
  uid: "usr-analyst-1",
  tenantId: "acme-tenant",
  role: "system_admin",
});

const globexToken = createSessionToken({
  uid: "usr-globex-9",
  tenantId: "globex-tenant",
  role: "analyst",
});

describe("ShieldDesk Closed-Loop EDR/SOC Integration Test Suite", () => {
  after(async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    if ((global as any).__shieldDeskPgPool) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (global as any).__shieldDeskPgPool.end().catch(() => {});
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global as any).__shieldDeskPgPool = undefined;
    }
  });

  it("Step 1 & 2: Telemetry Ingestion evaluates Sigma rules and detects Suspicious Encoded PowerShell", async () => {
    const maliciousBatch = [
      {
        eventType: "PROCESS_EXECUTION",
        payload: {
          processName: "powershell.exe",
          commandLine: "powershell.exe -ExecutionPolicy Bypass -enc JABhACAAPQAgACcAdABlAHMAdAAnAA==",
          parentProcess: "cmd.exe",
          user: "SYSTEM",
        },
        timestamp: new Date().toISOString(),
      },
    ];

    const detections = await evaluateTelemetryBatch(maliciousBatch, {
      agentId: "ea111111-1111-1111-1111-111111111111",
      tenantId: "acme-tenant",
      hostname: "FIN-WS-042",
    });

    assert.equal(detections.length, 1, "Must detect encoded powershell execution");
    assert.equal(detections[0].ruleId, "sigma_encoded_powershell");
    assert.equal(detections[0].severity, "high");
    assert.ok(detections[0].incidentCode, "Autonomous incident code must be generated");
    assert.ok(detections[0].incidentId, "Autonomous incident ID must be assigned");
  });

  it("Step 3: Streaming Telemetry Route /api/agent/telemetry correlates threats and returns detections", async () => {
    const req = new NextRequest("http://localhost:3000/api/agent/telemetry", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-shielddesk-agent-id": "ea111111-1111-1111-1111-111111111111",
      },
      body: JSON.stringify({
        agentId: "ea111111-1111-1111-1111-111111111111",
        events: [
          {
            eventType: "PROCESS_EXECUTION",
            payload: {
              processName: "vssadmin.exe",
              commandLine: "vssadmin.exe delete shadows /all /quiet",
              user: "NT AUTHORITY\\SYSTEM",
            },
          },
        ],
      }),
    });

    const res = await ingestTelemetry(req);
    assert.equal(res.status, 200);

    const data = await res.json();
    assert.equal(data.success, true);
    assert.equal(data.ingested, 1);
    assert.equal(data.detectionsCount, 1);
    assert.equal(data.detections[0].ruleId, "sigma_shadow_copy_deletion");
    assert.equal(data.detections[0].severity, "critical");
  });

  it("Step 4: Threat Engine API returns active detection rules and allows dynamic toggling", async () => {
    // 1. Get threat engine status
    const req = new NextRequest("http://localhost:3000/api/threats", {
      headers: { authorization: `Bearer ${analystToken}` },
    });

    const res = await getThreats(req);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data.detection_rules));
    assert.ok(data.detection_rules.length >= 6);

    // 2. Toggle a rule off
    const toggleReq = new NextRequest("http://localhost:3000/api/threats", {
      method: "POST",
      headers: {
        authorization: `Bearer ${analystToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        action: "toggle_rule",
        rule_id: "sigma_ssh_bruteforce",
        enabled: false,
      }),
    });

    const toggleRes = await postThreats(toggleReq);
    assert.equal(toggleRes.status, 200);
    const toggleData = await toggleRes.json();
    assert.equal(toggleData.new_status, "DISABLED");

    // Re-enable
    toggleDetectionRule("sigma_ssh_bruteforce", true);
  });

  it("Step 5: Incident Management API supports creation and strict tenant-isolated updates", async () => {
    // Create incident
    const createReq = new NextRequest("http://localhost:3000/api/incidents", {
      method: "POST",
      headers: {
        authorization: `Bearer ${analystToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        title: "Active C2 beacon detected on FIN-WS-042",
        description: "Beaconing traffic observed to known external IP range.",
        severity: "critical",
        hostname: "FIN-WS-042",
        linkedCves: ["CVE-2024-3400"],
      }),
    });

    const createRes = await createIncident(createReq);
    assert.equal(createRes.status, 200);
    const createData = await createRes.json();
    assert.equal(createData.success, true);
    assert.ok(createData.incidentCode);
    const createdIncidentId = createData.incidentId;

    // Cross-tenant attacker cannot update Acme's incident
    const crossUpdateReq = new NextRequest("http://localhost:3000/api/incidents", {
      method: "PATCH",
      headers: {
        authorization: `Bearer ${globexToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        id: createdIncidentId,
        status: "closed",
      }),
    });

    const crossUpdateRes = await updateIncident(crossUpdateReq);
    assert.ok([403, 404].includes(crossUpdateRes.status));

    // Authorized analyst updates status to 'investigating' with notes
    const validUpdateReq = new NextRequest("http://localhost:3000/api/incidents", {
      method: "PATCH",
      headers: {
        authorization: `Bearer ${analystToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        id: createdIncidentId,
        status: "investigating",
        notes: "Quarantine procedure initiated under emergency mitigation plan.",
      }),
    });

    const validUpdateRes = await updateIncident(validUpdateReq);
    assert.equal(validUpdateRes.status, 200);
    const validUpdateData = await validUpdateRes.json();
    assert.equal(validUpdateData.success, true);
    assert.equal(validUpdateData.newStatus, "investigating");
  });

  it("Step 6, 7 & 8: Approval Governance, Separation of Duties, and Token Binding", async () => {
    // 1. Analyst requests Tier 2 approval token for host isolation
    const reqTokenRes = await requestApprovalToken(
      { uid: TEST_ANALYST.id, tenantId: TEST_ANALYST.tenant_id, role: TEST_ANALYST.role },
      {
        taskId: "t-isolate-finws042",
        actionType: "isolate_host",
        blastRadius: "Workstation FIN-WS-042",
        targetEndpointIds: ["ea111111-1111-1111-1111-111111111111"],
        command: "isolate_host FIN-WS-042",
      }
    );

    assert.ok(reqTokenRes.token);
    const tokenId = reqTokenRes.token.id;
    assert.equal(reqTokenRes.token.status, "pending");

    // 2. Separation of duties check: Requester cannot approve own action
    const selfApprove = await approveActionToken(
      { uid: TEST_ANALYST.id, tenantId: TEST_ANALYST.tenant_id, role: TEST_ANALYST.role },
      { tokenId }
    );
    assert.equal(selfApprove.error, "separation_of_duties_violation");

    // 3. Independent SOC lead approves action
    const leadApprove = await approveActionToken(
      { uid: TEST_APPROVER.id, tenantId: TEST_APPROVER.tenant_id, role: TEST_APPROVER.role },
      { tokenId }
    );
    assert.equal(leadApprove.success, true);
    assert.ok(leadApprove.token);
    assert.equal(leadApprove.token.status, "approved");
    assert.equal(leadApprove.token.approved_by, TEST_APPROVER.id);
  });

  it("Step 9, 10 & 11: Real Command Execution Loop: Queued -> Delivered -> Executed -> Verified", async () => {
    // 0. Request & Approve a dedicated Tier 2 token
    const tokenRes = await requestApprovalToken(
      { uid: TEST_ANALYST.id, tenantId: TEST_ANALYST.tenant_id, role: TEST_ANALYST.role },
      {
        taskId: "t-isolate-finws042-loop",
        actionType: "isolate_host",
        blastRadius: "Workstation FIN-WS-042",
        targetEndpointIds: ["ea111111-1111-1111-1111-111111111111"],
        command: "isolate_host FIN-WS-042",
      }
    );
    assert.ok(tokenRes.token);
    const approvedToken = await approveActionToken(
      { uid: TEST_APPROVER.id, tenantId: TEST_APPROVER.tenant_id, role: TEST_APPROVER.role },
      { tokenId: tokenRes.token.id }
    );
    assert.equal(approvedToken.success, true);

    // 1. Queue command bound to approved token
    const queueRes = await executeAgentCommand({
      agentId: "ea111111-1111-1111-1111-111111111111",
      command: "isolate_host FIN-WS-042",
      tier: "Tier 2",
      tokenId: tokenRes.token.id,
      caller: TEST_ANALYST,
    });

    assert.equal(queueRes.success, true);
    const commandId = queueRes.commandId;

    // 2. Agent polls for commands: state transitions to 'delivered'
    const pendingCmds = await getQueuedCommandsForAgent("ea111111-1111-1111-1111-111111111111");
    const deliveredCmd = pendingCmds.find((c) => c.id === commandId);
    assert.ok(deliveredCmd, "Command must be polled by agent");
    assert.equal(deliveredCmd.status, "delivered");
    assert.ok(deliveredCmd.delivered_at, "delivered_at timestamp must be set");

    // 3. Agent reports successful execution with safety snapshot
    const recordRes = await recordCommandResult({
      commandId,
      agentId: "ea111111-1111-1111-1111-111111111111",
      status: "executed",
      verified: true,
      output: "Host network quarantined successfully via netsh firewall rules. Management tunnel preserved.",
      snapshotId: "snap-finws042-baseline",
    });

    assert.equal(recordRes.success, true);

    // 4. Verify command execution state is now 'verified'
    const memoryCmd = MOCK_AGENT_COMMANDS.find((c) => c.id === commandId);
    assert.ok(memoryCmd);
    assert.equal(memoryCmd.status, "verified");
    assert.equal(memoryCmd.snapshot_id, "snap-finws042-baseline");

    // 5. Verify cryptographic hash chain audit record was appended
    const auditRecord = MOCK_HASH_CHAINS.find(
      (h) => h.event_type === "AGENT_COMMAND_EXECUTED" && (h.payload as any).commandId === commandId
    );
    assert.ok(auditRecord, "Tamper-proof audit hash chain must contain AGENT_COMMAND_EXECUTED entry");
    assert.equal((auditRecord.payload as any).status, "verified");
  });
});
