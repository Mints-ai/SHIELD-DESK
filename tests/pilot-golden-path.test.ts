import "./setup";
import test, { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import crypto from "crypto";

import { POST as enrollAgent } from "@/app/api/agent/enroll/route";
import { POST as ingestTelemetry } from "@/app/api/agent/telemetry/route";
import { POST as ingestSiem } from "@/app/api/ingest/siem/route";
import { GET as pollCommands } from "@/app/api/agent/commands/route";
import { POST as reportResult } from "@/app/api/agent/commands/[id]/result/route";
import { GET as getScimUsers, POST as postScimUsers } from "@/app/api/scim/v2/Users/route";
import { POST as billingWebhook } from "@/app/api/billing/webhook/route";

import { createEnrollmentToken } from "@/lib/fleet/enrollment";
import { requestApprovalToken, approveActionToken } from "@/lib/governance/approvalTokens";
import { executeAgentCommand, MOCK_HASH_CHAINS, MOCK_AGENT_COMMANDS } from "@/lib/fleet/fleet";
import { verifyCommandSignature } from "@/lib/fleet/commandSigning";
import { getTenantSubscription } from "@/lib/billing/plans";
import { issueCommercialLicense } from "@/lib/billing/licenses";

describe("ShieldDesk Public Launch Golden Path Verification Suite", () => {
  after(async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    if ((global as any).__shieldDeskPgPool) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (global as any).__shieldDeskPgPool.end().catch(() => {});
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (global as any).__shieldDeskPgPool = undefined;
    }
  });

  const tenantAdmin = {
    id: "usr-admin-secops",
    tenant_id: "acme-tenant",
    role: "system_admin" as const,
  };

  const socApprover = {
    id: "usr-ciso-lead",
    tenant_id: "acme-tenant",
    role: "super_admin" as const,
  };

  let testEnrollToken = "";
  let enrolledAgentId = "";
  let approvedTokenId = "";
  const pilotInstallationId = "pilot-installation-win-01";
  const pilotLicense = issueCommercialLicense({
    tenantId: "acme-tenant",
    tier: "enterprise",
    maxEndpoints: 10000,
    maxUsers: 1000,
    features: ["endpointFleet"],
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
  }).rawLicense;

  it("Step 1 & 2: Administrator generates dynamic enrollment token and agent enrolls with certificate", async () => {
    // 1. Generate token
    const tokenRecord = await createEnrollmentToken({
      caller: tenantAdmin,
      label: "Pilot Windows Host Token",
      expiresInHours: 2,
      maxUses: 1,
    });
    testEnrollToken = tokenRecord.rawToken;
    assert.ok(testEnrollToken.startsWith("sdt_"));

    // 2. Agent presents token to /api/agent/enroll
    const enrollReq = new NextRequest("http://localhost:3000/api/agent/enroll", {
      method: "POST",
      body: JSON.stringify({
        token: testEnrollToken,
        hostname: "PILOT-WIN-01",
        ipAddress: "192.168.10.45",
        osType: "windows",
        agentVersion: "0.4.2",
        installationId: pilotInstallationId,
        licenseKey: pilotLicense,
      }),
    });

    const enrollRes = await enrollAgent(enrollReq);
    assert.equal(enrollRes.status, 200);

    const enrollData = await enrollRes.json();
    assert.equal(enrollData.success, true);
    assert.equal(enrollData.tenantId, "acme-tenant");
    assert.ok(enrollData.agentId);
    assert.ok(enrollData.certificate);
    assert.ok(enrollData.certificate.fingerprintSha256);

    enrolledAgentId = enrollData.agentId;
  });

  it("Step 3: Inbound SIEM Webhook ingests external alert with HMAC validation", async () => {
    const rawPayload = JSON.stringify({
      source: "defender",
      externalAlertId: "def-alert-9910",
      title: "Ransomware Behavior Detected on Host",
      severity: "critical",
      hostname: "PILOT-WIN-01",
      description: "Shadow copy deletion attempted via vssadmin.exe",
    });

    const secret = process.env.SHIELDDESK_WEBHOOK_SECRET || "sd_webhook_dev_secret";
    const signature = "sha256=" + crypto.createHmac("sha256", secret).update(rawPayload).digest("hex");

    const siemReq = new NextRequest("http://localhost:3000/api/ingest/siem", {
      method: "POST",
      headers: {
        "x-shielddesk-signature": signature,
        "x-shielddesk-tenant-id": "acme-tenant",
      },
      body: rawPayload,
    });

    const res = await ingestSiem(siemReq);
    assert.equal(res.status, 201);

    const data = await res.json();
    assert.equal(data.success, true);
    assert.ok(data.incidentCode);
  });

  it("Step 4 & 5: Streaming Telemetry evaluates Sigma rules and auto-correlates incident", async () => {
    const telemetryBatch = [
      {
        eventType: "PROCESS_EXECUTION",
        payload: {
          processName: "vssadmin.exe",
          commandLine: "vssadmin.exe delete shadows /all /quiet",
          user: "SYSTEM",
        },
      },
    ];

    const telemReq = new NextRequest("http://localhost:3000/api/agent/telemetry", {
      method: "POST",
      body: JSON.stringify({
        agentId: enrolledAgentId,
        events: telemetryBatch,
      }),
    });

    const telemRes = await ingestTelemetry(telemReq);
    assert.equal(telemRes.status, 200);

    const telemData = await telemRes.json();
    assert.equal(telemData.success, true);
    assert.equal(telemData.detections.length, 1);
    assert.equal(telemData.detections[0].ruleId, "sigma_shadow_copy_deletion");
    assert.ok(telemData.detections[0].incidentCode);
  });

  it("Step 6, 7 & 8: Separation-of-Duties approval token strictly prevents self-approval", async () => {
    // Requester requests isolation token
    const tokenRes = await requestApprovalToken(
      { uid: tenantAdmin.id, tenantId: tenantAdmin.tenant_id, role: tenantAdmin.role },
      {
        taskId: "task-contain-pilot-win",
        actionType: "isolate_host",
        blastRadius: "Host PILOT-WIN-01",
        targetEndpointIds: [enrolledAgentId],
        command: "isolate_host PILOT-WIN-01",
      }
    );
    assert.ok(tokenRes.token);
    const tokenId = tokenRes.token.id;
    approvedTokenId = tokenId;

    // Self-approval must be rejected
    const selfApprove = await approveActionToken(
      { uid: tenantAdmin.id, tenantId: tenantAdmin.tenant_id, role: tenantAdmin.role },
      { tokenId }
    );
    assert.equal(selfApprove.error, "separation_of_duties_violation");

    // Independent approver signs token
    const leadApprove = await approveActionToken(
      { uid: socApprover.id, tenantId: socApprover.tenant_id, role: socApprover.role },
      { tokenId }
    );
    assert.equal(leadApprove.success, true);
    assert.ok(leadApprove.token);
    assert.equal(leadApprove.token.status, "approved");
  });

  it("Step 9, 10 & 11: RSA Command Dispatch, Agent Poll, Signature Verification & Truthful Execution Reporting", async () => {
    // 1. Dispatch Tier 2 Command with approved token
    const execRes = await executeAgentCommand({
      agentId: enrolledAgentId,
      caller: tenantAdmin,
      command: "isolate_host PILOT-WIN-01",
      tier: "Tier 2",
      tokenId: approvedTokenId,
    });
    assert.equal(execRes.success, true);
    assert.ok(execRes.commandId);
    const commandId = execRes.commandId;

    // 2. Agent polls command from /api/agent/commands
    const pollReq = new NextRequest(`http://localhost:3000/api/agent/commands?agent_id=${enrolledAgentId}`);
    const pollRes = await pollCommands(pollReq);
    assert.equal(pollRes.status, 200);

    const pollData = await pollRes.json();
    assert.ok(Array.isArray(pollData.commands));
    const polledCmd = pollData.commands.find((c: { id: string }) => c.id === commandId);
    assert.ok(polledCmd);
    assert.ok(polledCmd.signature);

    // 3. Cryptographically verify RSA-2048 signature
    const isSigValid = verifyCommandSignature({
      signature: polledCmd.signature,
      agentId: enrolledAgentId,
      command: polledCmd.command,
      nonce: polledCmd.nonce,
      tier: polledCmd.tier,
    });
    assert.equal(isSigValid, true);

    // 4. Agent reports execution result
    const reportReq = new NextRequest(`http://localhost:3000/api/agent/commands/${commandId}/result`, {
      method: "POST",
      body: JSON.stringify({
        agentId: enrolledAgentId,
        status: "succeeded",
        output: "Host successfully isolated via netsh advfirewall. Management tunnel preserved.",
        snapshotId: "snap-pilot-win-01-1001",
      }),
    });

    const reportRes = await reportResult(reportReq, { params: Promise.resolve({ id: commandId }) });
    assert.equal(reportRes.status, 200);

    // 5. Verify Truthful Audit Event exists on Hash-Chain Ledger
    const cmdExecutedEvents = MOCK_HASH_CHAINS.filter(
      (h) => h.event_type === "AGENT_COMMAND_EXECUTED" && h.actor_id === `agent:${enrolledAgentId}`
    );
    assert.ok(cmdExecutedEvents.length >= 1, "AGENT_COMMAND_EXECUTED must be recorded on hash chain");
  });

  it("Step 12: SCIM 2.0 User Provisioning & Directory Sync", async () => {
    // 1. SCIM Users Query
    const scimGetReq = new NextRequest("http://localhost:3000/api/scim/v2/Users", {
      headers: { authorization: "Bearer scim-dev-bearer-token" },
    });
    const scimGetRes = await getScimUsers(scimGetReq);
    assert.equal(scimGetRes.status, 200);

    // 2. SCIM Provision new user
    const scimPostReq = new NextRequest("http://localhost:3000/api/scim/v2/Users", {
      method: "POST",
      headers: {
        authorization: "Bearer scim-dev-bearer-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        userName: "secops.pilot@acme.corp",
        emails: [{ value: "secops.pilot@acme.corp", primary: true }],
      }),
    });
    const scimPostRes = await postScimUsers(scimPostReq);
    assert.equal(scimPostRes.status, 201);
    const createdUser = await scimPostRes.json();
    assert.equal(createdUser.userName, "secops.pilot@acme.corp");
  });

  it("Step 13: Billing Webhook settlement upgrades tenant subscription tier", async () => {
    const webhookReq = new NextRequest("http://localhost:3000/api/billing/webhook", {
      method: "POST",
      headers: {
        "x-razorpay-signature": "test-signature",
      },
      body: JSON.stringify({
        tenantId: "acme-tenant",
        tier: "enterprise",
      }),
    });

    const webRes = await billingWebhook(webhookReq);
    assert.equal(webRes.status, 200);

    const sub = await getTenantSubscription("acme-tenant");
    assert.equal(sub.tier, "enterprise");
    assert.equal(sub.maxEndpoints, 10000);
  });
});
