import "./setup";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { NextRequest } from "next/server";
import { GET as scansGET, POST as scansPOST } from "../src/app/api/scans/route";
import {
  executeAgentCommand,
  getEndpointAgent,
  getQueuedCommandsForAgent,
  recordCommandResult,
  RealAgentExecutor,
  SimulationExecutor,
} from "../src/lib/fleet/fleet";
import {
  requestApprovalToken,
  approveActionToken,
} from "../src/lib/governance/approvalTokens";
import { getExecutiveRiskScorecard } from "../src/lib/reporting/scorecard";
import { ISO_27001_CONTROLS, getComplianceSummary } from "../src/lib/compliance/iso27001";
import { createSessionToken } from "../src/lib/auth/token";
import type { SessionUser } from "../src/lib/auth/session";
import crypto from "crypto";
import { issueCommercialLicense } from "../src/lib/billing/licenses";
import { issueEndpointCertificate } from "../src/lib/fleet/certificates";
import { LicenseActivationService } from "../src/lib/licensing/licenseActivation";

describe("Launch Audit Hardening & Closed-Loop Security Verification Suite", () => {
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

  const globexUser: SessionUser = {
    id: "dev-other",
    tenant_id: "globex-tenant",
    role: "analyst",
  };

  it("Audit Item 43: Scans API explicitly blocks demo mode in production (GET & POST)", async () => {
    const origAppEnv = process.env.APP_ENV;
    try {
      process.env.APP_ENV = "production";

      const token = createSessionToken({
        uid: "usr-admin-01",
        tenantId: "acme-tenant",
        role: "system_admin",
      });

      // GET with ?dataMode=demo in production -> 403 Forbidden
      const reqGet = new NextRequest("http://localhost:3000/api/scans?dataMode=demo", {
        headers: { authorization: `Bearer ${token}` },
      });
      const resGet = await scansGET(reqGet);
      assert.equal(resGet.status, 403, "GET /api/scans?dataMode=demo must return 403 in production");

      // POST with { action: 'cve_scan', dataMode: 'demo' } in production -> 403 Forbidden
      const reqPost = new NextRequest("http://localhost:3000/api/scans", {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ action: "cve_scan", dataMode: "demo" }),
      });
      const resPost = await scansPOST(reqPost);
      assert.equal(resPost.status, 403, "POST /api/scans with demo payload must return 403 in production");
    } finally {
      if (origAppEnv !== undefined) {
        process.env.APP_ENV = origAppEnv;
      } else {
        delete process.env.APP_ENV;
      }
    }
  });

  it("Audit Item 44: Production environment strictly enforces RealAgentExecutor over SimulationExecutor", async () => {
    const origAppEnv = process.env.APP_ENV;
    try {
      process.env.APP_ENV = "production";

      const agent = await getEndpointAgent("FIN-WS-042", acmeAnalyst);
      assert.ok(agent);
      const agentId = agent.id;
      const installationId = "launch-audit-installation-fin-ws-042";
      const certificate = await issueEndpointCertificate({ agentId, tenantId: acmeAnalyst.tenant_id, validityDays: 1 });
      const licenseKey = issueCommercialLicense({
        tenantId: acmeAnalyst.tenant_id,
        tier: "enterprise",
        maxEndpoints: 100,
        maxUsers: 10,
        features: ["endpointFleet"],
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      }).rawLicense;
      await LicenseActivationService.activate({
        tenantId: acmeAnalyst.tenant_id,
        installationId,
        deviceIdentity: agentId,
        certificatePem: certificate.certificatePem,
        licenseKey,
      });

      const res = await executeAgentCommand({
        agentId,
        command: "take_safety_snapshot",
        tier: "Tier 1",
        caller: acmeAnalyst,
      });

      assert.equal(res.success, true);
      assert.equal(res.state, "queued", "Production command must be enqueued, not simulated");
      assert.ok(
        res.output.includes("Awaiting signed host execution report"),
        "Production output must explicitly await remote host execution report"
      );

      // Verify SimulationExecutor throws when directly invoked in production
      const simExecutor = new SimulationExecutor();
      await assert.rejects(
        async () => {
          const agent = await getEndpointAgent("FIN-WS-042", acmeAnalyst);
          await simExecutor.execute({
            agent: agent!,
            command: "take_safety_snapshot",
            tier: "Tier 1",
            caller: acmeAnalyst,
            commandLogId: "test-cmd",
            signature: "sig",
            nonce: "nonce",
          });
        },
        /SIMULATION_DISABLED_IN_PRODUCTION/,
        "SimulationExecutor must reject execution in production"
      );
    } finally {
      if (origAppEnv !== undefined) {
        process.env.APP_ENV = origAppEnv;
      } else {
        delete process.env.APP_ENV;
      }
    }
  });

  it("Audit Item 45: Approval token binds to endpoint, command hash, and prevents replay attacks", async () => {
    const targetCommand = "isolate_host eth0";
    const commandHash = crypto.createHash("sha256").update(targetCommand).digest("hex");

    // 1. Analyst requests token bound to FIN-WS-042 and specific command hash
    const reqRes = await requestApprovalToken(
      { uid: acmeAnalyst.id, tenantId: acmeAnalyst.tenant_id, role: acmeAnalyst.role },
      {
        taskId: "t-task-audit-1",
        actionType: "isolate_host",
        blastRadius: "Host FIN-WS-042",
        command: targetCommand,
        targetEndpointIds: ["FIN-WS-042", "ea111111-1111-1111-1111-111111111111"],
      }
    );
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const token = (reqRes as any).token;
    assert.ok(token);
    assert.equal(token.command_hash, commandHash);

    // 2. Admin approves token
    await approveActionToken(
      { uid: acmeAdmin.id, tenantId: acmeAdmin.tenant_id, role: acmeAdmin.role },
      { tokenId: token.id }
    );

    // 3. Negative Test A: Command mismatch must be rejected
    await assert.rejects(
      async () => {
        await executeAgentCommand({
          agentId: "FIN-WS-042",
          command: "isolate_host eth1", // Wrong interface -> mismatched hash
          tier: "Tier 2",
          tokenId: token.id,
          caller: acmeAnalyst,
        });
      },
      /APPROVAL_TOKEN_COMMAND_MISMATCH/,
      "Must reject command with mismatched hash"
    );

    // 4. Negative Test B: Endpoint mismatch must be rejected
    await assert.rejects(
      async () => {
        await executeAgentCommand({
          agentId: "FIN-DB-01", // Wrong host
          command: targetCommand,
          tier: "Tier 2",
          tokenId: token.id,
          caller: acmeAnalyst,
        });
      },
      /APPROVAL_TOKEN_ENDPOINT_MISMATCH/,
      "Must reject token executed against unauthorized host"
    );

    // 5. Positive execution: matches endpoint and command hash -> succeeds
    const execRes = await executeAgentCommand({
      agentId: "FIN-WS-042",
      command: targetCommand,
      tier: "Tier 2",
      tokenId: token.id,
      caller: acmeAnalyst,
    });
    assert.equal(execRes.success, true);

    // 6. Anti-Replay: Attempting to use the SAME token a second time MUST be rejected
    await assert.rejects(
      async () => {
        await executeAgentCommand({
          agentId: "FIN-WS-042",
          command: targetCommand,
          tier: "Tier 2",
          tokenId: token.id,
          caller: acmeAnalyst,
        });
      },
      /APPROVAL_TOKEN_REPLAY_DETECTED/,
      "Token reuse/replay must be strictly rejected"
    );
  });

  it("Audit Item 46: Scorecard and Compliance metrics implement transparent MetricValue model", async () => {
    // 1. Executive Scorecard metrics
    const scorecard = await getExecutiveRiskScorecard(acmeAnalyst);
    assert.ok(scorecard.postureScoreMetric, "Scorecard must provide typed postureScoreMetric");
    assert.equal(scorecard.postureScoreMetric.status, "ESTIMATED");
    assert.ok(scorecard.postureScoreMetric.methodology, "Must provide estimation methodology");

    assert.equal(scorecard.mttdMinutes.metric.status, "BENCHMARK");
    assert.equal(scorecard.mttrMinutes.metric.status, "BENCHMARK");
    assert.equal(scorecard.estimatedLossAvoidedMetric.status, "BENCHMARK");
    assert.ok(scorecard.metrics.posture_score, "Must contain unified metrics catalog");

    // 2. ISO 27001 Controls
    assert.ok(ISO_27001_CONTROLS.length >= 8);
    for (const ctrl of ISO_27001_CONTROLS) {
      assert.ok(ctrl.metric, `Control ${ctrl.code} must provide typed metric`);
      assert.equal(ctrl.metric.status, "ESTIMATED");
      assert.ok(ctrl.metric.source, "Must document metric source");
    }

    const summary = await getComplianceSummary(acmeAnalyst);
    assert.ok(summary.overallScoreMetric, "Compliance summary must provide overallScoreMetric");
    assert.equal(summary.overallScoreMetric.status, "ESTIMATED");
  });

  it("Audit Item 10: Closed-Loop Command Lifecycle (QUEUED -> DELIVERED -> EXECUTED -> VERIFIED)", async () => {
    // 1. Enqueue command via RealAgentExecutor
    const realExec = new RealAgentExecutor();
    const agent = await getEndpointAgent("FIN-WS-042", acmeAnalyst);
    assert.ok(agent);

    const execResult = await realExec.execute({
      agent,
      command: "take_safety_snapshot",
      tier: "Tier 1",
      caller: acmeAnalyst,
      commandLogId: `cmd-test-${Date.now()}`,
      signature: "test-sig",
      nonce: "test-nonce",
    });

    assert.equal(execResult.state, "queued");

    // 2. Agent polls for queued commands -> transitions to DELIVERED
    const queued = await getQueuedCommandsForAgent(agent.id);
    const cmd = queued.find((c) => c.id === execResult.commandId);
    assert.ok(cmd, "Command must be delivered to agent upon polling");
    assert.equal(cmd.status, "delivered");

    // 3. Agent reports execution with verification -> transitions to VERIFIED
    const reportRes = await recordCommandResult({
      commandId: execResult.commandId,
      status: "executed",
      output: "Snapshot captured and verified successfully",
      snapshotId: "snap-verified-01",
      agentId: agent.id,
      verified: true,
    });
    assert.equal(reportRes.success, true);
  });
});
