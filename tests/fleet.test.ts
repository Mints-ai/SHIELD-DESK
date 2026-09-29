import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import {
  listEndpointAgents,
  getEndpointAgent,
  executeAgentCommand,
  triggerKillSwitch,
  getQueuedCommandsForAgent,
  recordCommandResult,
  MOCK_HASH_CHAINS,
} from "../src/lib/fleet/fleet";
import { requestApprovalToken, approveActionToken } from "../src/lib/governance/approvalTokens";
import { resetMockThrottle } from "../src/lib/governance/blastRadiusThrottle";
import { signCommand, verifyCommandSignature } from "../src/lib/fleet/commandSigning";
import type { SessionUser } from "../src/lib/auth/session";

test("ShieldDesk Layer 2: Endpoint Agent Fleet & Live Command Suite", async (t) => {
  const acmeAnalyst: SessionUser = {
    id: "dev-analyst",
    tenant_id: "acme-tenant",
    role: "user",
  };

  const acmeAdmin: SessionUser = {
    id: "dev-admin",
    tenant_id: "acme-tenant",
    role: "system_admin",
  };

  const globexUser: SessionUser = {
    id: "dev-other",
    tenant_id: "globex-tenant",
    role: "user",
  };

  await t.test("Tenant Isolation: acmeAnalyst sees only Acme endpoint agents", async () => {
    const agents = await listEndpointAgents(acmeAnalyst);
    assert.ok(agents.length >= 4, "Acme should have at least 4 enrolled test hosts");
    for (const a of agents) {
      assert.equal(a.tenant_id, "acme-tenant", `Agent ${a.hostname} must belong to acme-tenant`);
    }
  });

  await t.test("Tenant Isolation: globexUser cannot see Acme agents", async () => {
    const agents = await listEndpointAgents(globexUser);
    assert.ok(agents.length >= 1, "Globex should see its own test host");
    for (const a of agents) {
      assert.equal(a.tenant_id, "globex-tenant", `Agent ${a.hostname} must belong to globex-tenant`);
    }
  });

  await t.test("Anti-enumeration 404: globexUser cannot retrieve Acme agent FIN-WS-042", async () => {
    const agent = await getEndpointAgent("FIN-WS-042", globexUser);
    assert.equal(agent, null, "Cross-tenant agent lookup must return null (leading to 404)");
  });

  await t.test("Tier 1 Auto-Execution: runs automatically with safety snapshot", async () => {
    const res = await executeAgentCommand({
      agentId: "FIN-WS-042",
      command: "take_safety_snapshot",
      tier: "Tier 1",
      caller: acmeAnalyst,
    });

    assert.equal(res.success, true);
    assert.ok(res.output.includes("Filesystem & network state snapshot"), "Must take safety snapshot");
  });

  await t.test("Tier 2 Governance Gating: rejects execution without approved token", async () => {
    await assert.rejects(
      async () => {
        await executeAgentCommand({
          agentId: "FIN-WS-042",
          command: "isolate_host",
          tier: "Tier 2",
          caller: acmeAnalyst,
        });
      },
      /APPROVAL_TOKEN_REQUIRED/
    );
  });

  await t.test("Tier 2 Execution: succeeds when provided with approved human sign-off token", async () => {
    // 1. Analyst requests token
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tokenRes: any = await requestApprovalToken(
      { uid: acmeAnalyst.id, tenantId: acmeAnalyst.tenant_id, role: acmeAnalyst.role },
      {
        taskId: "t1111111-1111-1111-1111-111111111111",
        actionType: "isolate_host",
        blastRadius: "Host FIN-WS-042",
      }
    );
    const token = tokenRes.token;

    // 2. Distinct admin approves token (Separation of duties)
    await approveActionToken(
      { uid: acmeAdmin.id, tenantId: acmeAdmin.tenant_id, role: acmeAdmin.role },
      { tokenId: token.id }
    );

    // 3. Command executes successfully
    const res = await executeAgentCommand({
      agentId: "FIN-WS-042",
      command: "isolate_host",
      tier: "Tier 2",
      tokenId: token.id,
      caller: acmeAdmin,
    });

    assert.equal(res.success, true);
    assert.ok(res.output.includes("isolated successfully"), "Host must be isolated");
    assert.ok(res.snapshotId, "Safety snapshot must be captured before isolation");
  });

  await t.test("Emergency Admin Kill Switch: non-admin cannot trigger kill switch", async () => {
    await assert.rejects(
      async () => {
        await triggerKillSwitch({
          agentId: "FIN-WS-042",
          active: true,
          caller: acmeAnalyst,
        });
      },
      /UNAUTHORIZED_KILL_SWITCH/
    );
  });

  await t.test("Emergency Admin Kill Switch: admin can engage and disengage kill switch", async () => {
    // Engage kill switch
    const engageRes = await triggerKillSwitch({
      agentId: "FIN-WS-042",
      active: true,
      caller: acmeAdmin,
    });
    assert.ok(engageRes.affectedCount >= 1);

    // Verify commands are blocked while kill switch is active
    await assert.rejects(
      async () => {
        await executeAgentCommand({
          agentId: "FIN-WS-042",
          command: "take_safety_snapshot",
          tier: "Tier 1",
          caller: acmeAdmin,
        });
      },
      /KILL_SWITCH_ACTIVE/
    );

    // Disengage kill switch
    const disengageRes = await triggerKillSwitch({
      agentId: "FIN-WS-042",
      active: false,
      caller: acmeAdmin,
    });
    assert.ok(disengageRes.affectedCount >= 1);
  });

  await t.test("Blast-Radius Throttle: 6th Tier 1 command throws BLAST_RADIUS_EXCEEDED and audits downgrade", async () => {
    resetMockThrottle();

    // Fire 5 Tier 1 commands (all 5 must succeed)
    for (let i = 0; i < 5; i++) {
      const res = await executeAgentCommand({
        agentId: "FIN-WS-042",
        command: `block_ip 198.51.100.${10 + i}`,
        tier: "Tier 1",
        caller: acmeAnalyst,
      });
      assert.equal(res.success, true);
    }

    // 6th command must fail with BLAST_RADIUS_EXCEEDED
    await assert.rejects(
      async () => {
        await executeAgentCommand({
          agentId: "FIN-WS-042",
          command: "block_ip 198.51.100.99",
          tier: "Tier 1",
          caller: acmeAnalyst,
        });
      },
      /BLAST_RADIUS_EXCEEDED/
    );

    // Verify audit hash chain contains TIER1_THROTTLED_DOWNGRADED
    const downgradeAudit = MOCK_HASH_CHAINS.find(
      (e) => e.event_type === "TIER1_THROTTLED_DOWNGRADED"
    );
    assert.ok(downgradeAudit, "Must record TIER1_THROTTLED_DOWNGRADED audit event");
  });

  await t.test("Command Signing & Cryptographic Tamper Defense: verifies valid signature and rejects forged signature", async () => {
    const payload = {
      agentId: "FIN-WS-042",
      command: "isolate_host",
      nonce: "nonce-12345",
      tier: "Tier 2",
    };

    const signature = signCommand(payload);
    assert.ok(signature.length > 20, "Signature must be generated");

    // Valid signature verification
    const isValid = verifyCommandSignature({ ...payload, signature });
    assert.equal(isValid, true, "Signature must be cryptographically valid");

    // Tampered payload verification
    const isTamperedCommandValid = verifyCommandSignature({
      ...payload,
      command: "kill_process 1", // Attacker modified command
      signature,
    });
    assert.equal(isTamperedCommandValid, false, "Tampered command payload must fail verification");

    // Forged signature verification
    const isForgedSigValid = verifyCommandSignature({
      ...payload,
      signature: "forged-base64-signature==",
    });
    assert.equal(isForgedSigValid, false, "Forged signature must fail verification");
  });

  await t.test("Command Queue & Asynchronous Lifecycle: enqueues, polls, and reports execution result", async () => {
    resetMockThrottle();

    // 1. Enqueue a Tier 1 command
    const res = await executeAgentCommand({
      agentId: "FIN-WS-042",
      command: "block_ip 203.0.113.5",
      tier: "Tier 1",
      caller: acmeAnalyst,
    });
    assert.equal(res.success, true);
    assert.ok(res.commandId);

    // Verify intent audit event AGENT_COMMAND_QUEUED was recorded
    const queuedAudit = MOCK_HASH_CHAINS.find(
      (e) => e.event_type === "AGENT_COMMAND_QUEUED" && (e.payload as any)?.commandId === res.commandId
    );
    assert.ok(queuedAudit, "AGENT_COMMAND_QUEUED audit event must be recorded before execution");

    // Verify Section 3 (P0 Audit Truthfulness): AGENT_COMMAND_EXECUTED must NOT be fabricated at queue time
    const prematureExecutionAudit = MOCK_HASH_CHAINS.find(
      (e) => e.event_type === "AGENT_COMMAND_EXECUTED" && (e.payload as any)?.commandId === res.commandId
    );
    assert.equal(
      prematureExecutionAudit,
      undefined,
      "Audit trail must NEVER record AGENT_COMMAND_EXECUTED before the remote agent reports back"
    );

    // 2. Agent polls for pending commands
    const polled = await getQueuedCommandsForAgent("ea111111-1111-1111-1111-111111111111");
    const matchingCmd = polled.find((c) => c.id === res.commandId);
    assert.ok(matchingCmd, "Command must be delivered to polling agent");
    assert.equal(matchingCmd.status, "delivered");
    assert.ok(matchingCmd.signature, "Command must contain cryptographic signature");

    // 3. Agent reports execution result
    await recordCommandResult({
      commandId: res.commandId,
      status: "executed",
      output: "Host FIN-WS-042: firewall rule inserted to DROP 203.0.113.5",
      snapshotId: "snap-finws042-test",
    });

    // 4. Verify AGENT_COMMAND_EXECUTED event is logged exclusively upon real execution
    const executedAudit = MOCK_HASH_CHAINS.find(
      (e) => e.event_type === "AGENT_COMMAND_EXECUTED" && (e.payload as any)?.commandId === res.commandId
    );
    assert.ok(executedAudit, "AGENT_COMMAND_EXECUTED audit event must be recorded upon agent result");
    assert.equal((executedAudit.payload as any)?.status, "executed");
  });

  await t.test("API: GET /api/fleet/public-key returns control plane RSA-2048 public key", async () => {
    const { GET: publicKeyGET } = await import("../src/app/api/fleet/public-key/route");
    const res = await publicKeyGET();
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.algorithm, "RSA-SHA256");
    assert.equal(body.keySize, 2048);
    assert.ok(body.publicKey.includes("BEGIN PUBLIC KEY"), "Must return valid PEM public key");
  });
});

