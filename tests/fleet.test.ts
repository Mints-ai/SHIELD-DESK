import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import {
  listEndpointAgents,
  getEndpointAgent,
  executeAgentCommand,
  triggerKillSwitch,
} from "../src/lib/fleet/fleet";
import { requestApprovalToken, approveActionToken } from "../src/lib/governance/approvalTokens";
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
});
