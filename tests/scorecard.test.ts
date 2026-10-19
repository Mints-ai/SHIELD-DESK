import "./setup";
import "./fixtures/fleet";
import test from "node:test";
import assert from "node:assert/strict";
import { getExecutiveRiskScorecard } from "../src/lib/reporting/scorecard";
import {
  triggerKillSwitch,
  MOCK_ENDPOINT_AGENTS,
  removeMockEndpointAgent,
} from "../src/lib/fleet/fleet";
import { requestApprovalToken, approveActionToken } from "../src/lib/governance/approvalTokens";
import type { SessionUser } from "../src/lib/auth/session";

test("Executive Risk Scorecard — Live Telemetry & Dynamic Calculations", async (t) => {
  const acmeAdmin: SessionUser = {
    id: "dev-admin",
    tenant_id: "acme-tenant",
    role: "system_admin",
  };

  const acmeAnalyst: SessionUser = {
    id: "dev-analyst",
    tenant_id: "acme-tenant",
    role: "analyst",
  };

  const globexAnalyst: SessionUser = {
    id: "dev-other",
    tenant_id: "globex-tenant",
    role: "analyst",
  };

  await t.test("Computes tenant-specific live metrics for acme-tenant vs globex-tenant", async () => {
    const acmeScorecard = await getExecutiveRiskScorecard(acmeAnalyst);
    const globexScorecard = await getExecutiveRiskScorecard(globexAnalyst);

    assert.equal(acmeScorecard.tenantId, "acme-tenant");
    assert.equal(globexScorecard.tenantId, "globex-tenant");

    // Endpoints protected should reflect each tenant's actual enrolled fleet
    assert.ok(acmeScorecard.endpointsProtected >= 4, "Acme should protect >= 4 endpoints");
    assert.equal(globexScorecard.endpointsProtected, 1, "Globex should protect 1 endpoint");
    assert.notEqual(
      acmeScorecard.endpointsProtected,
      globexScorecard.endpointsProtected,
      "Endpoints protected must dynamically differ by tenant"
    );

    // Estimated loss avoided should differ because fleet size & token/incident counts differ
    assert.notEqual(
      acmeScorecard.estimatedLossAvoidedUsd,
      globexScorecard.estimatedLossAvoidedUsd,
      "Estimated loss avoided should be dynamically computed per tenant"
    );

    // Threat distribution percentages should sum to 100%
    const totalPct = acmeScorecard.threatDistribution.reduce((sum, item) => sum + item.percentage, 0);
    assert.equal(totalPct, 100, "Threat distribution percentages must sum to 100%");
    assert.ok(acmeScorecard.threatDistribution.length > 0, "Threat distribution must not be empty");
  });

  await t.test("Dynamically updates Posture Score and Endpoints Protected when Emergency Kill Switch is engaged", async () => {
    const baseline = await getExecutiveRiskScorecard(acmeAnalyst);

    await triggerKillSwitch({
      agentId: "FIN-WS-042",
      active: true,
      caller: acmeAdmin,
    });

    try {
      const degraded = await getExecutiveRiskScorecard(acmeAnalyst);
      assert.ok(
        degraded.postureScore < baseline.postureScore,
        `Expected degraded score (${degraded.postureScore}) < baseline (${baseline.postureScore})`
      );
      assert.equal(
        degraded.endpointsProtected,
        baseline.endpointsProtected - 1,
        "Killed/disconnected endpoint must be excluded from endpointsProtected"
      );
    } finally {
      await triggerKillSwitch({
        agentId: "FIN-WS-042",
        active: false,
        caller: acmeAdmin,
      });
    }
  });

  await t.test("Decrements Endpoints Protected immediately when an endpoint is disconnected or removed", async () => {
    const before = await getExecutiveRiskScorecard(acmeAnalyst);
    const target = MOCK_ENDPOINT_AGENTS.find((a) => a.hostname === "PROD-API-01");
    assert.ok(target, "Target endpoint PROD-API-01 should exist");

    // 1. Disconnect endpoint
    target.status = "disconnected";
    try {
      const afterDisconnect = await getExecutiveRiskScorecard(acmeAnalyst);
      assert.equal(
        afterDisconnect.endpointsProtected,
        before.endpointsProtected - 1,
        "Disconnected endpoint must not be counted in endpointsProtected"
      );
      assert.equal(
        afterDisconnect.disconnectedEndpoints,
        (before.disconnectedEndpoints ?? 0) + 1,
        "disconnectedEndpoints count should increment"
      );
    } finally {
      target.status = "connected";
    }

    // 2. Remove endpoint completely
    const backup = { ...target };
    const removed = removeMockEndpointAgent(target.id, "acme-tenant");
    assert.equal(removed, true);
    try {
      const afterRemove = await getExecutiveRiskScorecard(acmeAnalyst);
      assert.equal(
        afterRemove.endpointsProtected,
        before.endpointsProtected - 1,
        "Removed endpoint must be removed from endpointsProtected"
      );
      assert.equal(
        afterRemove.totalEnrolledEndpoints,
        (before.totalEnrolledEndpoints ?? 4) - 1,
        "Total enrolled endpoints should decrement when removed"
      );
    } finally {
      MOCK_ENDPOINT_AGENTS.push(backup);
    }
  });

  await t.test("Dynamically updates Autonomous Action Ratio when Tier 2 token is approved", async () => {
    const before = await getExecutiveRiskScorecard(acmeAnalyst);

    const reqRes = await requestApprovalToken(
      { uid: acmeAnalyst.id, tenantId: acmeAnalyst.tenant_id, role: acmeAnalyst.role },
      {
        taskId: "t-scorecard-test",
        actionType: "isolate_host",
        blastRadius: "Workstation FIN-WS-042",
        tier: "Tier 2",
      }
    );
    assert.ok("token" in reqRes && reqRes.token, "Token should be created");

    const appRes = await approveActionToken(
      { uid: acmeAdmin.id, tenantId: acmeAdmin.tenant_id, role: acmeAdmin.role },
      { tokenId: reqRes.token.id }
    );
    assert.ok("success" in appRes && appRes.success, "Token should be approved");

    const after = await getExecutiveRiskScorecard(acmeAnalyst);
    assert.ok(
      after.autonomousActionRatio.tier2HumanApproved > before.autonomousActionRatio.tier2HumanApproved,
      "Tier 2 human approved count should increment after token approval"
    );
  });
});
