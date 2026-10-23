import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import {
  getEndpointMonitoringPolicy,
  updateEndpointMonitoringPolicy,
  getEndpointCoreFunctionsData,
  CORE_FUNCTION_SCOPES,
} from "../src/lib/fleet/monitoringPolicy";
import type { SessionUser } from "../src/lib/auth/session";

test("Governed Core Function Monitoring Suite", async (t) => {
  const testAgentId = "test-agent-governance-001";
  const testTenantId = "tenant-secops-dev";

  const standardUser: SessionUser = {
    id: "usr-junior-analyst",
    tenant_id: testTenantId,
    role: "analyst",
  };

  const adminAuthorityUser: SessionUser = {
    id: "usr-secops-authority-admin",
    tenant_id: testTenantId,
    role: "super_admin",
  };

  await t.test("Default Policy: Only lightweight system performance enabled", async () => {
    const policy = await getEndpointMonitoringPolicy(testAgentId, testTenantId);
    assert.deepEqual(policy.enabled_scopes, ["system_performance"]);
    assert.equal(policy.status, "active");
  });

  await t.test("Enforcing Governance: Unapproved user cannot enable gated core functions", async () => {
    await assert.rejects(
      async () => {
        await updateEndpointMonitoringPolicy({
          agentId: testAgentId,
          tenantId: testTenantId,
          requestedScopes: ["network_sockets", "process_inventory"],
          caller: standardUser,
        });
      },
      /AUTHORITY_APPROVAL_REQUIRED/
    );
  });

  await t.test("Authority Approval: Authorized admin can approve core function monitoring", async () => {
    const result = await updateEndpointMonitoringPolicy({
      agentId: testAgentId,
      tenantId: testTenantId,
      requestedScopes: ["network_sockets", "firewall_baseline"],
      caller: adminAuthorityUser,
    });

    assert.equal(result.success, true);
    assert.ok(result.policy.enabled_scopes.includes("network_sockets"));
    assert.ok(result.policy.enabled_scopes.includes("firewall_baseline"));
    assert.equal(result.policy.approved_by, adminAuthorityUser.id);
    assert.ok(result.policy.policy_hash.length === 64);
  });

  await t.test("Data Privacy & Resource Control: Only approved scopes return data", async () => {
    const coreData = await getEndpointCoreFunctionsData(testAgentId, testTenantId, "TEST-HOST");

    // Approved scopes
    assert.equal(coreData.data.system_performance.enabled, true);
    assert.equal(coreData.data.network_sockets.enabled, true);
    assert.ok(coreData.data.network_sockets.sockets.length > 0);

    // Unapproved scope
    assert.equal(coreData.data.process_inventory.enabled, false);
    assert.equal(coreData.data.process_inventory.status, "disabled_by_policy");
    assert.equal(coreData.data.process_inventory.processes.length, 0);
  });

  await t.test("Linux Endpoint Telemetry Isolation: Never leaks Windows Defender or host server threats to Linux agents", async () => {
    const linuxAgentId = "linux-panda-agent-001";
    await updateEndpointMonitoringPolicy({
      agentId: linuxAgentId,
      tenantId: testTenantId,
      requestedScopes: ["system_performance", "defender_authority"],
      caller: adminAuthorityUser,
    });

    const coreData = await getEndpointCoreFunctionsData(linuxAgentId, testTenantId, "panda", "linux");
    assert.equal(coreData.data.defender_authority.enabled, true);
    const def = coreData.data.defender_authority.defender;
    assert.ok(def, "Defender/EDR data must be present");
    assert.equal(def.antivirusEnabled, true);
    assert.equal(def.signatureVersion, "Linux Sigma/YARA 2.4");
    assert.ok(def.productVersion?.includes("Linux"));
    assert.ok(def.runningMode?.includes("eBPF"));
    assert.ok(def.lastAudit?.toLowerCase().includes("panda"));

    // Verify zero Windows leakages
    assert.equal(def.threats?.some((t: any) => t.threatName?.includes("Win32")), false);
    assert.equal(def.detections?.some((d: any) => JSON.stringify(d).includes("C:\\")), false);
    assert.equal(def.lastAudit?.includes("DELL"), false);
  });
});
