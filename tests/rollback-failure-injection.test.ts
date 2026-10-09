import "./setup";
import test from "node:test";
import assert from "node:assert/strict";
import { VerificationEngine } from "../src/lib/verification-engine";
import { MOCK_HASH_CHAINS } from "../src/lib/fleet/fleet";

// These cases inject simulated post-command evidence; no endpoint or host is contacted.
const injectedFailures = [
  { name: "patch failure", method: "package_version_check", target: "openssl", expectedState: { version: "3.0" } },
  { name: "service failure", method: "service_health_check", target: "sshd", expectedState: { status: "healthy" } },
  { name: "network failure", method: "firewall_rule_check", target: "198.51.100.7", expectedState: { active: true } },
  { name: "snapshot corruption", method: "snapshot_state_check", target: "snap-test", expectedState: { restored: true } },
  { name: "disk full", method: "package_version_check", target: "package-write", expectedState: { version: "2.0" } },
  { name: "agent disconnect mid-execution", method: "service_health_check", target: "agent-control-plane", expectedState: { status: "healthy" } },
  { name: "reboot before verification", method: "service_health_check", target: "app", expectedState: { status: "healthy" } },
  { name: "partial execution", method: "config_state_check", target: "security.mode", expectedState: { value: "enforced" } },
] as const;

test("Rollback failure-injection harness records simulated rollback outcomes in the evidence chain", async (t) => {
  for (const [index, scenario] of injectedFailures.entries()) {
    await t.test(scenario.name, async () => {
      const commandId = `rollback-fi-${index}`;
      const plan = VerificationEngine.createPlan({
        action: "simulation.failure-injection",
        agentId: "agent-simulated",
        tenantId: "tenant-simulated",
        commandId,
        snapshotId: `snap-fi-${index}`,
        checks: [{ method: scenario.method, target: scenario.target, expectedState: scenario.expectedState }],
      });

      const result = await VerificationEngine.verify(plan, {});
      assert.equal(result.status, "FAILED");
      assert.equal(result.rollbackActionRequired, true);
      assert.equal(result.rollbackExecuted, true, "current rollback fixture reports its simulated outcome only");
      const evidence = MOCK_HASH_CHAINS.find((event) => event.event_type === "REMEDIATION_ROLLED_BACK" && event.payload.commandId === commandId && event.payload.rollbackExecuted === true);
      assert.ok(evidence, "rollback outcome should be appended to the evidence hash chain");
      assert.equal(evidence?.payload.rollbackExecuted, true);
    });
  }
});
