import "./setup";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { CAPABILITY_REGISTRY } from "../src/lib/fleet/capabilities";
import actionSpecs from "../src/lib/verification-engine/action-specs.json";
import { VerificationEngine } from "../src/lib/verification-engine";
import { VerificationMethods } from "../src/lib/verification-engine/methods";
import { VerificationCheckSpec } from "../src/lib/verification-engine/types";

describe("Declarative action verification specifications", () => {
  it("defines success, failure, verification and rollback contracts for every registered capability", () => {
    assert.deepEqual(Object.keys(actionSpecs).sort(), Object.keys(CAPABILITY_REGISTRY).sort());
    for (const spec of Object.values(actionSpecs)) {
      assert.ok(spec.verification_methods.length > 0);
      assert.ok(spec.success_condition.length > 0);
      assert.ok(spec.failure_condition.length > 0);
      assert.ok(spec.rollback_procedure.procedure.length > 0);
      assert.equal(typeof spec.rollback_procedure.available, "boolean");
    }
  });

  it("rejects unregistered actions instead of inventing a generic health check", () => {
    assert.throws(() => VerificationEngine.createPlan({ action: "mystery_action", agentId: "a", tenantId: "t", commandId: "c" }), /No registered verification specification/);
  });

  it("fails closed for unsupported verification methods", async () => {
    const plan = VerificationEngine.createPlan({
      action: "process.inspect", agentId: "a", tenantId: "t", commandId: "c",
      checks: [{ method: "custom_script_check", target: "anything", expectedState: { ok: true } }],
    });
    const result = await VerificationEngine.verify(plan, { status: "healthy" });
    assert.equal(result.verified, false);
    assert.match(result.failureReason || "", /unsupported/);
  });

  it("requires explicit restricted-quarantine evidence and verifies snapshot state", async () => {
    const quarantine: VerificationCheckSpec = { method: "file_quarantine_check", target: "C:/malware.exe", expectedState: { quarantined: true } };
    assert.equal((await VerificationMethods.checkFileQuarantine(quarantine, { quarantinedFiles: [{ originalPath: quarantine.target, quarantined: true, restricted: true, originalPathPresent: false }] })).success, true);
    assert.equal((await VerificationMethods.checkFileQuarantine(quarantine, { quarantinedFiles: [{ originalPath: quarantine.target, quarantined: true, restricted: false, originalPathPresent: false }] })).success, false);

    const snapshot: VerificationCheckSpec = { method: "snapshot_state_check", target: "snap-1", expectedState: { exists: true } };
    assert.equal((await VerificationMethods.checkSnapshotState(snapshot, { snapshots: [{ id: "snap-1" }] })).success, true);
    assert.equal((await VerificationMethods.checkSnapshotState(snapshot, {})).success, false);
  });

  it("reports partial patch proof as failed when the post-patch vulnerability rescan fails", async () => {
    const plan = VerificationEngine.createPlan({ action: "apply_patch", agentId: "a", tenantId: "t", commandId: "c", cveId: "CVE-1", expectedVersion: "2.0" });
    const result = await VerificationEngine.verify(plan, { installedVersion: "2.1", cveStatus: "vulnerable" });
    assert.equal(result.checks.length, 2);
    assert.equal(result.checks[0].success, true);
    assert.equal(result.checks[1].success, false);
    assert.equal(result.verified, false);
    assert.equal(result.status, "FAILED");
  });
});
