import "./setup";
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { VerificationEngine } from "../src/lib/verification-engine";
import { RollbackEngine } from "../src/lib/rollback-engine";

describe("Phase 12 & 13: Verification Engine & Rollback Engine Suite", () => {
  // ---------------------------------------------------------------------------
  // Verification Engine Tests
  // ---------------------------------------------------------------------------
  describe("VerificationEngine (Prove Before You Act)", () => {
    it("Plan Creation: Deterministically synthesizes appropriate verification checks", () => {
      // 1. Process termination plan
      const procPlan = VerificationEngine.createPlan({
        action: "terminate_process",
        agentId: "ag-win-01",
        tenantId: "acme-tenant",
        commandId: "cmd-101",
        target: "4812",
        snapshotId: "snap-win-01-abc",
      });
      assert.equal(procPlan.checks[0].method, "process_table_check");
      assert.equal(procPlan.checks[0].target, "4812");
      assert.equal(procPlan.rollbackOnFailure, true);

      // 2. Host isolation plan
      const isoPlan = VerificationEngine.createPlan({
        action: "isolate_host",
        agentId: "ag-linux-01",
        tenantId: "acme-tenant",
        commandId: "cmd-102",
      });
      assert.equal(isoPlan.checks[0].method, "firewall_rule_check");
      assert.equal(isoPlan.checks[0].expectedState.active, true);

      // 3. Patch verification plan
      const patchPlan = VerificationEngine.createPlan({
        action: "apply_patch",
        agentId: "ag-linux-01",
        tenantId: "acme-tenant",
        commandId: "cmd-103",
        cveId: "CVE-2024-1234",
      });
      assert.equal(patchPlan.checks[0].method, "package_version_check");
      assert.equal(patchPlan.checks[0].target, "CVE-2024-1234");
    });

    it("Rule 3 Invariant: Never treat command execution as success without state verification", async () => {
      const plan = VerificationEngine.createPlan({
        action: "terminate_process",
        agentId: "ag-win-01",
        tenantId: "acme-tenant",
        commandId: "cmd-201",
        target: "mimikatz.exe",
        snapshotId: "snap-win-01-xyz",
      });

      // Simulation: Command agent returned 'exit code 0', BUT host evidence still shows process running!
      const unverifiedEvidence = {
        commandExitCode: 0, // Fake/misleading exit code!
        runningProcesses: [
          { pid: 512, name: "services.exe" },
          { pid: 994, name: "mimikatz.exe" }, // Target is STILL running!
        ],
      };

      const result = await VerificationEngine.verify(plan, unverifiedEvidence);

      assert.equal(result.verified, false, "Must not verify when process is still running");
      assert.equal(result.status, "FAILED");
      assert.equal(result.rollbackActionRequired, true, "Must flag rollback as required");
      assert.match(result.failureReason || "", /still active on endpoint/i);
      assert.ok(result.verificationHash && result.verificationHash.length === 64);
    });

    it("Verification Success: Confirms remediated host state and returns VERIFIED", async () => {
      const plan = VerificationEngine.createPlan({
        action: "terminate_process",
        agentId: "ag-win-01",
        tenantId: "acme-tenant",
        commandId: "cmd-202",
        target: "4812",
        snapshotId: "snap-win-01-xyz",
      });

      // Valid post-execution host state: PID 4812 is absent
      const verifiedEvidence = {
        runningProcesses: [
          { pid: 512, name: "services.exe" },
          { pid: 1204, name: "explorer.exe" },
        ],
      };

      const result = await VerificationEngine.verify(plan, verifiedEvidence);

      assert.equal(result.verified, true);
      assert.equal(result.status, "VERIFIED");
      assert.equal(result.rollbackActionRequired, false);
      assert.ok(result.verificationHash && result.verificationHash.length === 64);
    });
  });

  // ---------------------------------------------------------------------------
  // Rollback Engine Tests
  // ---------------------------------------------------------------------------
  describe("RollbackEngine (Governed Reversion)", () => {
    it("RollbackEngine: Reverts state using snapshot and records hash-chain ledger entry", async () => {
      const rollback = await RollbackEngine.executeRollback({
        tenantId: "acme-tenant",
        agentId: "ag-win-01",
        commandId: "cmd-201",
        snapshotId: "snap-win-01-xyz",
        rollbackType: "snapshot_restore",
        reason: "Post-remediation state verification failed: mimikatz.exe remained active.",
        actorId: "engine:verification",
      });

      assert.equal(rollback.success, true);
      assert.equal(rollback.snapshotId, "snap-win-01-xyz");
      assert.equal(rollback.rollbackType, "snapshot_restore");
      assert.ok(rollback.rollbackId.startsWith("rb-ag-win-01"));
      assert.ok(rollback.rollbackHash && rollback.rollbackHash.length === 64, "Must generate SHA-256 hash");
      assert.match(rollback.output, /snap-win-01-xyz/);
    });

    it("Network Rollback: Executes restore_host for failed or aborted isolation", async () => {
      const rollback = await RollbackEngine.executeRollback({
        tenantId: "acme-tenant",
        agentId: "ag-linux-01",
        commandId: "cmd-305",
        snapshotId: "snap-net-01",
        rollbackType: "network_rollback",
        reason: "Operator manually triggered rollback of host isolation.",
        actorId: "usr-admin-secops",
      });

      assert.equal(rollback.success, true);
      assert.equal(rollback.rollbackType, "network_rollback");
      assert.ok(rollback.rollbackHash && rollback.rollbackHash.length === 64);
    });
  });
});
