# Rollback failure-injection coverage

The Node test harness injects failed post-command evidence for patch, service, network, corrupted snapshot, disk-full, agent disconnect, reboot, and partial-execution scenarios. It asserts failed verification, a rollback attempt, and a corresponding `REMEDIATION_ROLLED_BACK` event in the in-memory hash-chain evidence fixture.

## Validation boundary

**TESTED (simulation only):** verification failure handling and in-memory evidence-chain recording under the eight injected cases.

**IMPLEMENTED, not host-validated:** `RollbackEngine` currently constructs a rollback command description and records an event; it does not dispatch that command to an endpoint or prove state restoration. Its `success` result is therefore not evidence that a host was reverted. Real snapshot corruption, storage exhaustion, process interruption, disconnect/reconnect, and reboot behavior require dedicated endpoint test hosts and remain **BLOCKED-ON-HUMAN**.

Before production use, rollback dispatch must pass the same Decision Engine, Policy, Approval, Execution Broker, and Signed Command controls as other state-changing commands. Do not treat this test harness as authorization to execute a rollback directly.
