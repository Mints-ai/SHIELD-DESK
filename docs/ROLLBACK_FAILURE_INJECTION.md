# Rollback Failure-Injection Coverage & Host Restoration Validation Boundary

**Product Invariant:** **PROVE BEFORE YOU ACT (Rule 3)**  
**Outcome Taxonomy:**
- `ROLLBACK_REQUESTED` — Operator or policy requested reversion.
- `ROLLBACK_BLOCKED` — Prevented by kill switch, missing agent identity, or lack of authorization.
- `ROLLBACK_DISPATCHED` — Cryptographically signed rollback command dispatched to remote endpoint.
- `ROLLBACK_IN_PROGRESS` — Remote agent executing snapshot reversion or network un-isolation.
- `ROLLBACK_FAILED` — Remote execution error, timeout, or restore point corruption.
- `SIMULATION_ONLY` — Simulated test execution; strictly prohibited from claiming real host restoration.
- `RESTORATION_UNVERIFIED` — Rollback command finished but post-reversion host verification has not yet run.
- `RESTORATION_VERIFIED` — Independent evidence engine confirmed restored host state.

---

## 1. Automated Test Harness Coverage

The automated test suite (`tests/phase12-13-verification-and-rollback.test.ts` and `tests/commercial-launch-hardening-p0-p1.test.ts`) verifies:
1. Verification failure handling and deterministic rollback triggering.
2. Tamper-evident ledger recording (`REMEDIATION_ROLLED_BACK`, `REMEDIATION_ROLLBACK_BLOCKED`) with cryptographic hash-chaining.
3. Simulation tagging invariant: any execution with `isSimulated === true` or offline test fixtures is strictly labeled `SIMULATION_ONLY`. It can **NEVER** return `RESTORATION_VERIFIED`.
4. Injected failure modes: snapshot corruption, disk space exhaustion, agent disconnect/timeout, and operator kill-switch blocks.

---

## 2. Real Host Validation Boundary (GA Gate)

While `RollbackEngine` routes signed rollback commands through `executeAgentCommand` and records ledger attestations, **automated CI runs use simulated and in-memory execution adapters**.

> [!WARNING]
> **SIMULATION IS NOT RESTORATION EVIDENCE:**
> CI and unit test execution results (`SIMULATION_ONLY`) demonstrate pipeline logic only. They do not substitute for empirical restoration drills on physical or disposable virtual Windows/Linux endpoints.

### Real Host Exercises Required Prior to Unrestricted GA:
- Snapshot capture and restoration on Windows 10/11 / Server 2022 (VSS / firewall).
- Snapshot capture and restoration on Linux (systemd / nftables / iptables).
- Network un-isolation verify ping and DNS reachability following `restore_host`.
- Service rollback and binary downgrade on live running daemons.
- Restoration behavior under network partition and agent reconnect.

Until dedicated test hosts complete and document these drills, autonomous remediation and automated rollback remain restricted to human-governed pilot deployments.

