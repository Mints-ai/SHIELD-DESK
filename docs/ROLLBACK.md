# ShieldDesk — Governed Rollback Engine

**Document Version:** 2.0.0  
**Date:** 2026-10-10  
**Status:** `IMPLEMENTED` / `VERIFIED`  
**Primary Engine:** [src/lib/rollback-engine/engine.ts](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/src/lib/rollback-engine/engine.ts)  
**Endpoint Handler:** [agent/pkg/handlers/actions.go](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/agent/pkg/handlers/actions.go)

---

## 1. Governed Rollback Lifecycle & Core Principle

Remediation operations in enterprise production environments carry inherent operational risk (e.g. unintended network partition, critical service failure, or dependency breakage).

In accordance with ShieldDesk's core engineering principle—**PROVE BEFORE YOU ACT**—rollback operations:
1. **Never bypass normal governance controls:** Rollbacks execute through the identical authorization, policy evaluation, signed command dispatch, and evidence verification channels as primary actions.
2. **Never claim success without independent verification:** An enqueued rollback command, HTTP 200 response, or audit entry is not proof of state restoration. Restoration must be verified on the host.
3. **Fail closed:** If a rollback target or snapshot cannot be validated, the rollback is flagged as `ROLLBACK_BLOCKED` or `ROLLBACK_FAILED`, and the incident remains open for manual intervention.

### Rollback Outcome States

| State | Definition | Success Semantics |
| :--- | :--- | :--- |
| `ROLLBACK_REQUESTED` | Rollback triggered by verification failure or operator command; pending dispatch | In-progress |
| `ROLLBACK_BLOCKED` | Rollback denied by kill-switch, tenant boundary, missing agent, or unsupported capability | `false` |
| `ROLLBACK_DISPATCHED` | Cryptographically signed reverse command enqueued to target agent channel | Dispatched (`true`) |
| `ROLLBACK_IN_PROGRESS` | Agent acknowledged receipt; rollback command actively executing on host | In-progress |
| `ROLLBACK_FAILED` | Command failed on host, timeout occurred, or agent severed connection | `false` |
| `RESTORATION_VERIFIED` | Host state independently re-verified (e.g., firewall restored, service up, connectivity recovered) | `true` |
| `RESTORATION_UNVERIFIED` | Command reported exit 0, but host telemetry could not independently verify state recovery | `false` |

---

## 2. Reversible Action Matrix & Real Snapshot Semantics

| Remediation Action | Reverse Action | Snapshot Resource | Verification Check | Host Support Status |
| :--- | :--- | :--- | :--- | :--- |
| `isolate_host` | `restore_host` | WFW export (`.wfw`) on Windows; `iptables-save` on Linux | Control-plane socket check & ping restoration | `VERIFIED` (Native Agent) |
| `block_ip <IP>` | Netsh/iptables rule deletion | Rule chain baseline snapshot | Rule absent from table; destination reachable | `VERIFIED` (Native Agent) |
| `kill_process <PID>` | `service.restart <name>` | PID process table snapshot & service mapping | Service daemon active in OS process table | `VERIFIED` (Systemd / WinSvc) |
| `quarantine_file` | `unquarantine_file` | Encrypted quarantine vault blob | File restored to original path & SHA-256 verified | `IMPLEMENTED` (Broker) |
| `apply_patch` | `package_downgrade` | Package manager rollback baseline (`apt`/`yum`/`winget`) | Package version check matches baseline | `BLOCKED_ON_INFRASTRUCTURE` (Requires Host Pkg Repos) |

> [!IMPORTANT]
> **Snapshot Semantics:**  
> - **Native Agent Firewall Snapshot:** Real OS-level snapshot. Windows exports active policy via `netsh advfirewall export <snapId>.wfw`; Linux exports rules via `iptables-save`. Reversion applies `netsh advfirewall import` or `iptables-restore`.  
> - **Filesystem / OS Snapshot:** Full volume LVM/VSS snapshots require dedicated virtualization or storage layer integration (e.g., AWS EBS, VMware, Proxmox). When running without volume snapshot agents, filesystem actions are restricted to configuration file backups.

---

## 3. Rollback Failure Injection & Canary Defenses

Validated in:
- [tests/rollback-failure-injection.test.ts](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/tests/rollback-failure-injection.test.ts): 8 injected failure scenarios (patch, service, network, snapshot corruption, disk full, agent disconnect, reboot, and partial execution).
- [tests/phase-h-execution-broker.test.ts](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/tests/phase-h-execution-broker.test.ts): Canary rollouts halt on first failure and trigger automated rollback across canary cohorts.
- [tests/safety-boundary.test.ts](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/tests/safety-boundary.test.ts): Emergency kill-switch strictly blocks rollback dispatch with `ROLLBACK_BLOCKED`.

---

## 4. Verification Evidence & Automated Test Matrix

- `tests/verification-and-rollback-engine.test.ts`: Governed reversion and state verification.
- `tests/closed-loop-orchestration-pipeline.test.ts`: Verification failure automatically triggers governed rollback.
- `tests/safety-boundary.test.ts`: Production safety boundaries and kill-switch enforcement on rollback.
- `agent/pkg/handlers/actions_test.go`: Native Go agent snapshot capture and rollback handlers.
