# ShieldDesk — Governed Remediation Architecture

**Document Version:** 1.0.0  
**Date:** 2026-10-09  
**Status:** `IMPLEMENTED` / `TESTED`  
**Core Motto:** *PROVE BEFORE YOU ACT*  
**Primary Engine:** [src/lib/broker/executionBroker.ts](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/src/lib/broker/executionBroker.ts)

---

## 1. Remediation Lifecycle

High-impact remediation actions in ShieldDesk never execute through unverified LLM commands or direct shell dispatch. Every remediation strictly traverses the 10-stage pipeline:

```
1. DETECT         -> Telemetry ingested and normalized (Sigma/YARA)
2. UNDERSTAND     -> Context enrichment (CVE scoring, asset metadata)
3. PROVE          -> Attack-path and blast-radius graph calculations
4. DECIDE         -> Decision Engine evaluates risk & autonomy policy
5. SIMULATE       -> Pre-execution simulation of downtime & reversibility
6. APPROVE        -> Human dual-control governance sign-off (Tier 2/3)
7. SNAPSHOT       -> Pre-execution host state snapshot recorded
8. EXECUTE        -> Ephemeral token dispatched to agent with RSA signature
9. VERIFY         -> Verification Engine queries actual physical host state
10. ROLLBACK      -> Automatic snapshot recovery triggered if verification fails
```

---

## 2. Capabilities Allowlist

Endpoint execution is strictly constrained to 10 canonical capabilities defined in [src/lib/fleet/capabilities.ts](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/src/lib/fleet/capabilities.ts):
- `isolate_host`: Disconnects host from network while preserving control-plane mTLS connection.
- `restore_host`: Reverts network isolation rules.
- `block_ip`: Inserts drop firewall rule for target malicious IP.
- `unblock_ip`: Removes drop firewall rule.
- `kill_process`: Terminates process by PID or image name with protected OS process guardrails.
- `quarantine_file`: Moves malicious file to encrypted vault storage.
- `collect_telemetry`: Gathers CPU, memory, active sockets, and process trees.
- `take_snapshot`: Records host network state, active processes, and open ports.
- `revert_snapshot`: Reverts host state to recorded snapshot baseline.
- `audit_inspect`: Verifies file hashes and package versions against upstream baselines.

Arbitrary command shell execution (`sh`, `bash`, `cmd`, `powershell`) without capability allowlisting is **strictly forbidden**.

---

## 3. Verification Evidence

Verified across:
- `tests/golden-path-production.test.ts` (20-Step Closed Loop Remediation passing)
- `tests/phase-h-execution-broker.test.ts` (7/7 passing)
- `tests/decision-and-policy-engine.test.ts` (7/7 passing)
