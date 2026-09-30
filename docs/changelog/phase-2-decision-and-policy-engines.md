# Phase 2 & 5 Changelog: Decision & Policy Engine Isolation

**Date:** 2026-09-30  
**Phase:** Phase 5 (Decision Engine) & Phase 6 (Policy Engine)  
**Status:** Complete & Verified  

---

## What Changed
1. **Dedicated Policy Engine (`src/lib/policy-engine/` and `services/policy-engine/`):**
   - Created `src/lib/policy-engine/types.ts` defining autonomy modes (`observe`, `assist`, `autopilot`), asset criticality, condition models, and exceptions.
   - Created `src/lib/policy-engine/defaults.ts` specifying baseline rules for core security actions (`isolate_host`, `restore_host`, `terminate_process`, `apply_patch`, `block_ip`, `reboot_database`).
   - Created `src/lib/policy-engine/engine.ts` implementing deterministic evaluation with critical asset escalation and blast-radius threshold triggers.
   - Exposed service entrypoint in `services/policy-engine/index.ts`.
2. **Dedicated Decision Engine (`src/lib/decision-engine/` and `services/decision-engine/`):**
   - Created `src/lib/decision-engine/types.ts` standardizing the mandatory gateway schema:
     `DecisionInput` (tenant, incident, asset, risk, blast radius, policy, actor, evidence) -> `DecisionOutput` (`ALLOW | DENY | REQUIRE_APPROVAL | REQUIRE_DUAL_APPROVAL`).
   - Created `src/lib/decision-engine/engine.ts` evaluating:
     - `ProductionSafetyGuard` compliance
     - Strict tenant boundaries (anti-IDOR)
     - Actor role permissions (viewers/auditors blocked from initiating changes)
     - Emergency tenant kill switch state
     - "Prove Before You Act" evidence requirements
     - SHA-256 cryptographic decision hashing
   - Exposed service entrypoint in `services/decision-engine/index.ts`.
3. **Governance Integration:**
   - Updated `src/lib/governance/autonomyTier.ts` to delegate `classifyResponseTier()` to `PolicyEngine.evaluatePolicy()`, maintaining backwards compatibility.
   - Added `isKillSwitchEngaged()` and `setKillSwitchState()` with tenant registry tracking in `src/lib/fleet/fleet.ts`.
4. **Automated Verification:**
   - Created `tests/decision-and-policy-engine.test.ts` with 8 comprehensive integration tests.

---

## Security Impact
- **Non-Negotiable Rule 1 & 2 Enforced:** AI cannot bypass deterministic controls. High-impact remediation actions must route through the Decision Engine.
- **Prove Before You Act:** Actions proposed with zero evidence automatically escalate to human approval.
- **Tenant Isolation:** Cross-tenant action propositions are strictly rejected with security boundary violation errors.
- **Kill Switch Enforcement:** If an emergency kill switch is engaged, all remediation actions for that tenant immediately evaluate to `DENY`.

---

## Database Changes
None in this phase.

---

## API Changes
None breaking. Service interfaces exposed for cross-component consumption.

---

## Rollback Procedure
Revert changes to `src/lib/decision-engine/`, `src/lib/policy-engine/`, `services/decision-engine/`, `services/policy-engine/`, and `src/lib/governance/autonomyTier.ts`.

---

## Tests
- `tests/decision-and-policy-engine.test.ts` (8/8 passing)
- Full platform regression suite: 18 suites, 140 tests (140/140 passing)
