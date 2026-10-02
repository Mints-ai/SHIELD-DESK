# Public launch gate checklist

**Status:** Not launch-certified. Checked against repository code and automated test evidence on 2026-10-02. A checked repository item is not a production validation.

| Area | Gate | Status | Evidence / next action |
|---|---|---|---|
| Application | Decision, policy, approval and signed dispatch flow | done (TESTED) | Covered by repository automated tests; validate production settings before release. |
| Application | State verification has declarative specs for each registered capability | done (TESTED) | `src/lib/verification-engine/action-specs.json` and tests; evidence is simulated. |
| Application | Rollback actually restores endpoint state through governed broker | not done | Current rollback engine is descriptive/simulated. Integrate through Decision → Policy → Approval → Execution Broker → Signed Command, then test on hosts. |
| Security | Tenant controls, MFA, certificate checks and command replay protection | done (TESTED) | Automated tests only; external multi-tenant security review is still required. |
| Security | Independent penetration test across web, API, PKI, agent, AI, billing and infrastructure | blocked | Schedule and complete external assessment; see `docs/launch-gates/EXTERNAL_PENETRATION_TEST.md`. |
| Endpoint | Windows/Linux install, enrollment, command, verification, rollback and update matrix | blocked | Execute on the real OS matrix in `docs/launch-gates/ENDPOINT_TEST_MATRIX.md`. |
| Endpoint | Signed commands and simulated command lifecycle | done (TESTED) | Test keypairs and simulated agents; no customer endpoint certification. |
| SaaS | Stripe webhook signature and idempotency coverage | done (TESTED, limited) | Existing webhook tests; full realistic lifecycle sequence and live Stripe validation remain outstanding. |
| SaaS | Dedicated license activation bound to tenant, installation, device identity, X.509 identity and entitlement | not done | A new activation service/API and migration are implemented and unit-tested; enrollment and command-time enforcement are not wired. Complete those gates before launch. |
| SaaS | Customer pilot, support, status communications | blocked | Requires a customer, support owner and operational service. See `docs/launch-gates/CUSTOMER_PILOT.md`. |
| Infrastructure | Backup integrity, restore test, load, chaos and HA/DR exercise | blocked | Use the runbook/scripts in `docs/RESILIENCE_AND_RECOVERY.md`; execute in target environment before asserting RPO/RTO. |
| Infrastructure | Metrics and incident/kill-switch/certificate runbooks | not done | Instrumentation is partial; complete `docs/OPERATIONS_RUNBOOKS.md` actions and verify alert delivery. |
| Commercial | Terms, Privacy, DPA, SLA, subprocessors, disclosure, trust center, status page | blocked | Legal review and product-owner approval required. See `docs/launch-gates/LEGAL_COMMERCIAL_PACK.md`. |

Automated suite status and environment-specific failures are recorded in `docs/PRODUCTION_READINESS_AUDIT.md`. Production validation requires evidence from the target deployment, independent assessors, endpoint hosts, and customer operations; none is inferred from this checklist.
