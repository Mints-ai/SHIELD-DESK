# ShieldDesk launch readiness: evidence-based status

**Review date:** 2026-10-02
**Scope:** Repository evidence only. This is not an independent audit, certification, customer pilot, or production validation.

ShieldDesk is an **Evidence-Driven Security Operations & Remediation** project organized around **Prove Before You Act**. Repository code and automated tests show implemented application components. They do not establish that every configured deployment, endpoint, rollback, or third-party integration works in customer infrastructure.

## Capability status

| Capability | Status | Evidence / boundary |
|---|---|---|
| Decision, policy, approval, execution broker, command signing | TESTED | Repository tests exercise the application flow with test fixtures. Production configuration and customer operations are not validated. |
| Tenant-scoped APIs, RBAC, MFA, certificate checks | TESTED | Automated regression coverage exists; independent security review and external penetration testing remain outstanding. |
| Action-specific verification specs | TESTED | Specs cover the registered action catalog with simulated evidence. Endpoint execution and restoration are not established by these tests. |
| Rollback | IMPLEMENTED | The current `RollbackEngine` writes a descriptive event and returns a simulated success value; it does not dispatch restoration or prove host state. |
| Billing and license modules | IMPLEMENTED | Application modules and tests exist. Stripe account configuration, full lifecycle behavior, and entitlement enforcement at every command boundary require further verification. |
| AI safety and evaluation | TESTED | Local guard and evaluation tests exist. External model behavior, model-version regressions, and production cost/latency are not validated. |
| Metrics and health endpoints | IMPLEMENTED | Instrumentation exists. Alert routing, production SLOs, tracing coverage, and on-call response are not validated. |
| Backup, restore, HA/DR | BLOCKED-ON-HUMAN | Requires executed restore and recovery exercises in the target hosting environment. |
| Endpoint platform support | BLOCKED-ON-HUMAN | Requires the documented Windows/Linux OS matrix on real hosts. |
| External penetration test and customer pilot | BLOCKED-ON-HUMAN | Requires independent testers and a participating customer. |
| Legal/commercial readiness | BLOCKED-ON-HUMAN | Requires qualified legal review and product-owner decisions. |

No capability is marked **PRODUCTION-VALIDATED** in this repository review.

## Automated test snapshot

The full local suite runs with the repository's test files and Node's test runner. On this Windows environment, the last full run had one known Trivy-dependent failure because the `trivy.exe` binary was unavailable and the installer could not download it; CI installs Trivy separately. The passing test count is not a launch certification. See `docs/ROLLBACK_FAILURE_INJECTION.md` for the specific scope of rollback simulation.

## Claim language

- Describe audit records as a **cryptographically tamper-evident audit and evidence trail**. A hash chain alone does not establish non-repudiation.
- Describe relevant controls as **SOC 2-aligned / ISO 27001-aligned controls / NIST CSF mapping** only when supported by an explicit control mapping. Do not claim certification without a valid independent certification.
- Describe attack-path output as models that **prioritize attack paths from available evidence**; do not claim exhaustive discovery.
- Label test-fixture behavior as simulated. Keep **Implemented**, **Tested**, and **Production-Validated** distinct.
