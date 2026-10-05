# Customer pilot plan

**Status: BLOCKED-ON-HUMAN.** Requires a consenting pilot customer, named customer sponsor, support coverage, and signed pilot agreement.

## Entry criteria

- Security and legal owners approve data flow, retention, incident contacts, pilot scope, and rollback/kill-switch procedures.
- Customer selects non-critical assets and provides a dedicated tenant and test agent group.
- Production secrets, TLS, backups, monitoring, alert routing, and tenant boundary checks are reviewed.
- Remediation begins in observe/simulate mode; any live state change requires explicit customer approval and the full Decision → Policy → Approval → Execution Broker → Signed Command path.
- Customer is told which agent actions and OS versions are supported and which controls are test-only or simulated.

## Pilot stages and measures

1. **Read-only onboarding:** install/enroll/heartbeat, connector ingestion, alert quality, tenant isolation, support response.
2. **Simulation:** run proposed decisions, policy outcomes, blast-radius analysis, and verification plans without executing.
3. **Controlled low-risk actions:** limited assets, approved window, operator present, confirmed snapshot and restoration procedure.
4. **Review:** reconcile false positives/negatives, latency, availability, operational burden, rollback evidence, and customer feedback.

Agree numeric success thresholds with the customer before start (availability, alert quality, response latency, and support response). Maintain a daily issue log and incident channel. Stop on tenant leakage, unapproved execution, missing audit evidence, failed safety controls, or customer request. Pilot completion requires written customer acceptance and documented open risks; it does not imply general production validation.
