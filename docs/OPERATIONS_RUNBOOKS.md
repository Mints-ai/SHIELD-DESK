# Operations signals and runbooks

## Status boundary

Counters and latency histograms are emitted for database queries, agent heartbeats, command dispatch/results, verification/rollback results, AI provider calls, and connector ingestion. `GET /api/metrics` exposes Prometheus text only when `METRICS_BEARER_TOKEN` is configured. Protect it behind private network access and rotate the token. Metrics are process-local; use a supported collector/exporter or shared backend before relying on them in horizontally scaled/serverless deployments.

The included alert rules are templates and are not active until installed in the target Prometheus/Alertmanager and routed to an on-call destination. API p95/p99, queue depth/age, auth failures, certificate expiry, and independent rollback-state confirmation still need instrumentation. Sentry setup does not by itself prove distributed tracing or alert delivery. Verify signal freshness and thresholds in staging.

## Incident response

1. Acknowledge the alert, assign incident commander and technical lead, create an incident record, and preserve timestamps/evidence IDs.
2. Determine tenant and affected service/agents from authenticated records. Avoid copying secrets or customer payloads into public channels.
3. Assess blast radius using available evidence; do not execute remediation from an alert or runbook shortcut.
4. If containment is needed, submit through Decision Engine → Policy → Approval → Execution Broker → Signed Command. Confirm required approver/MFA and snapshot first.
5. Verify resulting endpoint state independently. Treat rollback status strings as unconfirmed until host evidence proves restoration.
6. Communicate customer impact through the approved status channel; retain a timeline, decisions, approvals, evidence references, and recovery actions.
7. Close only after monitoring is stable, owners accept residual risk, and follow-up actions have dates.

## Kill-switch procedure

1. Declare emergency and confirm the target tenant/agent scope with a second operator where available.
2. Use the authenticated administrative kill-switch API. Record actor, tenant, scope, reason, approval/reference, and timestamp.
3. Confirm the database state and agent command-delivery rejection; do not infer endpoint isolation from command disconnection.
4. Keep the switch engaged while investigating queued commands, credentials, and certificate revocations.
5. Re-enable only after incident commander approval, certificate/credential review, agent health verification, and a documented test command through normal policy controls.

## Certificate rotation

1. Identify tenant, agent identity, current serial/fingerprint, expiry and revocation status.
2. Verify the replacement identity and key custody using the supported rotation workflow. Do not transmit private keys through logs or tickets.
3. Install and validate the replacement certificate while preserving a documented rollback window.
4. Confirm mTLS heartbeat and signed result using the new identity; then revoke the old certificate and verify rejection.
5. Record both serials, operator, approval, timestamps, endpoint test result and evidence-chain ID. Escalate if agent reconnect fails; avoid bypassing certificate validation.

## Alert ownership

Configure each rule in `monitoring/prometheus-alerts.yml` with a named service owner, pager route, maintenance policy, runbook URL and tested threshold. Review false positives after a staging exercise; never disable a security failure alert without recorded risk approval.
