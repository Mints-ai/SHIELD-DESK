# ShieldDesk — Enterprise Incident Response Plan (IRP)

**Document Version:** 1.0.0  
**Target Release:** ShieldDesk Enterprise SaaS GA  
**Security Operations:** 24/7/365 ShieldDesk SOC & Engineering Escalation  
**Compliance Standard:** NIST SP 800-61 Rev. 2 / ISO 27035

---

## 1. Severity Classifications & SLAs

Security incidents within the ShieldDesk platform are categorized into four severity tiers:

| Severity | Definition | Initial Response SLA | Status Update Frequency | Customer Notification SLA |
| :--- | :--- | :--- | :--- | :--- |
| **SEV-1 (Critical)** | Active compromise of control plane, verified cross-tenant data leakage, or unauthorized code execution in customer fleet. | **< 15 minutes** | Every 30 minutes | Within 2 hours |
| **SEV-2 (High)** | Outage of primary detection/remediation pipeline, failure of verification engine, or suspected compromise of single tenant credentials. | **< 30 minutes** | Every 1 hour | Within 6 hours |
| **SEV-3 (Medium)** | Degraded performance of LLM Gateway, partial delay in telemetry ingestion, or non-exploitable vulnerability identified. | **< 2 hours** | Every 4 hours | Within 24 hours |
| **SEV-4 (Low)** | Minor cosmetic defect, non-critical telemetry sync delay, or informational finding with no operational impact. | **< 8 hours** | Daily | Release notes |

---

## 2. Five-Phase Response Workflow

```
[Phase 1: Detection & Triage]
  - PagerDuty alert fires via Prometheus / Datadog / Sentry / Cloudflare
  - Incident Commander (IC) designated; dedicated Slack war room (#incident-<id>) opened
        |
        v
[Phase 2: Containment & Isolation]
  - Trigger Emergency Tenant Isolation Kill-Switch if malicious activity detected
  - Revoke affected API tokens, rotate session signing keys, isolate rogue agent nodes
        |
        v
[Phase 3: Eradication]
  - Identify root cause (patch vulnerability, terminate unauthorized sessions)
  - Verify integrity of PostgreSQL database partitions and Evidence Vault Merkle chain
        |
        v
[Phase 4: Recovery & Verification]
  - Re-enable services under canary deployment with heightened telemetry logging
  - Execute full end-to-end regression test suite (`npm test`, `go test`)
        |
        v
[Phase 5: Post-Mortem & Evidence Archival]
  - Conduct blameless post-mortem within 48 hours
  - Publish customer-facing RCA (Root Cause Analysis) within 5 business days
```

---

## 3. Emergency Fleet & Tenant Kill-Switch

If an adversarial compromise is suspected within a specific tenant or agent cohort:
1. **Fleet Lockout API:**
   ```bash
   curl -X POST https://app.shielddesk.io/api/fleet/emergency-lockdown \
     -H "Authorization: Bearer $SUPERADMIN_KEY" \
     -d '{"tenantId": "target-tenant", "reason": "Suspected Credential Compromise", "action": "revoke_all_sessions_and_freeze_agents"}'
   ```
2. **Behavior:**
   - Immediately revokes all active session cookies and JWTs.
   - Instructs connected agents to pause all automated execution playbooks.
   - Preserves agent telemetry buffers for forensic extraction without accepting incoming remote commands.
