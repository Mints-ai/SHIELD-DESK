# ShieldDesk Autonomy Tiers & Response Governance

ShieldDesk implements a progressive autonomy framework that ensures high-risk remediation actions are never executed without proper authorization.

---

## 1. The 4 Autonomy Tiers

| Tier | Category | Risk Profile | Authorization Requirement | Example Actions |
|---|---|---|---|---|
| **Tier 0** | **Passive Visibility** | Read-Only | None (Autonomous) | Telemetry ingest, process anomaly detection, CVE mapping, report generation. |
| **Tier 1** | **Low-Impact Reversible** | Low Risk | Autonomous (Within blast-radius throttle) | Safety snapshot, flush DNS, block known external C2 IP on single host. |
| **Tier 2** | **Containment & Disruption** | Medium Risk | Single Human Sign-Off (Responder / Admin with MFA) | Workstation network isolation, kill malicious process, revoke user session. |
| **Tier 3** | **High-Impact / Destructive** | High Risk | Dual-Approval (Two independent Super Admins with MFA) | Fleet-wide host isolation, domain controller certificate revocation, service shutdown. |

---

## 2. Separation of Duties

To comply with SOC 2 CC6.3 and ISO 27001 A.5.25:
- The operator requesting an approval token cannot approve their own action.
- Approval tokens are single-use, bound to a specific tenant ID, action hash, and target endpoint IDs.
- Expired tokens (>15 minutes by default) are automatically rejected.
