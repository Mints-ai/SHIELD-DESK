# Security Policy — ShieldDesk™

**Product:** ShieldDesk™ Autonomous SOC & Threat Platform  
**Organization:** Mints AI  
**Last Updated:** October 2026  

---

## 1. Reporting a Vulnerability

The ShieldDesk team takes security and trust seriously. If you discover a security vulnerability in ShieldDesk (including the control plane, endpoint agent, cryptographic command signing, or billing subsystems), please report it responsibly.

**Reporting Contacts:**
- **Email:** [security@shielddesk.com](mailto:security@shielddesk.com) or [security@mints.ai](mailto:security@mints.ai)
- **PGP Key:** Available upon request or via standard DNS security records.

**Please include the following in your report:**
1. Component / Route / File affected (e.g., control plane API, Go endpoint agent, webhook processor).
2. Type of issue (e.g., Cross-Tenant Access, Authentication Bypass, Command Injection, SSRF).
3. Detailed reproduction steps or proof-of-concept payload.
4. Impact assessment and potential blast radius.

---

## 2. Response & SLA Commitments

- **Initial Acknowledgement:** Within **24 hours** of submission.
- **Triage & Assessment:** Within **72 hours**.
- **Remediation & Patch Target:** Critical findings prioritized within **7 calendar days**; high-severity findings within **14 calendar days**.
- **Public Disclosure:** Coordinated disclosure after verified patch deployment to all supported release channels.

---

## 3. Supported Versions

Security updates and patches are actively provided for:

| Version | Status | Security Support |
| :--- | :--- | :--- |
| `2.4.x` (Current `main`) | **Supported** | Active security patches and vulnerability advisories. |
| `2.3.x` | **Supported** | Critical CVE and remote code execution fixes only. |
| `< 2.3.0` | **End of Life** | Please upgrade to the latest supported release. |

---

## 4. Responsible Disclosure Guidelines

- Do not access, modify, exfiltrate, or destroy customer production data.
- Avoid denial-of-service (DoS/DDoS) attacks against live infrastructure.
- Give the security team reasonable time to remediate before public disclosure.
- Safe harbor: Security research conducted in good faith within this policy is recognized and protected against legal action.
