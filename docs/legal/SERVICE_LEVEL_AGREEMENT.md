# ShieldDesk — Enterprise Service Level Agreement (SLA)

**Target Availability:** 99.9% Uptime  
**Applicability:** Production SaaS Subscriptions (Growth & Enterprise Tiers)  

## 1. Availability Commitment
ShieldDesk commits to maintain an operational Service Availability of at least 99.9% during each calendar month, excluding scheduled maintenance.

$$\text{Monthly Uptime \%} = \frac{\text{Total Minutes} - \text{Downtime Minutes}}{\text{Total Minutes}} \times 100$$

## 2. Incident Response Times

| Severity | Definition | Initial Response Target | Remediation / Workaround Target |
| :--- | :--- | :--- | :--- |
| **P1 - Critical** | Control plane outage or fleet command signing gateway unavailable | < 15 minutes | < 2 hours |
| **P2 - Major** | Telemetry ingestion degraded or AI gateway latency elevated | < 30 minutes | < 6 hours |
| **P3 - Moderate** | Reporting, digital twin graph sync, or non-blocking UI issue | < 2 hours | < 24 hours |
| **P4 - Low** | Minor cosmetic defect or enhancement inquiry | < 8 hours | Next scheduled release |

## 3. Service Credits
If monthly availability falls below the commitment, customer is entitled to Service Credits:
- 99.0% - 99.9%: 10% credit of monthly billing
- 95.0% - 99.0%: 25% credit of monthly billing
- < 95.0%: 50% credit of monthly billing
