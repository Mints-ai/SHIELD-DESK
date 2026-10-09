# ShieldDesk — Sovereign Data Residency Architecture

**Document Version:** 1.0.0  
**Target Release:** ShieldDesk Enterprise SaaS GA  
**Compliance Frameworks:** UAE PDPL (Federal Decree-Law No. 45/2021), EU GDPR (Schrems II), US Cloud Act / FedRAMP Moderate  
**Core Invariant:** Absolute geographic data isolation; zero cross-border telemetry leakage without customer authorization.

---

## 1. Multi-Region Sovereign Footprint

ShieldDesk maintains independent regional control planes and data isolation zones:

| Region Identifier | Geographic Location | Cloud Ingress / Datacenter | Regulatory Alignment |
| :--- | :--- | :--- | :--- |
| `uae-central` | Dubai / Abu Dhabi, UAE | AWS ME (Bahrain / UAE) / Azure UAE | UAE PDPL, NESA, ISR |
| `eu-west` | Frankfurt / Dublin | AWS Frankfurt (eu-central-1) | EU GDPR, Schrems II |
| `us-east` | N. Virginia / Ohio | AWS us-east-1 / GCP us-central1 | SOC 2 Type II, HIPAA, FedRAMP |

---

## 2. Tenant Regional Binding Architecture

```
[Customer Traffic Ingress]
           |
           v
[Global Anycast DNS & Edge Router (Cloudflare / GeoDNS)]
           |
           +---> Tenant Region Lookup via Organization Domain / Host
           |
           v
+-----------------------------------------------------------------------------------+
|                        Designated Sovereign Region (e.g., UAE)                     |
+-----------------------------------------------------------------------------------+
|  [Regional Control Plane Web & API Cluster]                                       |
|  [Isolated PostgreSQL Cluster (Encrypted with Regional AWS KMS / Cloud HSM)]      |
|  [Local Redis In-Memory Cache]                                                    |
|  [Regional S3 Object Storage & Evidence Vault]                                    |
|  [Regional AI LLM Gateway Endpoints (In-Region Inference)]                        |
+-----------------------------------------------------------------------------------+
```

### Architectural Controls

1. **Database Partitioning by Region:** Every tenant is strictly pinned to a physical database cluster located within their designated sovereign region.
2. **In-Region LLM Processing:** Tenants bound to `eu-west` or `uae-central` route AI model requests exclusively to regional private inference endpoints (e.g., European/Middle Eastern hosted instances) to prevent extraterritorial data transit.
3. **Dedicated Encryption Keys (CMEK):** Customer-Managed Encryption Keys remain resident within regional HSMs and never leave the host country.
4. **Audit Attestation:** Every log emitted to the Evidence Vault includes a signed cryptographic attestation verifying the host server's geographic location.
