# ShieldDesk — Enterprise Data Retention & Lifecycle Management

**Document Version:** 1.0.0  
**Target Release:** ShieldDesk Enterprise SaaS GA  
**Compliance Standards:** GDPR (Art. 5, 17, 32), SOC 2 Type II, ISO 27001, HIPAA Security Rule  
**Core Invariant:** Automated data lifecycle expiration with verifiable cryptographic purge.

---

## 1. Retention Schedules by Subscription Tier

Data retention windows are strictly bound to tenant licensing tiers:

| Tier | Raw Endpoint Telemetry | Investigated Incidents | Compliance & Evidence Vault | Backup Snapshots |
| :--- | :--- | :--- | :--- | :--- |
| **Starter** | 14 days | 30 days | 30 days | 14 days |
| **Professional**| 90 days | 180 days | 180 days | 30 days |
| **Enterprise** | 365 days (configurable) | 730 days | 7 years (statutory compliance) | 90 days |

---

## 2. Storage Tiering Lifecycle (Hot / Warm / Cold)

```
[Ingestion Stream]
        |
        v
[Hot Storage: 0 - 30 Days]
- Primary PostgreSQL Cluster & Redis Cache
- Millisecond query latency for active SOC analysts
        |
        v
[Warm Storage: 31 - 90 Days]
- Partitioned PostgreSQL tables with columnar compression
- Sub-second analytical search for threat hunting
        |
        v
[Cold Storage: 91+ Days]
- Encrypted Object Storage (AES-256-GCM S3 / GCS Glacier)
- Compressed Parquet / JSON bundles, tamper-evident hash manifests
        |
        v
[Cryptographic Purge]
- Automated cryptographic shredding upon retention expiration
```

---

## 3. GDPR Article 17 — Right to Erasure Workflow

When a tenant admin requests full data deletion or a user invokes their right to erasure:
1. **Tenant De-provisioning:** The tenant is placed in `PURGE_PENDING` status; all ingestion streams and agent connections are immediately severed.
2. **Cascading Database Purge:** An automated worker executes:
   ```sql
   DELETE FROM public.tenant_users WHERE tenant_id = $1;
   DELETE FROM public.fleet_agents WHERE tenant_id = $1;
   DELETE FROM public.security_incidents WHERE tenant_id = $1;
   DELETE FROM public.telemetry_events WHERE tenant_id = $1;
   ```
3. **Object Storage Shredding:** Associated S3/GCS buckets and KMS customer-managed encryption keys (CMEK) are shredded.
4. **Evidence Vault Anonymization:** In accordance with GDPR Article 17(3)(b) (compliance with a legal obligation), compliance audit logs retain Merkle tree proof integrity while all personal identifiable information (PII) is irreversibly hashed or anonymized.
5. **Certificate of Destruction:** A cryptographically signed destruction manifest is delivered to the tenant compliance officer.
