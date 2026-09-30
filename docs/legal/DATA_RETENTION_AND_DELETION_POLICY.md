# ShieldDesk — Data Retention & Deletion Policy

## 1. Retention Schedules by Data Class

| Data Class | Default Retention | Configurable Enterprise Window | Storage Mechanism |
| :--- | :--- | :--- | :--- |
| **Active Telemetry (Raw)** | 30 Days | 7 - 90 Days | High-throughput time-series store |
| **Normalized Security Events** | 90 Days | 30 - 365 Days | Partitioned PostgreSQL tables |
| **Incident Dossiers & AI Reports** | 1 Year | 1 - 7 Years | Encrypted relational store |
| **Evidence Vault & Merkle Ledger** | 7 Years | Indefinite (Immutable) | WORM (Write Once Read Many) compliant object store |
| **Audit Logs (Authentication & Governance)** | 3 Years | 1 - 7 Years | Append-only encrypted log store |

## 2. Customer-Initiated Deletion & Offboarding
- Customers may request complete data purging upon tenant deactivation.
- Soft-deletion persists for a 14-day grace period to safeguard against accidental deletion.
- Permanent cryptographic erasure is executed on day 15, zeroing all tenant encryption keys and purging tenant-tagged partitions across database and object stores.
- A cryptographic Deletion Certificate signed by ShieldDesk is provided to the Customer.
