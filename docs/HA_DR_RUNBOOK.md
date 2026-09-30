# ShieldDesk Enterprise High Availability & Disaster Recovery Runbook

**Document Version:** 1.0.0  
**Classification:** Enterprise Operational Standard  
**Target RPO (Recovery Point Objective):** < 5 Minutes  
**Target RTO (Recovery Time Objective):** < 30 Minutes  

---

## 1. High Availability Architecture Overview

ShieldDesk's high availability is structured into three decoupled layers:

```
[ Global CDN / Cloudflare WAF ]
              │
              ▼
   [ Ingress Kong Gateway ]
              │
     ┌────────┴────────┐
     ▼                 ▼
[ App Cluster A ] [ App Cluster B ]
     │                 │
     └────────┬────────┘
              ▼
[ HA PostgreSQL / TimescaleDB Primary ]
              │ Streaming Replication (Sync/Async)
              ▼
[ Standby Replica (Multi-AZ) ]
              │ Continuous WAL Archiving
              ▼
     [ Immutable S3 / GCS Vault ]
```

1. **Stateless Control Plane:** Next.js application servers deployed in active-active configurations across multiple availability zones.
2. **Stateful Database Cluster:** PostgreSQL with TimescaleDB extension deployed with synchronous streaming replication to a hot standby in an alternate AZ.
3. **Resilient Endpoint Agents:** Universal Endpoint Agents feature an internal ring buffer (10,000 events) and exponential reconnect backoff to prevent event loss during control plane maintenance or failover.

---

## 2. Automated Backup Strategy

### Continuous Archiving:
- **Engine:** WAL-G or pgBackRest.
- **Full Base Backups:** Taken automatically every 24 hours at 01:00 UTC.
- **Incremental WAL Shipping:** Continuous (archived within 60 seconds of generation).
- **Retention:** 30 days point-in-time recovery; 365 days monthly snapshots encrypted with customer-managed KMS keys.

---

## 3. Disaster Recovery Drill & Restoration Procedure

### Step 1: Declare Incident & Lock Ingress
```bash
# Direct traffic to maintenance page if database is in an inconsistent state
kubectl scale deployment shielddesk-web --replicas=0
```

### Step 2: Restore from Latest Point-in-Time Backup
```bash
# 1. Initialize restore container with target recovery timestamp
pgbackrest --stanza=shielddesk --type=time "--target=2026-09-30 00:00:00+00" restore

# 2. Start PostgreSQL service in recovery mode
systemctl start postgresql
```

### Step 3: Verify Cryptographic Hash-Chain Ledger Integrity
```bash
# Run ledger verification script to confirm zero tampering or gap
npx tsx scripts/verify-hash-chain.ts
```

### Step 4: Resume Application Fleet
```bash
kubectl scale deployment shielddesk-web --replicas=3
```

---

## 4. Endpoint Agent Reconnect Protocol During Control Plane Outages

1. **Local Buffering:** Agents automatically detect HTTP 500/502/503 responses and route events to local memory ring buffer.
2. **Backoff Schedule:** 1s, 2s, 4s, 8s, 16s, capped at 30s.
3. **Drain Sequence:** Once `/api/health/live` returns 200, agents drain their ring buffer in chronological batches without dropping security evidence.
