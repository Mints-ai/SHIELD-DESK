# Resilience, backup and recovery

## Proposed service objectives

These are planning targets, not measured service commitments. Product and infrastructure owners must approve them, and operations must demonstrate them in a recovery exercise before publishing an SLA.

| Measure | Proposed target | Current evidence |
|---|---:|---|
| Recovery Point Objective (RPO) | 15 minutes | Not measured; backup/PITR configuration must be confirmed in the target environment. |
| Recovery Time Objective (RTO) | 4 hours | Not measured; requires a timed restore and application recovery drill. |
| Backup retention | 35 daily copies and 12 monthly copies | Proposed minimum; retention and encryption must be verified with the hosting provider. |

**HA/DR status: BLOCKED-ON-HUMAN** until owners approve the targets and run the exercises against production-equivalent infrastructure.

## Backup policy

- Back up PostgreSQL using the provider's supported consistent snapshot/PITR mechanism. Include WAL/PITR configuration where available.
- Encrypt backups at rest and in transit; restrict restore credentials; record backup identifier, source, timestamp, checksum, and retention expiry.
- Keep at least one copy in a separate failure domain. Confirm key recovery and deletion/retention behavior with the provider.
- Preserve evidence and audit data under the same tenant isolation and retention controls as the primary database.
- Alert on missed backup windows, failed integrity checks, and retention-policy drift.

## Restore procedure

1. Declare incident, assign incident commander and recovery operator, and record incident/evidence IDs.
2. Select the last known good backup and required WAL/PITR point. Verify source account, region, timestamp, integrity, and encryption-key access.
3. Restore into a new isolated database. Never overwrite the only surviving production copy during validation.
4. Run schema/migration checks, tenant-boundary checks, integrity queries, authentication checks, and application smoke checks.
5. Compare recovered data to the approved recovery point; record observed RPO, elapsed RTO, gaps, and evidence hashes.
6. Obtain owner approval before traffic cutover. Preserve the original database and recovery logs until incident closure.
7. Document follow-up actions and update targets only after a reviewed exercise.

## Scripts and exercises

- `scripts/verify_backup.ps1` performs a local checksum check and, for PostgreSQL custom-format archives, a non-mutating `pg_restore --list` integrity check.
- `scripts/restore_test.ps1` restores only to a database whose name starts with `shielddesk_restore_test_`; it requires an explicit disposable target URL.
- `load-tests/health.js` is a minimal k6 health-endpoint smoke/load scenario. It is not a capacity result or production benchmark.
- Chaos exercise plan: simulate DB failover, delayed/missing backups, connector outage, AI provider timeout, queue backlog, agent disconnect, and certificate rotation. Confirm alerts and safe fail-closed behavior, then recover and reconcile evidence.

Record the environment, software version, backup ID, start/end times, observed RPO/RTO, checks performed, operator, approver, and remediation for every exercise.
