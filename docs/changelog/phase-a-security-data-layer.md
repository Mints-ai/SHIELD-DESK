# Phase A: Security Data Layer

**Branch:** `feature/phase-a-security-data-layer`  
**Date:** 2026-09-30  
**Tests:** 225/225 passing (26 new Phase A tests added)  
**TypeScript:** 0 errors  
**DB Migration:** `db/migrations/phase_a_security_data_layer.sql` applied to production Supabase  

---

## What Was Built

### Database (4 new tables, 5 new columns on `assets`)

| Table | Purpose |
| --- | --- |
| `security_events` | Canonical normalized event store with dedup fingerprint, CVSS/EPSS/KEV, asset criticality, and recheck scheduling |
| `connector_config` | Per-tenant connector registration with health state tracking |
| `connector_cursors` | Incremental collection cursor persistence (timestamp/offset/sequence/bookmark) |
| `asset_vulnerabilities` | Deduplicated vulnerability findings per asset × CVE across all scanners |

New columns on `assets`: `criticality`, `business_impact`, `asset_value_usd`, `os_family`, `tags`.

All tables use Postgres RLS with `app.current_tenant` tenant isolation.

### Universal Security Event Model (`src/lib/connectors/event-model.ts`)

- `CanonicalSecurityEvent` — extended from `UniversalSecurityEvent` with: CVSS score/vector, EPSS score/percentile, KEV catalogue flag, asset criticality profile, finding context, dedup fingerprint, recheck scheduling.
- `VulnerabilityIntelligence` — structured block for CVE findings (cveId, cvssScore, cvssVector, epssScore, epssPercentile, kevListed, packageName, installedVersion, fixedVersion).
- `AssetCriticalityProfile` — criticality + business impact + justification.
- **Legacy `UniversalSecurityEvent` re-exported unchanged** — all existing tests continue to pass.

### Connector SDK Interface (`ISecurityConnector`)

Seven mandatory methods enforced as a TypeScript interface:
1. `healthCheck(baseUrl, creds)` — connectivity and credential verification
2. `authenticate(baseUrl, creds)` — store credentials; throw `ConnectorAuthError` on failure
3. `collect(tenantId, opts)` — fetch + normalize events using stored cursor
4. `normalize(raw, tenantId)` — pure normalization; no network calls; deterministic
5. `validate(event)` — completeness and consistency check; returns errors/warnings
6. `getCursor()` — returns current cursor for persistence
7. `disconnect()` — graceful cleanup

### Connectors Implemented

| Connector | File | Type | Cursor |
| --- | --- | --- | --- |
| **WazuhConnector** | `src/lib/connectors/wazuh.ts` | SIEM | Offset (integer count) |
| **TrivyConnector** | `src/lib/connectors/trivy.ts` | SCA Scanner (push) | SHA-256 of last report fingerprint |
| **OpenVASConnector** | `src/lib/connectors/openvas.ts` | Network Scanner | Timestamp-based |

### Asset Criticality Service (`src/lib/connectors/asset-criticality.ts`)

- 10-rule deterministic priority table matching hostnames to criticality/business-impact.
- Tenant override registry (from DB or API) takes precedence over default rules.
- `enrich(event)` enriches `CanonicalSecurityEvent` in-place — feeds blast-radius engine.

### Event Deduplication & Finding Correlation (`src/lib/connectors/deduplication.ts`)

**EventDeduplicator:**
- Time-window dedup (default 24h) by `dedupFingerprint`.
- Per-tenant isolation.
- `expire(fingerprint)` for immediate re-ingestion after remediation.

**FindingCorrelator (deterministic — no AI):**
- `cve_campaign` — ≥2 events sharing the same CVE ID
- `ransomware_ioc` — events tagged `ransomware`
- `mass_exploitation` — ≥5 events with identical title pattern
- `lateral_movement` — ≥3 auth failures across ≥2 hosts
- `isolated_alert` — everything else

**Risk Score Formula (fully explainable):**
```
riskScore = min(100, CVSS × 10 + (kevListed ? 20 : 0) + min(spreadCount × 2, 15))
```

---

## What Is Still Not Production-Ready

1. **No persistent cursor storage in DB**: `getCursor()` returns in-memory cursor. For crash-safe operation, the API layer must persist cursor to `connector_cursors` table after each successful collect. This wire-up is Phase B.
2. **EPSS enrichment**: `epssScore`/`epssPercentile` fields are always `undefined` until we integrate the FIRST/EPSS API feed. This is a Phase D enrichment task.
3. **KEV flag enrichment**: `kevListed` is always `false` until we ingest the CISA KEV JSON feed (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`). Phase D.
4. **TrivyConnector is push-only**: The CI/CD pipeline must be configured to POST Trivy JSON reports to the ingest endpoint. No pull mode.
5. **Wazuh and OpenVAS connectors make real HTTP calls**: They are not usable without a real Wazuh/OpenVAS endpoint. Production deployment requires real credentials in `connector_config`.
