# Phase B: Security Digital Twin — Postgres Graph

**Branch:** `feature/phase-b-security-digital-twin`  
**Date:** 2026-09-30  
**Tests:** 244/244 passing (19 new Phase B tests added, 225 from prior phases preserved)  
**TypeScript:** 0 errors  
**DB Migration:** `db/migrations/phase_b_security_digital_twin.sql` applied — 27 total tables  

---

## What Was Built

### Database (3 new tables)

| Table | Purpose |
| --- | --- |
| `twin_nodes` | Vertices of the security knowledge graph (assets, CVEs, identities, business services) with FK to `assets`, criticality, status, environment |
| `twin_edges` | Directed edges between nodes with relation type, bidirectional flag, port/protocol, and FK cascade deletion |
| `twin_sync_log` | Audit trail for every Phase A event → graph sync operation (nodes/edges upserted, duration, errors) |

All tables use Postgres RLS with `app.current_tenant` tenant isolation and purpose-built composite indexes for CTE traversal performance.

### Postgres CTE Graph Engine (`src/lib/security-twin/twinDbAdapter.ts`)

Seven durable graph operations powered by recursive CTEs:

| Function | Description |
| --- | --- |
| `upsertNodeToDB(node)` | INSERT … ON CONFLICT idempotent node write |
| `upsertEdgeToDB(edge)` | INSERT … ON CONFLICT idempotent edge write |
| `getNodeFromDB(tenantId, id)` | Single node fetch |
| `getNodesFromDB(tenantId, type?)` | Tenant-scoped node list |
| `getEdgesFromDB(tenantId)` | All edges for tenant |
| `getReachableFromDB(tenantId, start, maxDepth)` | **Recursive CTE** — forward reachability traversal with cycle guard |
| `getInboundReachableFromDB(tenantId, target, maxDepth)` | **Recursive CTE** — reverse reachability (attack surface) |
| `findAttackPathsFromDB(tenantId, target, maxDepth)` | **Recursive CTE** — all shortest attack paths as path arrays, cycle-guarded, limited to 100 results |
| `simulateIsolationInDB(tenantId, target)` | Full isolation simulation via CTE: severed edges + upstream + business services + identities + blast-radius score |

Every function returns `{ data, durationMs }` for benchmarking against the 50 ms latency target.

### Phase A → Twin Sync Pipeline (`src/lib/security-twin/twinSyncPipeline.ts`)

Automatic graph construction from `CanonicalSecurityEvent` batches:

| Event Field | Graph Objects Created |
| --- | --- |
| `affectedAsset.hostname` | `TwinNode` (type inferred from hostname pattern, criticality from `AssetCriticalityService`) |
| `vulnerability.cveId` | `TwinNode` (type=vulnerability) + `has_vulnerability` edge |
| `processContext.name` | `TwinNode` (type=application) + `runs_on` edge |
| `networkContext.srcIp/dstIp` | `can_reach` edge + auto-discovered endpoint node |

**Dual-write:** in-memory `SecurityDigitalTwin` (hot path) + Postgres (durable checkpoint). `persistToDB: false` skips all DB calls safely (used in tests).

**Stable IDs:** `SHA-256(tenant|type|key)[:16]` — same inputs always produce the same node/edge ID, enabling safe upserts.

### Critical Technical Decision: Lazy DB Import

`TwinSyncPipeline` uses `await import(...)` (dynamic import) for db-dependent modules to prevent `server-only` from being resolved at module load time. This keeps the tsx test runner happy without disabling the server-only protection in production Next.js context. The existing `src/lib/db/index.ts` guard (`import "server-only"`) is preserved.

---

## What Is Still Not Production-Ready

1. **CTE depth limit:** `maxDepth = 6` is configurable but not tenant-configurable yet. Large enterprise graphs may need adjustment.
2. **No graph TTL / stale node cleanup:** Nodes auto-discovered from events accumulate indefinitely. A housekeeping job (Phase H) should evict nodes unseen for > 30 days.
3. **Twin → DB initial bulk load:** The sync pipeline only handles new events. Existing events in `security_events` are not retroactively synced. A backfill job is needed on first deploy.
4. **findAttackPathsFromDB LIMIT 100:** In very large graphs this may miss paths. Phase D will add configurable result limits per tenant.
