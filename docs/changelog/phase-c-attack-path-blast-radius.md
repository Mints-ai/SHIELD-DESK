# Phase C: Attack-Path and Blast-Radius Engines

**Branch:** `feature/phase-c-attack-path-blast-radius`  
**Date:** 2026-09-30  
**Tests:** 252/252 passing (8 new Phase C tests added, 244 from prior phases preserved)  
**TypeScript:** 0 errors  
**DB Migration:** `db/migrations/phase_c_attack_path_blast_radius.sql` applied — 29 total tables in Supabase PostgreSQL  

---

## What Was Built

### 1. Attack-Path Engine (`src/lib/attack-path/`)
- **Ranked Kill-Chain Analysis:** Calculates all deterministic attack paths leading from exposed entry points (DMZ, internet-facing, APIs, endpoints) to target crown jewels.
- **Explainable Narratives & MITRE ATT&CK Mapping:** Every path provides:
  - `rank`: Sorted strictly by `aggregateRiskScore` descending.
  - `killChainSummary`: Concise tactic progression (e.g., `Initial Access (T1190) → Lateral Movement (T1021) → Impact (T1485)`).
  - `explanation`: Full human-readable breakdown of the adversary's traversal mechanics.
  - Step-level `mitreTactic`, `technique`, `likelihood`, and step `rationale`.
  - Evidence citations linking each step to concrete network ports, protocols, CVEs, or identity bindings.
- **Choke-Point Efficacy:** Identifies intermediate nodes across attack paths, computing the exact number of paths severed and `riskReductionPercentage` if isolated or remediated.
- **Fail-Closed Target Scoping:** Unregistered assets fail closed, returning structured empty paths with descriptive guidance.

### 2. Blast-Radius Engine (`src/lib/blast-radius/`)
- **Multi-Dimensional Impact Analysis:**
  - **Services:** Evaluates affected upstream and downstream business services, categorizing into `tier_1_mission_critical` vs `tier_2_standard`.
  - **Apps:** Isolates affected applications and APIs with environment and criticality tags.
  - **Users:** Identifies affected human identities, service accounts, and departments.
  - **Sensitive Systems:** Deep scan of affected assets for compliance tags: PII, PCI DSS, SOX 404, HIPAA, and crown jewel assets.
  - **Downtime Modeling:** Computes expected downtime minutes and severity (`none`, `minimal`, `moderate`, `major`, `catastrophic`) based on the requested action (`isolate_host`, `restart_service`, `patch_vulnerability`).
  - **Rollback Availability Assessment:** Validates automated reversion capability (`restore_host`, `revert_network_rules`, `restart_service`, `reinstall_package`), snapshot requirement, and reversibility risk (`low`, `medium`, `high`).
  - **Targeted Mitigation Options:** Proposes surgical containment alternatives (such as severing an entry-point choke point) to prevent unnecessary full-host downtime.
- **Calculation Modes:** Explicitly tags reports as `measured` (complete topology), `inferred` (partial graph), `simulated` (isolated topology), or `estimated` (unregistered fallback).

### 3. Database Schema & Persistence (`db/migrations/phase_c_attack_path_blast_radius.sql`)
- Added `attack_path_reports` table for historical audit, risk trend analysis, and Decision Engine consumption.
- Added `blast_radius_reports` table with multi-dimensional JSONB payloads.
- Row-Level Security (RLS) policies configured on both tables using `app.current_tenant`.
- Applied successfully via `scripts/migrate-phase-c.cjs` bringing live database to 29 provisioned tables.

### 4. REST API Route Handlers
- `GET /api/v1/twin/attack-paths` & `POST /api/v1/twin/attack-paths`: Authenticated, tenant-scoped, RBAC-guarded (`incident.investigate`) endpoint for attack path evaluation.
- `GET /api/v1/twin/blast-radius` & `POST /api/v1/twin/blast-radius`: Authenticated, tenant-scoped, RBAC-guarded (`incident.investigate`) endpoint for blast radius simulations.

---

## What Is Still Not Production-Ready

1. **Max Path Depth Configuration:** Default graph search depth is capped at 6 hops (configurable up to 10 via query/body parameters). Enterprise configurations with deep VPC topologies may require adaptive depth tuning.
2. **Real-Time WebSocket Graph Streaming:** Current API returns synchronous JSON reports. Visual UI nodes/edges graph animation will benefit from streaming WebSocket subscriptions in later UI polish.
3. **Automated Choke-Point Policy Dispatch:** Choke-point isolation currently generates recommended remediation text; automated single-click execution of choke-point remediation will be wired into Phase D (Policy Engine) and Phase H (Execution Broker).
