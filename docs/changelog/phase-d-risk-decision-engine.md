# Phase D: Risk and Decision Engine

**Branch:** `feature/phase-d-risk-decision-engine`  
**Date:** 2026-09-30  
**Tests:** 259/259 passing (7 new Phase D tests added, 252 from prior phases preserved)  
**TypeScript:** 0 errors  
**DB Migration:** `db/migrations/phase_d_decision_records.sql` applied — 30 total tables in Supabase PostgreSQL  

---

## What Was Built

### 1. Evidence Engine (`src/lib/decision-engine/evidenceEngine.ts`)
- **Canonical Evidence Hashing:** Constructs `DecisionEvidenceItem` with deterministic SHA-256 signatures (`evi-<hash[:16]>`) preventing telemetry tampering or spoofing.
- **Cryptographic Integrity Verification:** `verifyEvidenceIntegrity(item)` verifies data authenticity prior to evaluating high-impact actions.
- **Explainable Risk Formulation (Rule 7 Compliance):** Every risk factor carries an explicit, verifiable `evidenceId`:
  - CVSS Base Severity (points to CVE intelligence evidence)
  - CISA KEV In-the-Wild Exploitation (points to KEV catalog evidence)
  - EPSS High Exploit Probability (points to predictive EPSS telemetry)
  - Asset Criticality Weighting (points to asset inventory records)
  - Perimeter Exposure (points to network topology graph nodes)
  - Critical Kill-Chain Choke Points (points to attack-path analysis)
  - Regulated Sensitive Data Scope (points to compliance vault metadata)

### 2. Policy Engine & Asset-Level Autonomy (`src/lib/policy-engine/`)
- **Asset-Level Autonomy Resolution:**
  - Asset autonomy mode (`observe` | `assist` | `autopilot`) overrides the tenant default.
  - **Crown Jewel Safety Protection:** Critical infrastructure cannot run in unattended `autopilot` mode — clamped strictly to `assist` requiring human approval.
- **Mapping to Autonomy Tiers (0-3):**
  - **Tier 0:** Telemetry collection, read operations (0 approvals).
  - **Tier 1:** Low-risk, fully reversible immediate containment (0 approvals once enabled).
  - **Tier 2:** Medium-risk / host isolation / patch remediation (1 human approval).
  - **Tier 3:** High-risk / break-glass / database reboot (dual human approval).

### 3. Decision Engine & Confidence Separation (`src/lib/decision-engine/`)
- **Separation of Security Confidence from AI Confidence (Rules 1 & 2):**
  - `securityConfidence` (0.0 - 1.0) is calculated deterministically from evidence completeness, graph topology verification, and telemetry recency.
  - `aiConfidence` (0.0 - 1.0) captures LLM self-assessed probability.
  - **Invariant:** Even if `aiConfidence` is 0.99, if `securityConfidence < 0.65`, unattended execution is blocked, escalating to human review (`REQUIRE_APPROVAL`). If `securityConfidence < 0.40` on critical scopes, it escalates to `REQUIRE_DUAL_APPROVAL`.
- **Decision Records & Tamper-Evident Ledger:**
  - Emits immutable `DecisionOutput` records with `decisionHash` computed over tenant, action, actor, timestamp, and confidence metrics.
  - `persistDecisionRecord`: Asynchronously stores decisions in PostgreSQL `decision_records` table.
  - `getDecisionRecord` & `listDecisionRecords`: Queryable by tenant with asset and decision filters.

### 4. Database Schema & REST Endpoints
- **Migration:** `db/migrations/phase_d_decision_records.sql` provisions `decision_records` table with RLS tenant isolation.
- **REST Route:** `GET /api/v1/decisions` (listing / record fetch) and `POST /api/v1/decisions/evaluate` (evaluation with automatic persistence).

---

## What Is Still Not Production-Ready

1. **Custom Risk Weight Profiles:** Risk factor weights (CVSS 0.4, KEV 0.2, etc.) are currently defined by the default security baseline. Custom tenant risk weighting profiles will be introduced in the enterprise administration suite.
2. **Offline Local Decision Cache:** Decision records persist to PostgreSQL; offline signed caching for edge nodes disconnected from the cloud database will be finalized in Phase I.
3. **Approval Escalation Webhooks:** Decisions resulting in `REQUIRE_APPROVAL` or `REQUIRE_DUAL_APPROVAL` return tokens; automatic push notifications via Slack/Teams/PagerDuty are wired into notification channels in Phase E.
