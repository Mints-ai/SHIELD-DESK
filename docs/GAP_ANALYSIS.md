# ShieldDesk — Gap Analysis & Production Add-On Audit

**Document Version:** 1.0.0  
**Target Repository:** [Mints-ai/SHIELD-DESK](https://github.com/Mints-ai/SHIELD-DESK)  
**Date:** 2026-09-30  
**Auditor:** Senior Staff Software Architect & DevSecOps Engineer  
**Reference Spec:** `docs/SHIELDDESK_MASTER_PRODUCT_AND_LAUNCH_SPEC.md`  
**Core Motto:** *PROVE BEFORE YOU ACT*  

---

## Executive Summary & Non-Breaking Impact Assessment

### Will implementing this negatively affect the current code?
**No. Implementing these phases will NOT negatively affect the current code**, provided we adhere strictly to the following architectural guardrails:
1. **Strictly Additive Changes:** No existing tables, columns, API routes, or exported helper signatures will be dropped or modified destructively.
2. **Backwards Compatibility Guarantee:** All existing 199 unit, integration, and security tests across 31 test suites must continue passing 100% green on every phase commit.
3. **Database Migration Safety:** All database migrations will use `IF NOT EXISTS`, non-destructive `ALTER TABLE` statements, and additive tables only.
4. **Isolated Service Layout:** New capabilities (such as the Universal Connector SDK, Postgres CTE Digital Twin, Decision Records, and Recheck Workers) will integrate seamlessly into the existing `services/` and `src/lib/` structure.
5. **No Regressions in Next.js 16 Edge Proxy:** Routing, tenant isolation, and security headers remain unified in `src/proxy.ts`.

---

## 1. Current Architecture, Stack & Baseline State

### Technology Stack
- **Web Console / App:** Next.js 16 (React 19 App Router), TypeScript 5.7, Tailwind CSS + Vanilla CSS tokens.
- **Edge Routing & Proxy:** `src/proxy.ts` handling subdomains (`api.`, `status.`, `trust.`, `portal.`), CSP headers, and CORS.
- **Data Persistence:** PostgreSQL (Supabase `dpuotfxyfqvwggewczhs`) via `pg` connection pool with Row-Level Security (RLS) policies and `pgcrypto`.
- **Endpoint Agent Fleet:** Go 1.23 cross-platform agent (`agent/`) supporting Windows (`netsh`) and Linux (`iptables`), mutual TLS (mTLS), and RSA-2048 canonical SHA-256 signature verification.
- **AI / Security Intelligence:** Python 3 FastAPI engines (`services/scan/`, `services/ai-advisor/`, `services/threat/`), local-first Ollama LLM Gateway (`src/lib/ai/ollama.ts`), and Gemini/OpenAI adapters.
- **Observability:** Prometheus metrics registry (`src/lib/observability/metrics.ts`), Sentry error tracking (`sentry.server.config.ts`), and tamper-evident SHA-256 Merkle audit chains.
- **Test Baseline:** 199 tests passing across 31 test suites (`npm test`).

### Current Database Schema (20 Tables)
1. `users` (with TOTP MFA columns, password hashes, and roles)
2. `incidents` (incident codes, severity, status)
3. `incident_events` (audit timeline of events per incident)
4. `assets` (hostnames, asset types, tenant binding)
5. `incident_assets` (join table)
6. `incident_cves` (linked CVE identifiers)
7. `chat_audit_log` (prompt & AI audit trail)
8. `mitigation_plans` (governed action plans with dual approval separation constraint)
9. `mitigation_tasks` (individual action tasks)
10. `approval_tokens` (cryptographic HMAC-SHA256 tokens with expiry and replay guards)
11. `approval_audit_log` (audit record of all tier 1-3 decisions)
12. `endpoint_agents` (enrolled host agents, OS, mTLS cert fingerprints)
13. `endpoint_certificates` (X.509 certificates with ASN.1 DER integer padding)
14. `endpoint_enrollment_tokens` (one-time enrollment secrets)
15. `agent_commands` (canonical signed commands queued for execution)
16. `agent_command_logs` (execution stdout/stderr logs)
17. `endpoint_telemetry` (host metrics, CPU, memory, active connections)
18. `endpoint_snapshots` (pre-execution state snapshots for automated rollback)
19. `endpoint_kill_switches` (emergency tenant/agent kill switches)
20. `hash_chain_audit` (SHA-256 Merkle-linked audit ledger)

---

## 2. Comprehensive Spec-to-Code Gap Matrix

| Spec Section / Phase | Status | Existing Implementation File Paths | Missing / Gaps to Implement |
| :--- | :---: | :--- | :--- |
| **Phase A: Security Data Layer** | **PARTIAL** | `src/lib/telemetry/normalizer.ts`<br>`src/lib/connectors/registry.ts`<br>`src/lib/connectors/normalizer.ts`<br>`services/scan/cve_scanner.py` | • Universal event schema across SIEM/EDR/scanners<br>• Asset criticality & business value weighting<br>• Dedicated Connector SDK (`authenticate`, `healthCheck`, `collect`, `normalize`, `validate`, `cursor`, `disconnect`)<br>• Trivy & OpenVAS connector implementations |
| **Phase B: Security Digital Twin** | **PARTIAL** | `src/lib/security-twin/digitalTwin.ts`<br>`src/lib/security-twin/types.ts`<br>`services/security-twin/index.ts` | • Currently in-memory graph only<br>• Missing Postgres graph tables (`twin_nodes`, `twin_edges`)<br>• Missing recursive CTE reachability & dependency queries<br>• Ingestion sync pipeline from Phase A data |
| **Phase C: Attack-Path & Blast-Radius** | **EXISTS** | `src/lib/attack-path/engine.ts`<br>`src/lib/blast-radius/engine.ts`<br>`services/attack-path/`<br>`services/blast-radius/` | • Choke-point discovery and kill chains exist<br>• Blast radius distinguishes `measured` vs `estimated`<br>• Need deeper bridge to persistent Postgres graph nodes |
| **Phase D: Risk & Decision Engine** | **PARTIAL** | `src/lib/decision-engine/engine.ts`<br>`src/lib/policy-engine/engine.ts`<br>`src/lib/governance/autonomyTier.ts` | • Autonomy policies (Observe, Assist, Autopilot) exist<br>• Need dedicated `decision_records` table per spec schema<br>• Explicit separation of Security Confidence vs AI Confidence |
| **Phase E: Remediation Simulator & Verification** | **PARTIAL** | `src/lib/verification-engine/engine.ts`<br>`src/lib/verification-engine/methods.ts`<br>`src/lib/rollback-engine/engine.ts`<br>`src/lib/orchestration/closedLoopPipeline.ts` | • Pre-flight snapshots, state verification, and auto-rollback exist<br>• Need root-cause grouping across bulk findings<br>• Need background recheck worker for closed findings |
| **Phase F: Evidence Vault** | **PARTIAL** | `src/lib/compliance/evidenceVault.ts`<br>`src/lib/compliance/merkle.ts`<br>`src/app/api/compliance/route.ts` | • SHA-256 Merkle chain and hash verification exist<br>• Need automated PDF & CSV export generators with signed integrity headers |
| **Phase G: AI Layer & Governance** | **PARTIAL** | `src/lib/ai/ollama.ts`<br>`services/llm-gateway/`<br>`src/lib/tools/shieldDeskChatTools.ts`<br>`src/lib/security/redactor.ts` | • Local-first Ollama + Gemini/OpenAI pluggable gateway exists<br>• Anti-prompt injection filters exist<br>• Need persistent AI Evaluation Lab dataset tables and automated hallucination/tool error tracking |
| **Phase H: Execution Broker & Agent Hardening** | **PARTIAL** | `src/app/api/agent/commands/route.ts`<br>`src/lib/fleet/commandSigning.ts`<br>`src/lib/fleet/certificates.ts`<br>`agent/` (Go 1.23 Universal Agent) | • Single broker dispatch with RSA-2048 signing exists<br>• mTLS device certificates exist<br>• Need signed agent self-update with rollback on boot failure |
| **Phase I: Licensing, Entitlements & Stripe** | **PARTIAL** | `src/app/api/webhooks/stripe/route.ts`<br>`src/lib/billing/plans.ts`<br>`src/lib/billing/licenses.ts` | • Stripe webhook handler and tiered plans exist<br>• Need server-side `entitlementService.require(...)` guard middleware<br>• Need Postgres idempotency table for `stripe_event_id` deduplication |

---

## 3. Places Using Demo, Fallback, or Estimated Metrics

1. **Dev User Personas (`src/lib/constants/devUsers.ts`):**
   - Contains seed logins (`analyst@acme.test`, `admin@shielddesk.internal`).
   - *Safety Status:* Protected by `ProductionSafetyGuard` (`src/config/index.ts`). In production mode (`APP_ENV === "production"`), mock personas are completely blocked from authenticating.
2. **Blast Radius Calculation (`src/lib/blast-radius/engine.ts`):**
   - When asset dependency data is incomplete, engine sets `calculationMode = "estimated"` and adds explicit caveats to the risk payload.
   - In production paths, estimated calculations trigger Tier 3 dual-approval escalation.
3. **AI Gateway Fallback (`src/lib/ai/ollama.ts`):**
   - If Ollama is unreachable in development, a deterministic fallback proposal is returned with an explicit `dev_fallback: true` flag. In production, this fails closed with an error.

---

## 4. Proposed Folder Placement Matching CURRENT Layout

To avoid architectural conflicts or breaking existing imports:

```text
SHIELD-DESK/
├── db/
│   ├── migrations/
│   │   ├── launch_readiness_001.sql        (Existing)
│   │   ├── phase_a_security_events.sql     (New: Universal security events & connector cursors)
│   │   ├── phase_b_digital_twin_graph.sql  (New: twin_nodes, twin_edges tables & CTE indexes)
│   │   ├── phase_d_decision_records.sql    (New: decision_records audit table)
│   │   └── phase_i_entitlements_stripe.sql (New: stripe deduplication & signed offline cache)
├── services/
│   ├── connectors/                         (Connector SDK & worker daemons)
│   │   ├── sdk/
│   │   ├── wazuh/
│   │   ├── trivy/
│   │   └── openvas/
│   ├── security-twin/                      (Postgres CTE query builder & benchmark harness)
│   ├── decision-engine/                    (Extended evidence scoring & decision records)
│   ├── verification-engine/                (Continuous recheck scheduler)
│   └── llm-gateway/                        (AI eval harness & prompt versioning)
├── src/
│   ├── app/api/
│   │   ├── v1/events/                      (Universal event ingestion)
│   │   ├── v1/twin/                        (Digital twin graph queries)
│   │   └── v1/connectors/                  (Connector management endpoints)
│   └── lib/
│       ├── connectors/                     (SDK interfaces & adapters)
│       ├── security-twin/                  (Postgres CTE Graph engine wrapping memory cache)
│       ├── decision-engine/                (Decision record persistence)
│       ├── verification-engine/            (Recheck engine)
│       └── billing/                        (Server-side entitlementService.require guard)
```

---

## 5. Risks and Spec Conflicts with Existing Code

| Identified Risk | Conflict Analysis | Proposed Safe Resolution |
| :--- | :--- | :--- |
| **Graph DB vs Postgres CTE** | Spec mentions Neo4j or Apache AGE, but Rule 6 emphasizes local-first and minimal footprint. | Benchmark Postgres recursive CTEs first on `twin_nodes`/`twin_edges`. Only propose external graph engines if CTE traversal exceeds 50ms at scale. |
| **Next.js 16 Proxy Limitation** | Next.js 16 forbids having both `middleware.ts` and `proxy.ts`. | Keep all edge guards inside `src/proxy.ts` and server components. Never create a separate `middleware.ts`. |
| **In-Memory Digital Twin Tests** | Existing 199 tests rely on `src/lib/security-twin/digitalTwin.ts` in-memory graph methods. | Design the new DB-backed digital twin as an additive wrapper/adapter that implements the same interface, so unit tests run seamlessly in-memory while production uses Postgres CTEs. |
| **Stripe Event Idempotency** | Webhooks could trigger duplicate plan upgrades or provisioning. | Introduce `stripe_events_processed` table with unique constraint on `stripe_event_id` and transactional locking. |

---

## 6. Audit Conclusion & Next Action

The repository is in an **exceptionally healthy baseline state**:
- 199/199 passing tests
- 0 TypeScript errors
- Clean live Supabase database with all 20 tables provisioned
- Complete separation of AI proposals from deterministic execution

**We are ready to begin Phase A (Security Data Layer) upon your explicit approval.**
