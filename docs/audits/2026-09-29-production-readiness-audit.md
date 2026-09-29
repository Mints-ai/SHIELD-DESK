# ShieldDesk — Production Launch Readiness Audit

**Product:** ShieldDesk™ — Mints Global  
**Repository:** [https://github.com/Mints-ai/SHIELD-DESK](https://github.com/Mints-ai/SHIELD-DESK)  
**Audit Date:** 2026-09-29  
**Purpose:** Determine whether the current repository is a complete public production product, with special attention to everything outside the AI chat system.

---

## 1. Executive Verdict

**Short answer:**  
**No — ShieldDesk is not yet a complete production-ready public SOC product.**

The repository is substantially more than a chatbot. It contains a real Next.js control-plane/dashboard, PostgreSQL-backed tenant-aware data access, incident investigation, mitigation plans, approval governance, task-board UI, compliance reporting, risk scorecards, scanner integrations, threat-engine UI/API surfaces, endpoint-agent/fleet models, command governance, audit-chain logic, and AI/blast-radius functionality.

However, a significant portion of the non-chat functionality is currently demo/simulation/scaffolding rather than a production control loop:
- **The product UI and control-plane workflows exist, but the real-world security execution layer is not yet proven end-to-end.**
- The uploaded architecture documents define ShieldDesk as a four-layer system:
  1. AI orchestration
  2. Endpoint agent
  3. Telemetry lake
  4. Governance
- The beginner guide explicitly says that the endpoint agent is a separate, much larger undertaking and that the final "done" state requires an approved signed command to execute safely on a second machine.
- The build plan places the Universal Endpoint Agent in Phase 2, pilot validation in Phase 2b, Tier 1 containment in Phase 3, Tier 2 remediation/fleet rollout in Phase 4, and Tier 3 break-glass in Phase 5.
- Therefore, having the dashboard and chat working does not equal having the complete ShieldDesk product defined by the original architecture.

---

## 2. Current Repository Reality

The public repository currently contains:
- Next.js application & React/TypeScript frontend
- PostgreSQL data layer
- Python CVE/ML service & additional Go/Python services
- Endpoint-agent directory
- Infrastructure/Terraform/Helm material
- Gateway configuration & shared contracts
- Automated tests & Docker Compose
- Operational/build documentation

It currently has 56 commits with no public release tag yet.

---

## 3. High-Priority Launch Blockers & Action Plan

### P0 — Must Fix Before Any Real Customer Endpoint Is Connected
1. **Remove production mock-success fallbacks**: Eliminate silent `try real -> catch -> return simulated success` patterns.
2. **Explicit Environment Modes**: Implement strict `APP_ENV=production` vs `APP_ENV=development` and `DEMO_MODE=true|false`.
3. **Fail-Closed Execution**: If a dependency (scanner, agent, fleet broker) is offline in production, fail closed with explicit error codes.
4. **Disable Development Personas**: Hard-gate `DEV_USERS`, `dev-admin`, and frontend header spoofing (`X-ShieldDesk-User`) in production.
5. **Enforce Real Authentication**: Replace client-supplied identity headers with signed JWT/session resolution at middleware.
6. **Command Signing & Kill Switch**: Prove cryptographic signatures and fleet-wide kill switch enforcement on real daemon processes.

### P1 — Must Fix Before Public Production SaaS
1. **Universal Endpoint Agent**: Real Windows (ETW/WMI) and Linux (eBPF/auditd) enrollment, mTLS gRPC channel, heartbeat, and execution engine.
2. **Telemetry Lake**: Replace simulated stats with live ingestion pipeline (TimescaleDB / OpenSearch / S3 cold store).
3. **Live Scanner & Threat Engine**: Wire Trivy, Gitleaks, YARA, and Sigma to live background execution queues.
4. **Tenant Onboarding & Enterprise Auth**: Client organization creation, domain verification, SSO (SAML/OIDC), and SCIM.

### P2 — Commercial & Compliance Readiness
1. **Accurate UI Copy**: Replace "SOC 2 Type II" certified badge with "SOC 2 Readiness"; label benchmark/industry metrics vs measured telemetry.
2. **Billing & Usage Metering**: Subscription tiers, endpoint caps, and ingestion metering.
3. **Legal & Security Package**: DPA, Terms of Service, Subprocessor registry, and responsible disclosure policy.

---

## 4. Final Status Matrix Summary

| Component | Architecture & Control Plane | Execution Layer | Status |
| :--- | :--- | :--- | :--- |
| **SOC Chat & Copilot** | Deterministic intent routing, tool allowlist, RBAC | Local Ollama / tool executors | 🟢 Real |
| **Incident Queue & Investigation** | Tenant-scoped filters, timeline visualization | Telemetry ingestion needs production EDR/SIEM | 🟢/🟡 Control Plane Real |
| **Mitigation Plans** | 3-horizon planning, tier badges, confidence scores | Command dispatch to endpoints | 🟢/🟡 Control Plane Real |
| **Approval Governance** | Anti-replay, separation-of-duties, Tier 3 dual approval | Execution returns `simulated_containment_successful` | 🟢/🟡 Logic Real, Exec Simulated |
| **Endpoint Fleet Model** | Heartbeat, CPU/EPS models, command queue | Mock records, simulated host actions | 🟡 Scaffolding / Simulated |
| **Universal Endpoint Agent** | Go agent directory, architecture specs | mTLS, ETW/eBPF, signed execution | 🔴 Not Proven in Prod |
| **Security Scanner** | Trivy/Gitleaks UI & runbooks | Live scanner uses fallback demo fixtures | 🔴 Demo Fallbacks |
| **Threat Detection Engine** | YARA/Sigma UI, anomaly baseline cards | Live telemetry returns hardcoded values | 🔴 UI Simulation |
| **Compliance & Scorecards** | ISO 27001 mapping, risk dashboard | Industry benchmark estimates (not live cert) | 🟡 Needs Readiness Labeling |
| **Audit Log Ledger** | SHA-256 hash chaining, tenant association | WORM / immutable external store | 🟡 App Hash-Chain Real |

---

## 5. Recommended Immediate Sprints

### Sprint 1: Production Safety Boundary
- Introduce `DEMO_MODE` and `FAIL_CLOSED=true` configuration.
- Audit and eliminate simulated success returns in `/api/scans`, `/api/threats`, `/api/approvals`, and `/api/fleet`.
- Disable dev personas (`dev-admin`, `dev-analyst`) when `NODE_ENV === "production"`.
- Update compliance and scorecard copy: "SOC 2 Readiness", "Estimated Benchmark MTTD/MTTR".

### Sprint 2: Real Endpoint Loop
- Implement minimal real agent enrollment via mTLS on 1 Linux VM and 1 Windows VM.
- Verify heartbeat transmission, signed command verification, and real host execution (snapshot, isolate, restore).

### Sprint 3: Live Ingestion & Ingestion Hardening
- Wire live webhook HMAC validation for CrowdStrike / Defender / Wazuh alert ingestion.
