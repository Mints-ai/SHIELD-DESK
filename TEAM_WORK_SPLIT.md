# ShieldDesk 9-Member Team Work Allocation & Execution Matrix

Based on the official **ShieldDesk Team Assignment Charter** and system architecture, the project responsibilities are distributed across all **9 team members**. Each role contains defined ownership, daily responsibilities, deliverables, and collaboration dependencies.

---

## 1. Team Org Structure & Squad Breakdown

```
                         ┌──────────────────────────────────────────────┐
                         │  Technical Director & System Architect      │
                         │             Anand Sudhi                      │
                         └──────────────────────┬───────────────────────┘
                                                │
         ┌──────────────────────────────────────┼──────────────────────────────────────┐
         │                                      │                                      │
┌────────┴─────────────┐              ┌─────────┴────────────┐               ┌─────────┴────────────┐
│ Squad 1: Backend &   │              │ Squad 2: Frontend &  │               │ Squad 3: AI & Threat │
│ Core Services        │              │ Trust UI             │               │ Intelligence         │
├──────────────────────┤              ├──────────────────────┤               ├──────────────────────┤
│ • Akshay (Lead)      │              │ • Abhinandanam       │               │ • Akhilesh (AI/ML)   │
│ • Sanal T (Database) │              │   (UI/UX Lead)       │               │ • Fayiz (Threat Eng) │
└──────────────────────┘              └──────────────────────┘               └──────────────────────┘
         │                                      │                                      │
         └──────────────────────────────────────┼──────────────────────────────────────┘
                                                │
                         ┌──────────────────────┴───────────────────────┐
                         │ Cross-Cutting Assurance & Governance         │
                         ├──────────────────────────────────────────────┤
                         │ • Athil Hisham (QA & Test Automation Lead)   │
                         │ • Adithyadev (Pentesting & Red Teaming)      │
                         │ • Noyal Savio (GRC, DevOps & CI/CD)          │
                         └──────────────────────────────────────────────┘
```

---

## 2. Individual Role Cards & Responsibilities

### 1. Akshay (Me) — Lead Backend & Tool Gateway Architect
- **Squad**: Backend & Core Services (Squad Lead)
- **Primary Ownership**:
  - Main API router (`src/app/api/chat/route.ts`) and Server-Sent Events (SSE) streaming engine.
  - Tool Gateway function (`runTool()`) orchestrating `getIncidents`, `investigateIncident`, `analyzeCve`, and `generateMitigationPlan`.
  - Intent classification logic (deterministic regex fast-path + Ollama function-calling fallback).
  - Integration between Frontend, PostgreSQL, and Python AI Service.
- **Key Deliverables**:
  - Robust `/api/chat` API endpoint with error boundaries and SSE streaming.
  - Deterministic router for incident codes (`INC-XXXX`) and CVEs (`CVE-XXXX-XXXX`).
  - End-to-end tool execution pipeline connecting all backend tools.
- **Works Closest With**: Abhinandanam (API contracts), Sanal T (Database queries), Akhilesh (Python AI engine).

---

### 2. Sanal T — Database & Data Infrastructure Engineer
- **Squad**: Backend & Core Services
- **Primary Ownership**:
  - PostgreSQL database schema (`db/schema.sql`) and data migrations.
  - Multi-tenant data isolation and RBAC policy enforcement at the SQL query layer.
  - Database connection pooling (`src/lib/db/index.ts`) using `pg.Pool`.
  - Development seed data (`db/seed.sql`) and Audit logging storage (`chat_audit_log` table).
- **Key Deliverables**:
  - Optimized database indexes for `incidents`, `incident_events`, `assets`, and `incident_cves`.
  - Strict tenant filtering (`tenant_id = $1`) to prevent data leakage across tenants.
  - Asynchronous audit log persistence for compliance tracking.
- **Works Closest With**: Akshay (DB query helpers), Noyal Savio (Database Dockerization).

---

### 3. Akhilesh — AI / ML & Vulnerability Intelligence Engineer
- **Squad**: AI & Threat Intelligence (Squad Lead)
- **Primary Ownership**:
  - Local Ollama LLM integration (`src/lib/ai/ollama.ts`) and model management (`qwen3:4b-instruct-2507-q4_K_M`).
  - Python AI Engine (`server.py` / `cve_ai_engine.py`) exposing `/api/lookup` and `/api/predict`.
  - RAG (Retrieval-Augmented Generation) pipeline indexing NVD CVEs, MITRE ATT&CK, and CISA KEV.
  - Model prompt engineering, hallucination suppression, and Model Confidence scoring.
- **Key Deliverables**:
  - Low-latency Python microservice serving 10,000+ CVE knowledge base queries on port 8000.
  - Optimized system prompts (`ROUTING_SYSTEM_PROMPT` and `FORMAT_SYSTEM_PROMPT`).
  - Confidence scoring calculation algorithm for mitigation recommendations.
- **Works Closest With**: Akshay (Tool API hooks), Fayiz (Threat intelligence validation).

---

### 4. Abhinandanam — UI / UX & Trust Interface Developer
- **Squad**: Frontend & Trust UI (Squad Lead)
- **Primary Ownership**:
  - ShieldDesk Chat Widget (`src/components/ai-chat/ChatWidget.tsx`).
  - Streaming token rendering with smooth auto-scroll and real-time response buffering.
  - Dark-room design system styling (Tailwind CSS, Framer Motion animations, Lucide icons).
  - Trust Interface components: Autonomy Tier badges, Model Confidence meters, and Action Approval modals.
- **Key Deliverables**:
  - Floating responsive AI chat interface with suggested quick-action prompts.
  - Structured visual cards for incidents, timelines, and mitigation steps.
  - User role switcher component for development/demonstration testing.
- **Works Closest With**: Akshay (SSE stream reader), Athil Hisham (UI test cases).

---

### 5. Athil Hisham — QA & Test Automation Lead
- **Squad**: Cross-Cutting Assurance
- **Primary Ownership**:
  - Comprehensive automated test suite for chat API, tools, and RBAC rules.
  - Regression testing across all development phases.
  - Pilot validation checklist: latency benchmarks, false-positive review, error handling.
  - KPI quality dashboard (uptime, response latency, tool invocation success rate).
- **Key Deliverables**:
  - Automated integration test suite (`evaluate_test_cases.py` / Jest / Playwright).
  - Validation tests proving separation-of-duties and tenant boundary enforcement.
  - Phase-gate evidence reports (no phase moves forward without QA sign-off).
- **Works Closest With**: Akshay (API regression testing), Adithyadev (Security edge cases).

---

### 6. Anand Sudhi — Technical Director & System Architect
- **Squad**: Project Leadership & Architecture
- **Primary Ownership**:
  - Overall ShieldDesk architectural blueprint and system design integrity.
  - Final authority on Phase-Gate approvals (Go / No-Go decisions).
  - Cross-squad dependency resolution, unblocking team members, and code review oversight.
  - Future Endpoint Agent architecture (Go/Rust agent core and mTLS communication).
- **Key Deliverables**:
  - Approved Architecture Design Document (ADD) and Phase Roadmap.
  - Formal sign-off on Phase Gate transitions.
  - Weekly cross-squad architecture review sessions.
- **Works Closest With**: All Squad Leads (Akshay, Abhinandanam, Akhilesh, Noyal).

---

### 7. Fayiz — Cybersecurity & Threat Policy Engineer
- **Squad**: AI & Threat Intelligence
- **Primary Ownership**:
  - Autonomy Tier definitions: establishing rules for Tier 1 (automatic), Tier 2 (analyst approved), and Tier 3 (break-glass SuperAdmin).
  - MITRE ATT&CK technique mapping for incident titles and lateral movement detections.
  - Mitigation plan templates: Immediate containment, short-term patching, and long-term hardening rules.
  - Verification of CISA Known Exploited Vulnerabilities (KEV) operational remediation tiers.
- **Key Deliverables**:
  - Written Autonomy Policy Document defining permissible autonomous actions.
  - Threat classification matrix for incident triage (`critical`, `high`, `medium`, `low`).
  - Rulebook for mitigation recommendations generated by the chatbot.
- **Works Closest With**: Akhilesh (CVE & RAG scoring), Adithyadev (Attack scenario modeling).

---

### 8. Adithyadev — Pentester & Adversarial Security Specialist
- **Squad**: Cross-Cutting Assurance
- **Primary Ownership**:
  - Adversarial security validation: Attempting to break the chatbot and underlying APIs.
  - Prompt injection, jailbreaking, and system prompt extraction resistance testing.
  - RBAC & tenant isolation penetration testing (verifying `globex-tenant` cannot view `acme-tenant` records).
  - Audit log tamper testing and control plane API vulnerability assessment.
- **Key Deliverables**:
  - Red-Team Assessment Report detailing injection test findings and mitigations.
  - Breach & Attack Simulation (BAS) test scripts for incident triggering.
  - Input validation fuzzing results for `/api/chat` payload.
- **Works Closest With**: Athil Hisham (Security test cases), Akshay (Input sanitization fixes).

---

### 9. Noyal Savio — GRC (Governance, Risk & Compliance) & DevOps Lead
- **Squad**: Cross-Cutting Assurance
- **Primary Ownership**:
  - Compliance mapping: Aligning mitigation horizons and audit logs with **ISO 27001 Annex A** and **SOC 2 Type II** controls.
  - Data privacy & residency verification (ensuring zero customer data crosses to external third-party LLMs).
  - CI/CD automation pipeline (GitHub Actions / GitLab CI) for linting, type-checking, and testing.
  - Containerization (Docker / Docker Compose) for PostgreSQL, Next.js, and Python AI service.
- **Key Deliverables**:
  - `docker-compose.yml` orchestrating PostgreSQL, Python AI engine, and Next.js web application.
  - ISO 27001 compliance matrix mapping actions to security controls.
  - Automated CI pipeline running `tsc --noEmit`, ESLint, and test suites on pull requests.
- **Works Closest With**: Sanal T (PostgreSQL containerization), Anand Sudhi (Phase-gate compliance).

---

## 3. Master Phase Assignment Table

| Phase & Feature | Primary Owner | Supporting Members | Exit Criteria & Artifact |
|---|---|---|---|
| **Phase 0: Architecture & Environment** | Anand Sudhi | Akshay, Noyal Savio | Running Next.js, Ollama, and Dockerized PostgreSQL. |
| **Phase 1: Chat Routing & Tool Gateway** | Akshay | Akhilesh, Sanal T | `/api/chat` routes to all 4 tools and streams SSE chunks. |
| **Phase 2: Database & Audit Logging** | Sanal T | Noyal Savio, Akshay | Real PostgreSQL tables active with automated audit writes. |
| **Phase 3: Python AI & CVE Intelligence** | Akhilesh | Fayiz, Akshay | `/api/lookup` returns CVE data, CVSS, and KEV status. |
| **Phase 4: Trust Interface & UI Widget** | Abhinandanam | Athil Hisham, Akshay | Responsive chat widget with confidence & tier badges. |
| **Phase 5: Security Policy & Tiers** | Fayiz | Adithyadev, Anand Sudhi | Autonomy tier rules defined and enforced in mitigation plans. |
| **Phase 6: Adversarial & Red-Team Testing** | Adithyadev | Akshay, Athil Hisham | Zero prompt injection bypasses; tenant isolation verified. |
| **Phase 7: QA Automation & Regression** | Athil Hisham | Anand Sudhi, Akshay | 100% automated test pass rate with coverage report. |
| **Phase 8: GRC, CI/CD & Final Delivery** | Noyal Savio | Anand Sudhi, Sanal T | ISO 27001 mapping completed, Docker Compose production ready. |

---

## 4. Weekly Rhythms & Collaboration Rules

1. **Standup Sync (2x / week - 15 mins)**:
   - Each squad shares: *What I finished*, *What I am doing next*, and *Any blocker*.
2. **Phase Gate Reviews**:
   - No feature moves to "Done" based on assumptions.
   - Requires: Code review (Akshay/Anand) + QA Evidence (Athil) + Security sign-off (Adithyadev) + Compliance sign-off (Noyal).
3. **Escalation Path**:
   - Technical Blocker $\rightarrow$ Akshay (Lead Backend) or Anand Sudhi (Technical Director).
   - Security/Privacy concern $\rightarrow$ Immediately raise to Adithyadev and Fayiz.
