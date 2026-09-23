# ShieldDesk — Autonomous SOC Operations Platform

> **An enterprise-grade Autonomous Security Operations Center (SOC) platform with multi-tenant isolation, human-in-the-loop governance (Tiers 0–3), a retrained Vulnerability Intelligence ML Engine, universal endpoint fleet management, live SIEM/EDR webhook ingestion, and an on-premises AI Co-Pilot.**

Designed with an architectural, editorial **Beige & Deep Forest Spruce** aesthetic (`#f7f4ed` canvas, `#123826` brand) adhering to strict UI/UX Pro Max guidelines. **No customer, incident, or endpoint telemetry data ever leaves your own infrastructure.**

---

## Architecture Overview

```
                      +-------------------------------------------------------------+
                      |                      USER BROWSER / UI                      |
                      |            http://localhost:3000 (Next.js 15 / React 19)    |
                      |  • Minimal Beige & Deep Forest Spruce Theme                 |
                      |  • Incident Queue & Timeline   • Endpoint Fleet & Kill Switch|
                      |  • 3-Horizon Mitigation Plans  • ISO 27001 Compliance Desk  |
                      |  • Kanban Task Governance Board • Executive Risk Scorecard   |
                      +------------------------------+------------------------------+
                                                     |
                                           POST /api/chat (SSE Stream)
                                           REST APIs (/api/fleet, /api/ingest, etc.)
                                                     |
                                                     v
                      +-------------------------------------------------------------+
                      |                 SHIELDDESK SECURITY GATEWAY                 |
                      |  1. Session Authentication & Multi-Tenant Scoping (Tenant ID)|
                      |  2. RBAC Policy Check & Anti-Enumeration 404 Engine         |
                      |  3. Pre-LLM Regex Classifier & Adversarial Prompt Sanitizer |
                      |  4. Layer 4 Governance: Autonomy Tiers 0-3 & Dual Sign-Off  |
                      |  5. SIEM Normalizer: CrowdStrike, Defender, Wazuh, OCSF     |
                      +-------+----------------------+--------------------+---------+
                              |                      |                    |
            Database Tools    |        Threat ML API |                    | Fallback or
            (Tenant-Scoped)   |        (Port: 8000)  |                    | SSE Streaming
                              v                      v                    v
      +-------------------------+    +-----------------------+    +----------------------+
      |   POSTGRESQL DATABASE   |    | PYTHON ML ENGINE      |    |   LOCAL OLLAMA LLM   |
      |       Port: 5432        |    |      Port: 8000       |    |     Port: 11434      |
      +-------------------------+    +-----------------------+    +----------------------+
      | • Multi-Tenant Schema   |    | • 12,968 CVE KB       |    | • qwen3:4b (Local)   |
      | • Incidents, Assets     |    | • Hybrid Word/Char    |    | • Few-Shot Intent    |
      | • Mitigation Plans      |    |   N-Grams + Threat RGX|    |   Routing & Notes    |
      | • 24h Approval Tokens   |    | • 160-Tree Ensemble   |    | • Zero-Downtime      |
      | • Chained Audit Ledger  |    | • KEV ROC-AUC: 0.9801 |    |   Deterministic      |
      |                         |    | • Tier Acc: 90.79%    |    |   Offline Fallback   |
      +-------------------------+    +-----------------------+    +----------------------+
                   ^
                   | Endpoint Telemetry & Action Execution
                   |
      +------------+-----------------------------------------+
      |       UNIVERSAL ENDPOINT AGENT FLEET (Layer 2)       |
      | • Go Agent: Telemetry buffer, Tier 1/2 auto-actions  |
      | • Rust Daemon: Tier 3 break-glass & two-person rule  |
      | • Safety Snapshots: Pre-flight rollback captures     |
      | • Emergency Kill Switch: Instant fleet-wide severing |
      +------------------------------------------------------+
```

---

## Key Platform Capabilities

### 1. Interactive SOC Operations Dashboards
- **Incident Queue & Triage Console (`/`)**: Real-time tenant-scoped incident list, chronological telemetry attack timelines, affected workstation/server inventories, linked CVE threat intelligence, and one-click mitigation triggers.
- **3-Horizon Mitigation Planner (`/dashboard/plans/[id]`)**: Actionable containment workflows grouped by horizon:
  - **Horizon 1**: Immediate Containment & Host Isolation (< 1 hour)
  - **Horizon 2**: Short-Term Patching & Credential Revocation (< 24–48 hours)
  - **Horizon 3**: Long-Term Architectural Hardening & Policy Updates (< 7–30 days)
- **SOC Kanban Task Board (`/dashboard/tasks`)**: 4-column operational board (*Pending Authorization*, *Authorized & Queued*, *In Progress*, *Completed & Audited*) with Tier 1–3 human authorization sign-off workflows.
- **Universal Endpoint Fleet & Live Command (`/dashboard/fleet`)**: Host enrollment telemetry, CPU/Memory telemetry meters, live command dispatcher with pre-flight safety snapshots, SHA-256 chained audit verification, and emergency admin kill switch.
- **ISO 27001 Compliance & Evidence Attestation (`/dashboard/compliance`)**: Audit readiness index (96%), automated vs. policy-governed control mapping (A.5.24–A.8.28), and verifiable cryptographic evidence package export.
- **Executive Risk Scorecard (`/dashboard/risk-scorecard`)**: Posture Grade A, Estimated Loss Avoided ($1.45M), 16 contained threats, 96%+ MTTD/MTTR reduction metrics, and threat vector distribution analytics.
- **Autonomous AI Chat Drawer (`ChatWidget`)**: Floating drawer with tenant persona switcher (`dev-analyst`, `dev-admin`, `dev-other`), quick prompts, and real-time streaming intelligence.

### 2. High-Accuracy Vulnerability Intelligence (Port 8000)
- Powered by a retrained **Unified Random Forest Model** over 12,968 historical records:
  - **Hybrid Feature Extractor**: 12,000 sublinear word n-grams + 8,000 character n-grams + 10 deterministic cybersecurity threat regex patterns (RCE, PrivEsc, AuthBypass, Memory Corruption, DoS, SQLi, XSS, SSRF, Zero-Day in the wild, Network attack vectors).
  - **CISA KEV Exploit Discrimination**: **`0.9801 ROC-AUC`** (98% exploit discrimination).
  - **Remediation Tier Accuracy**: **`90.79%`** (Weighted F1: `0.8957`).
  - **CVSS Score Regressor**: Continuous numerical prediction with Mean Absolute Error of **`0.606`** points on a 0–10 scale.
  - **Semantic Playbook Retrieval**: K-Nearest Neighbors mitigation retrieval mapping newly observed threat descriptions to verified historical vendor remediation steps.

### 3. Live SIEM / EDR Webhook Ingestion Engine (`/api/ingest/webhooks`)
- High-throughput ingestion listener protected by `X-ShieldDesk-API-Key`.
- Pre-built alert parsers for **CrowdStrike Falcon**, **Microsoft Defender for Endpoint**, **Wazuh HIDS**, and **OCSF JSON**.
- Normalizes threat telemetry, extracts linked CVEs, and dynamically creates incident timelines.

### 4. Real-Time Alert Dispatcher & Human-in-the-Loop Governance
- Dispatches formatted, actionable cards to **Slack Incoming Webhooks**, **Microsoft Teams**, and **SIEM webhooks**.
- Alerts analysts immediately when Tier 2/3 action approval tokens require separation-of-duties sign-off.
- **Autonomy Tiers**:
  - **Tier 0**: Passive monitoring & telemetry ingestion (Autonomous).
  - **Tier 1**: Low-risk automated actions (Autonomous with safety snapshot, e.g. session revocation).
  - **Tier 2**: Medium-risk actions requiring explicit Human-in-the-Loop authorization (e.g. host isolation).
  - **Tier 3**: High-risk destructive actions requiring Dual Named SuperAdmin Sign-Off (e.g. core firewall flush).

---

## Quick Start Guide

### Option A: 1-Command Docker Deployment (Recommended for Production)
```bash
docker compose up -d
```
*Boots the Next.js web application (`:3000`), Python CVE ML Engine (`:8000`), PostgreSQL (`:5432`), and Redis (`:6379`) with auto-mounted database schemas and persistent volumes.*

---

### Option B: Local Development Startup

#### 1. Start the Next.js Frontend & API Gateway
```powershell
npm install
npm run dev
```
*Frontend runs at: `http://localhost:3000`*

#### 2. Start the Python Vulnerability Intelligence Service
```powershell
cd ai-chat-desk
pip install -r requirements.txt
python server.py
```
*Vulnerability Engine runs at: `http://localhost:8000`*

#### 3. (Optional) Start the Local Ollama Assistant
```powershell
ollama run qwen3:4b
```
*If Ollama is offline, ShieldDesk automatically activates the built-in deterministic telemetry synthesis fallback without failing or interrupting operations.*

---

## Automated Test Suite

Run the full automated test suite (**39 passing tests** across 6 suites):

```powershell
npm test
```

### Verified Test Suites:
- **ShieldDesk Multi-Tenant RBAC & Isolation Suite** (8/8 PASS)
- **ShieldDesk Approval Tokens & Layer 4 Governance Suite** (7/7 PASS)
- **ShieldDesk Endpoint Agent Fleet & Live Command Suite** (8/8 PASS)
- **ShieldDesk Public Ingestion & Webhook Normalizer Suite** (4/4 PASS)
- **ShieldDesk ISO 27001 Compliance & Executive Scorecard Suite** (4/4 PASS)
- **ShieldDesk Adversarial Security & Injection Defense Suite** (5/5 PASS)

---

## Repository Structure

```
├── src/
│   ├── app/
│   │   ├── login/                    # Multi-tenant login, registration & persona switcher
│   │   ├── dashboard/
│   │   │   ├── compliance/page.tsx   # ISO 27001 compliance & evidence export
│   │   │   ├── fleet/page.tsx        # Endpoint fleet management & live command
│   │   │   ├── plans/[id]/page.tsx   # 3-horizon interactive mitigation plan
│   │   │   ├── risk-scorecard/page.tsx # Executive posture & MTTD/MTTR scorecard
│   │   │   └── tasks/page.tsx        # SOC Kanban governance task board
│   │   ├── api/
│   │   │   ├── auth/                 # Sign in & self-service tenant registration
│   │   │   ├── chat/route.ts         # Intent router, tool gateway, SSE streaming & fallback
│   │   │   ├── fleet/                # Endpoint fleet heartbeat & command execution
│   │   │   ├── governance/           # Approval tokens & separation of duties
│   │   │   ├── ingest/webhooks/      # Live SIEM / EDR alert ingestion endpoint
│   │   │   └── compliance/           # ISO 27001 control mapping & evidence package
│   │   ├── layout.tsx                # Root layout mounting global ChatWidget
│   │   ├── page.tsx                  # Incident queue & active triage console
│   │   └── globals.css               # Beige + Deep Forest Spruce design tokens
│   ├── components/
│   │   ├── ai-chat/ChatWidget.tsx    # Slide-out AI chat drawer
│   │   └── Navigation.tsx            # Global SOC navigation bar
│   └── lib/
│       ├── ai/ollama.ts              # Local Ollama client configuration
│       ├── auth/session.ts           # Multi-tenant session resolver
│       ├── governance/               # Approval tokens, autonomy tiers & kill switch
│       ├── notifications/dispatcher.ts # Slack & Teams real-time alerting
│       ├── supabase/                 # Supabase client & server auth utilities
│       └── tools/shieldDeskChatTools.ts # The 4 constrained SOC tools
├── agent/
│   ├── cmd/main.go                   # Go endpoint agent daemon
│   ├── pkg/                          # Telemetry ring buffer, hash chaining, handlers
│   ├── rust_daemon/                  # Rust Tier 3 emergency break-glass sentinel
│   ├── deploy-agent.ps1              # Windows endpoint enrollment script
│   └── deploy-agent.sh               # Linux systemd endpoint enrollment script
├── ai-chat-desk/
│   ├── Dockerfile                    # Container definition for Python ML service
│   ├── feature_extractor.py          # Hybrid n-gram & threat regex extractor
│   ├── cve_random_forest.py          # Unified Multi-Target Random Forest architecture
│   ├── train_rf_model.py             # Model training & validation script
│   ├── server.py                     # Vulnerability REST API (port 8000)
│   └── models/                       # Persisted .joblib model bundle & metrics
├── Dockerfile                        # Next.js 15 standalone production container
├── docker-compose.yml                # 1-command multi-service orchestration
├── .env.example                      # Production environment template
├── db/
│   ├── schema.sql                    # Multi-tenant PostgreSQL schema
│   └── seed.sql                      # Idempotent baseline seed data
└── tests/                            # 39 automated unit, security, and governance tests
```

---

## License & Security Mandate
ShieldDesk is built strictly for isolated, privacy-first security operations. All sensitive operations enforce Human-in-the-Loop governance, cryptographic auditability, and zero cross-tenant enumeration.
