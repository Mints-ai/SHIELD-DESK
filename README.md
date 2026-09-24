<p align="center">
  <img src="public/logo.png" alt="ShieldDesk Logo" width="220" />
</p>

<h1 align="center">ShieldDesk™ — AI-Powered Security Operations</h1>

<p align="center">
  <strong>DETECT &middot; INVESTIGATE &middot; RESPOND &middot; SAFER TOGETHER</strong><br/>
  <em>A Product by Mints Global</em>
</p>

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

## Team Onboarding & Working Guide

Welcome to the ShieldDesk engineering team! Follow this guide to set up your local development environment, run the services, execute automated tests, and adhere to our team quality standards.

> [!IMPORTANT]
> **Mandatory Team Checklists**: Before submitting a PR or issuing a release, review and complete the role-specific items in [CHECKLIST.md](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/CHECKLIST.md) (tailored for **Security Engineers**, **Software Developers**, and **Software Testers**).

---

### 1. Prerequisites
Ensure you have the following installed on your machine:
- **Node.js**: v18.18+ or v20+ (`node -v`)
- **npm**: v9+ or v10+ (`npm -v`)
- **Python**: v3.10+ or v3.12 (`python --version`)
- **Go** *(Optional, for microservices)*: v1.21+ (`go version`)
- **Docker Desktop** *(Optional, for containerized run)*: v24+

---

### 2. Quick Setup in 3 Steps

#### Step 1: Clone & Configure Environment Variables
```bash
git clone https://github.com/Mints-ai/SHIELD-DESK.git
cd shielddesk

# Create local environment config from example
cp .env.example .env.local
```
Review `.env.local` and ensure your Supabase keys, API gateway keys, and service URLs are configured.

#### Step 2: Install Dependencies
```bash
# Install frontend & API gateway dependencies
npm install

# (Optional) Install Python ML & scan service dependencies
pip install -r services/scan/requirements.txt
```

#### Step 3: Launch Local Dev Servers

**Terminal 1 — Next.js Application & API Gateway (Port 3000):**
```bash
npm run dev
```
Open **`http://localhost:3000`** in your browser.

**Terminal 2 — Python CVE & ML Vulnerability Server (Port 8000 / 8001):**
```bash
cd ai-chat-desk
python server.py
```

**Terminal 3 (Optional) — Local Ollama AI Assistant (Port 11434):**
```bash
ollama run qwen3:4b
```
*(If Ollama is not installed or offline, ShieldDesk automatically engages its built-in deterministic offline fallback engine with zero downtime.)*

---

### 3. How to Authenticate & Test Personas Locally

ShieldDesk features multi-tenant isolation. To test across tenants without creating external accounts:
1. Navigate to **`http://localhost:3000/login`**.
2. **Option A (Quick Persona Switcher):**
   - Click **"Quick Persona"** tab.
   - Choose **Alex Rivera (Acme SOC Analyst)**, **Sarah Chen (Platform Admin)**, or **Marcus Vance (Globex Corp)**.
   - Click **"Enter SOC Console"** for instant 1-click access.
3. **Option B (Supabase Cloud Auth):**
   - Click the **"Supabase"** tab.
   - Log in using your registered Supabase credentials against the live project (`dpuotfxyfqvwggewczhs.supabase.co`).
4. **Switching Personas On-the-Fly:**
   - Open the floating **AI Co-Pilot Drawer** in the bottom-right corner.
   - Click the persona badge in the header to switch roles instantly and test cross-tenant boundaries.

---

### 4. Running the Automated Test Suite

Every commit must pass all automated test suites:

```bash
# Run Next.js, RBAC, Governance, Fleet, Ingest & Security tests (39 tests)
npm test
```

#### What `npm test` Validates:
1. **Multi-Tenant RBAC & Isolation Suite** (8 tests) — Ensures no tenant can see or enumerate another tenant's incidents or plans.
2. **Approval Tokens & Layer 4 Governance Suite** (7 tests) — Tests 24h expiration, anti-replay, and separation of duties.
3. **Endpoint Agent Fleet & Live Command Suite** (8 tests) — Validates agent isolation, safety snapshots, and emergency kill switch.
4. **Public Ingestion & Webhook Normalizer Suite** (4 tests) — Tests CrowdStrike, Defender, and Wazuh SIEM payload parsing.
5. **ISO 27001 Compliance & Executive Scorecard Suite** (4 tests) — Verifies control mapping and evidence hash chains.
6. **Adversarial Security & Injection Defense Suite** (5 tests) — Confirms prompt injection, SQLi, and secret redaction filters.

#### Testing Python & Go Microservices (Optional):
```bash
# Python Scan & AI Advisor tests
pytest services/scan/test_scan.py
pytest services/ai-advisor/test_advisor.py

# Go Threat Detection & Webhooks tests
go test ./services/threat/...
go test ./services/webhooks/...
```

---

### 5. Team Git & Contribution Workflow

1. **Branching Strategy**:
   - `main`: Production-ready branch. Direct pushes must have passing tests.
   - Feature branches: `feat/<feature-name>`, `fix/<bug-name>`, `sec/<security-patch>`.
2. **Commit Message Format**:
   Follow conventional commits:
   - `feat(scope): add new feature`
   - `fix(scope): resolve bug or regression`
   - `sec(scope): security hardening or isolation fix`
   - `test(scope): add or update test suites`
3. **Pre-PR Checklist**:
   - [x] Run `npm test` (all 39 tests passing).
   - [x] Run `npx tsc --noEmit` (no TypeScript errors).
   - [x] Verify no hardcoded secrets or API tokens in new files.
   - [x] Review [CHECKLIST.md](file:///d:/Ddeveloped_things/shield_deskmain/shielddesk/CHECKLIST.md) for your role.

---

### 6. 1-Command Docker Deployment (Production)

To boot the full stack in Docker containers:
```bash
docker compose up -d
```
*Launches Next.js (`:3000`), Python CVE Engine (`:8000`), PostgreSQL (`:5432`), and Redis (`:6379`) with auto-mounted schemas.*

---

## Repository Structure

```
├── src/
│   ├── app/
│   │   ├── login/                        # Multi-tenant login, registration & persona switcher
│   │   ├── dashboard/
│   │   │   ├── compliance/page.tsx       # ISO 27001 compliance & evidence export
│   │   │   ├── fleet/page.tsx            # Endpoint fleet management & live command
│   │   │   ├── plans/[id]/page.tsx       # 3-horizon interactive mitigation plan
│   │   │   ├── risk-scorecard/page.tsx   # Executive posture & MTTD/MTTR scorecard
│   │   │   ├── scanner/page.tsx          # Security Scanner & Remediation Center
│   │   │   ├── tasks/page.tsx            # SOC Kanban governance task board
│   │   │   └── threats/page.tsx          # Threat Detection & Ingestion Engine console
│   │   ├── api/
│   │   │   ├── ai/advisor/               # Blast radius simulation & AI runbook synthesis
│   │   │   ├── approvals/                # Tier 2/3 approval token creation & sign-off
│   │   │   ├── auth/                     # Sign in & self-service tenant registration
│   │   │   ├── chat/route.ts             # Intent router, tool gateway, SSE streaming & fallback
│   │   │   ├── compliance/               # ISO 27001 control mapping & evidence package
│   │   │   ├── fleet/                    # Endpoint fleet heartbeat & command execution
│   │   │   ├── health/route.ts           # Platform health & dependency status endpoint
│   │   │   ├── incidents/route.ts        # Tenant-scoped incident CRUD
│   │   │   ├── ingest/webhooks/          # Live SIEM / EDR alert ingestion endpoint
│   │   │   ├── plans/                    # Mitigation plan generation & persistence
│   │   │   ├── reports/scorecard/        # Executive risk scorecard data endpoint
│   │   │   ├── scans/                    # Trivy CVE, Gitleaks secrets & SSH patching
│   │   │   ├── threats/                  # YARA/Sigma rules & 3-sigma anomaly baselines
│   │   │   └── webhooks/                 # HMAC-SHA256 test dispatcher
│   │   ├── error.tsx                     # App Router Error Boundary
│   │   ├── global-error.tsx              # Root Layout Error Boundary
│   │   ├── layout.tsx                    # Root layout mounting TopNavBar & ChatWidget
│   │   ├── page.tsx                      # Incident queue & active triage console
│   │   └── globals.css                   # Beige + Deep Forest Spruce design tokens
│   ├── components/
│   │   ├── ai-chat/ChatWidget.tsx        # Slide-out AI chat drawer
│   │   ├── governance/
│   │   │   ├── ApprovalModal.tsx         # Tier 2/3 human-in-the-loop approval dialog
│   │   │   ├── AutonomyTierBadge.tsx     # Visual badge for Tier 0–3 autonomy level
│   │   │   └── ModelConfidenceMeter.tsx  # ML model confidence display meter
│   │   ├── navigation/TopNavBar.tsx      # Global SOC navigation bar with Supabase health
│   │   └── ui/avatar.tsx                 # Reusable avatar component
│   ├── lib/
│   │   ├── ai/ollama.ts                  # Ollama LLM client wrapper & offline fallback
│   │   ├── auth/session.ts               # Multi-tenant session resolver (production-gated)
│   │   ├── compliance/                   # ISO 27001 control mappings & evidence utilities
│   │   ├── constants/devUsers.ts         # Centralized dev user metadata
│   │   ├── context/                      # React context providers (e.g. tenant, session)
│   │   ├── db/                           # PostgreSQL client & query helpers
│   │   ├── fleet/                        # Endpoint fleet telemetry & command utilities
│   │   ├── governance/
│   │   │   ├── approvalTokens.ts         # 24h token lifecycle, anti-replay & dual sign-off
│   │   │   └── autonomyTier.ts           # Tier 0–3 classification & enforcement logic
│   │   ├── notifications/dispatcher.ts   # Slack / Teams / SIEM real-time alert dispatcher
│   │   ├── observability/errorTracker.ts # Unified error tracking & telemetry
│   │   ├── permissions.ts                # RBAC permission matrix & canExecuteTool()
│   │   ├── reporting/scorecard.ts        # Executive scorecard metric aggregation
│   │   ├── security/redactor.ts          # PII & secret redactor utility
│   │   ├── supabase/                     # Supabase client & server auth utilities
│   │   ├── tools/shieldDeskChatTools.ts  # Constrained SOC incident tools
│   │   └── utils.ts                      # Shared utility helpers
│   └── types/                            # Shared TypeScript type definitions
├── ai-chat-desk/                         # Python Vulnerability Intelligence Engine (Port 8000)
│   ├── server.py                         # FastAPI server — CVE scoring & ML inference
│   ├── cve_random_forest.py              # Unified Random Forest model architecture
│   ├── feature_extractor.py              # Hybrid n-gram + threat regex feature pipeline
│   ├── data_pipeline.py                  # CVE data ingestion & preprocessing
│   ├── train_rf_model.py                 # Model training script (Random Forest)
│   ├── train_model.py                    # Alternative full model training pipeline
│   ├── evaluate.py                       # Model evaluation & metric reporting
│   ├── predict.py                        # Inference utilities for standalone use
│   ├── cve_ai_engine.py                  # High-level engine wrapper
│   └── requirements.txt                  # Python dependencies
├── services/
│   ├── ingest/                           # Go 1.22 gRPC Ingest (:50051) with mTLS & PII scrubber
│   ├── threat/                           # Go 1.22 daemon with YARA, Sigma & 3-sigma ML anomaly
│   ├── scan/                             # Python 3.12 FastAPI (:8001) Trivy CVE & Gitleaks
│   ├── iam/                              # Node.js 20 Express (:4000) JWT, TOTP MFA & RBAC
│   ├── ai-advisor/                       # Python 3.12 LangChain (:8002) Claude 3.5 Sonnet RAG
│   └── webhooks/                         # Go 1.22 HMAC-SHA256 dispatcher with retry queue
├── shared/
│   ├── proto/                            # Protobuf gRPC contracts & v1 Go bindings
│   ├── schemas/                          # PostgreSQL 16 schema-per-tenant, TimescaleDB & pgvector
│   └── events/                           # NATS JetStream event subjects & JSON schemas
├── gateway/
│   └── kong.yml                          # Kong API Gateway declarative routing & rate limiting
├── infra/
│   ├── terraform/                        # AWS EKS 1.29, RDS Multi-AZ, ElastiCache Redis, S3 & VPC
│   └── helm/                             # Production Kubernetes Helm chart (Deployments, HPA, PDB)
├── agent/
│   ├── cmd/main.go                       # Go endpoint agent daemon
│   ├── pkg/                              # Telemetry ring buffer, hash chaining, handlers
│   ├── deploy-agent.ps1                  # Windows endpoint enrollment script
│   └── deploy-agent.sh                   # Linux systemd endpoint enrollment script
├── tests/                                # 39 automated unit, security, and governance tests
├── docker-compose.yml                    # 1-command multi-service orchestration
├── Dockerfile                            # Container image for Next.js application
└── .env.example                          # Production environment template (see below)
```

---

## Environment Configuration

Copy `.env.example` to `.env.local` and configure the following variables:

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | ✅ | PostgreSQL connection string (default: `postgresql://shielddesk:shielddesk@localhost:5432/shielddesk`) |
| `PYTHON_AI_SERVICE_URL` | ✅ | URL for Python Vulnerability ML Engine (default: `http://localhost:8000`) |
| `OLLAMA_BASE_URL` | ✅ | Ollama LLM endpoint (default: `http://localhost:11434/v1`) |
| `OLLAMA_MODEL` | ✅ | Ollama model name (default: `qwen3:4b`) |
| `SHIELDDESK_INGEST_API_KEY` | ✅ | API key protecting `POST /api/ingest/webhooks` |
| `NEXT_PUBLIC_SUPABASE_URL` | ⬜ | Optional Supabase project URL for cloud auth |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | ⬜ | Supabase anonymous public key |
| `SUPABASE_SERVICE_ROLE_KEY` | ⬜ | Supabase service role key (server-side only) |
| `SLACK_WEBHOOK_URL` | ⬜ | Slack incoming webhook for Tier 2/3 alert cards |
| `TEAMS_WEBHOOK_URL` | ⬜ | Microsoft Teams incoming webhook for alert cards |
| `SECURITY_WEBHOOK_URL` | ⬜ | External SIEM webhook for real-time alert forwarding |
| `REDIS_URL` | ⬜ | Redis connection URL for multi-node session caching |

> **Note:** Supabase configuration is optional. When omitted, ShieldDesk uses the local Quick Persona switcher for authentication with the local PostgreSQL database.

---

## License & Security Mandate
ShieldDesk is built strictly for isolated, privacy-first security operations. All sensitive operations enforce Human-in-the-Loop governance, cryptographic auditability, and zero cross-tenant enumeration.
