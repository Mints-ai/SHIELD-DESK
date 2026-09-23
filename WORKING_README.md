# ShieldDesk Autonomous SOC Platform — Working Architecture & Run Guide

> **A comprehensive operational guide to how the Web UI, PostgreSQL Database, Python Vulnerability Intelligence Engine, Endpoint Agent Fleet, and Local LLM Co-Pilot function together as an integrated system.**

---

## 1. System Port Map & Services

| Service | Port | Technology | Purpose |
|---|---|---|---|
| **Web UI & Security Gateway** | `3000` | Next.js 15 / React 19 (TypeScript) | Incident triage, Kanban task board, fleet control, compliance, and AI chat |
| **Vulnerability ML Engine** | `8000` | Python 3.10+ / FastAPI / Scikit-Learn | Real-time CVSS scoring, KEV exploit risk, remediation tier classification |
| **Multi-Tenant Database** | `5432` | PostgreSQL 15+ | Incidents, assets, mitigation plans, 24h approval tokens, immutable audit logs |
| **Local LLM Co-Pilot** | `11434` | Ollama (`qwen3:4b`) | Local conversational synthesis & intent routing (zero data egress) |
| **Endpoint Agent Fleet** | N/A | Go + Rust Daemons | Telemetry collection, safety snapshots, Tier 1–3 remediation execution |

---

## 2. End-to-End Operational Flow

### Step 1: Authentication & Role Selection
When opening `http://localhost:3000/login`, the user selects an operational persona:
- **`dev-analyst` (Acme Corporation)**: Role `user` in `acme-tenant`. Scoped strictly to Acme incidents and endpoints.
- **`dev-admin` (Acme Corporation)**: Role `system_admin` in `acme-tenant`. Has elevated approval authority and fleet emergency kill-switch rights.
- **`dev-other` (Globex Corporation)**: Role `user` in `globex-tenant`. Used to test and verify multi-tenant isolation and anti-enumeration.

The session is persisted via cookie and verified at the API layer with `getSessionFromRequest()`.

---

### Step 2: Autonomous SOC Navigation & Views
The platform provides 6 dedicated operational consoles in the minimal **Beige & Deep Forest Spruce** design system:

1. **Incident Triage Queue (`/`)**:
   - Inspect active tenant incidents (`INC-1042: Suspicious lateral movement on FIN-WS-042`).
   - Review correlated chronological attack timelines.
   - Inspect affected endpoint assets (`FIN-WS-042`, `FIN-DB-01`).
   - Review linked vulnerability intelligence and trigger mitigation plan synthesis.

2. **3-Horizon Mitigation Workspace (`/dashboard/plans/[id]`)**:
   - **Horizon 1 (Immediate Containment)**: Host network quarantine, user session termination.
   - **Horizon 2 (Short-Term Patching)**: Deploy vendor hotfixes, remediate linked CVEs.
   - **Horizon 3 (Long-Term Hardening)**: Zero-trust micro-segmentation, SIEM correlation updates.

3. **SOC Kanban Governance Board (`/dashboard/tasks`)**:
   - 4-column operational lifecycle: *Pending Authorization* -> *Authorized & Queued* -> *In Progress* -> *Completed & Audited*.
   - Filter by horizon, execute Tier 1 auto-actions, or submit human approval tokens for Tier 2/3 tasks.

4. **Universal Endpoint Fleet & Live Command (`/dashboard/fleet`)**:
   - Live telemetry monitors (active hosts, aggregate EPS, baseline safety health).
   - Enrolled host list with CPU & Memory utilization gauges.
   - Live command dispatcher with pre-flight safety snapshots.
   - Fleet-wide Emergency Kill Switch (admin-gated).

5. **ISO 27001 Compliance & Evidence Attestation (`/dashboard/compliance`)**:
   - 96% Audit Readiness Index.
   - Control mappings across Annex A.5.24, A.5.28, A.8.7, A.8.16, A.8.28.
   - Cryptographic export button generating signed audit packages with hash-chain verification.

6. **Executive Risk Scorecard (`/dashboard/risk-scorecard`)**:
   - Posture Grade A with $1.45M estimated loss avoided.
   - 96%+ reduction in Mean Time to Detect (MTTD) and Mean Time to Remediate (MTTR).

---

### Step 3: AI Co-Pilot & Security Gateway (`/api/chat`)
When interacting with the AI chat drawer:

```
Analyst Query ──► Pre-LLM Regex Guardrails ──► Intent Classifier (Path A / Path B)
                                                        │
                      ┌─────────────────────────────────┴─────────────────────────────────┐
                      ▼                                                                   ▼
       Path A: Deterministic Structure                                     Path B: Few-Shot Model Call
       • Explicit CVE ID (e.g. CVE-2020-6240)                              • Conversational Queries
       • Explicit Incident Code (e.g. INC-1042)                            • Ambiguous Next Steps
       • Broad Listing (e.g. "show incidents")                             • Out-of-scope Rejection
                      │                                                                   │
                      └───────────────────────────────┬───────────────────────────────────┘
                                                      │
                                                      ▼
                                       RBAC & Tenant Verification
                                       canExecuteTool(role, tool)
                                                      │
                                                      ▼
                                       Tool Execution via Gateway
                              ┌───────────────────────┴───────────────────────┐
                              ▼                                               ▼
                     PostgreSQL Database                             Python ML Engine (Port 8000)
                     (Tenant Scoped)                                 (Random Forest Inference)
                              │                                               │
                              └───────────────────────┬───────────────────────┘
                                                      │
                                                      ▼
                                         Ollama Response Synthesis
                                      (With Deterministic Offline Fallback)
```

1. **Adversarial Guardrails**: Sanitizes prompt injection patterns and blocks forbidden code/command metacharacters.
2. **Intent Resolution**: Resolves queries into one of the 4 allow-listed tools:
   - `getIncidents`: Scoped tenant listing with severity & status filters.
   - `investigateIncident`: Joins incident details, timeline events, and affected assets.
   - `analyzeCve`: Calls the Python Random Forest engine for real-time risk scores and mitigations.
   - `generateMitigationPlan`: Generates multi-horizon playbooks and persists them to the database.
3. **Resilient Offline Fallback**: If Ollama is offline or in cold start, `formatToolResultFallback` synthesizes the exact database and ML telemetry into clean, structured analyst advisories without failing.
4. **Audit Logging**: Every query and response is recorded in `chat_audit_log` with user ID, tenant ID, tool called, and timestamp.

---

## 3. Daily Startup Instructions

To launch the full development environment:

### Terminal 1: Next.js Frontend & API Server
```powershell
# In the repository root:
npm install
npm run dev
```
*Accessible at: `http://localhost:3000`*

### Terminal 2: Python Vulnerability Intelligence Microservice
```powershell
cd ai-chat-desk
pip install -r requirements.txt
python server.py
```
*Accessible at: `http://localhost:8000`*

### Terminal 3: (Optional) Local Ollama LLM
```powershell
ollama run qwen3:4b
```
*Accessible at: `http://localhost:11434`*

---

## 4. Retraining the Vulnerability Model

The Python engine features a retrained **Unified Random Forest Architecture** (`CVERandomForestModel`):
- **12,968 historical CVE records** across Operating Systems, Enterprise ERP, SAP, and Defender.
- **Hybrid feature extractor**: 12,000 sublinear word n-grams + 8,000 char n-grams + 10 threat regex patterns + EPSS/KEV priors.
- **Evaluation Metrics**:
  - CISA KEV Threat ROC-AUC: **`0.9801`**
  - Remediation Tier Accuracy: **`90.79%`** (Weighted F1: `0.8957`)
  - CVSS Continuous Score Regressor: Mean Absolute Error of **`0.606`** points ($R^2 = 0.5072$)

To retrain the model artifact:
```powershell
cd ai-chat-desk
python train_rf_model.py
```
The model bundle is automatically validated and saved to `ai-chat-desk/models/cve_random_forest_model.joblib`.

---

## 5. Running the Test Suite

ShieldDesk includes 34 automated unit, security, and governance tests:

```powershell
npm test
```

### Coverage:
- **Tenant Isolation**: Verifies that `dev-other` cannot query or inspect `acme-tenant` incidents or endpoint agents.
- **Anti-Enumeration**: Verifies that cross-tenant queries return `404 Not Found` (anti-enumeration 404).
- **Separation of Duties**: Verifies that requesters cannot approve their own Tier 2/3 action tokens.
- **Adversarial Injections**: Verifies that prompt injections, SQL injections, and metacharacters are neutralized.
- **Audit Attestation**: Verifies hash-chain verification and compliance evidence generation.
