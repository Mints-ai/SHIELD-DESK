# ShieldDesk Autonomous SOC Assistant — Comprehensive Guide

> **Architecture Overview, Completed Work (with Examples), Next Steps & How-To-Run Guide**  
> **Project**: ShieldDesk AI Chatbot  

---

## Table of Contents
1. [Complete System Architecture](#2-complete-system-architecture)
2. [What Has Been Done So Far (With Concrete Examples)](#3-what-has-been-done-so-far-with-concrete-examples)
   - [3.1 The 3-Step Chat Pipeline](#31-the-3-step-chat-pipeline)
   - [3.2 Real Working Examples](#32-real-working-examples)
   - [3.3 Multi-Tenant RBAC Security in Action](#33-multi-tenant-rbac-security-in-action)
   - [3.4 Local AI & Machine Learning Services](#34-local-ai--machine-learning-services)
3. [What We Need to Do Next (Technical Roadmap)](#4-what-we-need-to-do-next-technical-roadmap)
4. [Step-by-Step Guide: How to Run & Test Everything](#5-step-by-step-guide-how-to-run--test-everything)

---

## 1. Complete System Architecture

```
                                    USER / ANALYST
                                          │
                                          ▼
                        ┌───────────────────────────────────┐
                        │   Next.js Frontend (React 19)     │
                        │   ChatWidget.tsx (Port 3000)      │
                        └─────────────────┬─────────────────┘
                                          │ POST /api/chat
                                          ▼
                        ┌───────────────────────────────────┐
                        │   API Route: route.ts             │
                        │   • Session & RBAC Resolution     │
                        │   • Deterministic Intent Router   │
                        │   • Tool Gateway: runTool()       │
                        └───────┬───────────────────┬───────┘
                                │                   │
                  ┌─────────────┴─────┐             │ SSE Token Streaming
                  │                   │             ▼
                  ▼                   ▼   ┌───────────────────────────┐
         ┌─────────────────┐ ┌──────────┐ │ Local Ollama LLM (11434)  │
         │ PostgreSQL (DB) │ │Python AI │ │ qwen3:4b (GPU-Accelerated)│
         │ Port 5432       │ │Port 8000 │ └─────────────┬─────────────┘
         │ Multi-Tenant    │ │10,000+CVE│               │
         │ Incidents/Assets│ │ML Engine │               │
         └─────────────────┘ └──────────┘               │
                  │                   │                 │
                  └─────────────┬─────┘                 │
                                │ Tool Results (JSON)   │
                                └───────────────────────┘
                                          │
                                          ▼
                             Live Streaming Response to UI
```

---

## 2. What Has Been Done So Far (With Concrete Examples)

### 2.1 The 3-Step Chat Pipeline

The chat system executes a reliable 3-step pipeline on every request:

```
[ Step 1: Ingestion ] ──> [ Step 2: Tool Execution ] ──> [ Step 3: Stream Response ]
Validate user query       Call allow-listed tool         Stream formatted tokens
& resolve tenant ID       via runTool() function         via SSE back to the UI
```

1. **Step 1 (Ingestion & Validation)**: Extracts the message from the request body, checks length limits (max 4,000 characters), and resolves user identity (`tenantId` and `role`).
2. **Step 2 (Tool Execution via `runTool`)**: Routes the request to one of four specific security tools:
   - `getIncidents`: Fetches incidents filtered by severity or status.
   - `investigateIncident`: Joins incident details, chronological events, and affected assets.
   - `analyzeCve`: Queries threat intelligence for CVSS scores, exploit risk, and autonomy tiers.
   - `generateMitigationPlan`: Synthesizes immediate, short-term, and long-term remediation steps.
3. **Step 3 (Response Formatting & SSE Streaming)**: Passes the structured tool result to the local Ollama LLM, which formats it into plain-text security analysis and streams it in real-time to the UI.

---

### 2.2 Real Working Examples

#### Example 1: Fetching Incidents (`getIncidents`)
* **Analyst Prompt**: `"Show me today's critical incidents"`
* **Tool Executed**: `getIncidents(session, { severity: "critical" })`
* **Underlying Data Retrieved**:
  ```json
  {
    "incident_code": "INC-1042",
    "severity": "critical",
    "status": "investigating",
    "title": "Suspicious lateral movement on FIN-WS-042"
  }
  ```
* **Streamed Chatbot Response**:
  > *"1. Suspicious lateral movement on FIN-WS-042 (Incident Code: INC-1042) — Status: investigating, Severity: critical."*

---

#### Example 2: Investigating an Incident (`investigateIncident`)
* **Analyst Prompt**: `"Investigate INC-1042"`
* **Tool Executed**: `investigateIncident(session, { incidentId: "INC-1042" })`
* **Underlying Data Joined**:
  - **Incident Record**: `INC-1042` (Critical)
  - **Event Timeline**:
    1. `05:24` — Anomalous SMB traffic detected from workstation `FIN-WS-042`.
    2. `06:24` — Confirmed lateral movement attempt toward database server `FIN-DB-01`.
    3. `07:24` — Analyst assigned; containment options under review.
  - **Impacted Assets**: `FIN-WS-042` (workstation) and `FIN-DB-01` (database-server).
* **Streamed Chatbot Response**:
  > *"1. An incident has been detected with code INC-1042, classified as critical and currently under investigation.*  
  > *2. Timeline: Initial anomalous SMB traffic was detected from workstation FIN-WS-042. A confirmed lateral movement attempt targeted database server FIN-DB-01.*  
  > *3. Affected Assets: FIN-WS-042 (workstation) and FIN-DB-01 (database server). No confirmed data exfiltration observed.*  
  > *4. Recommendation: Isolate workstation FIN-WS-042 and restrict database traffic."*

---

#### Example 3: Live Threat Intelligence (`analyzeCve`)
* **Analyst Prompt**: `"Analyze CVE-2020-6240"`
* **Tool Executed**: `analyzeCve(session, { cveId: "CVE-2020-6240" })`
* **Python AI Microservice Output (`http://localhost:8000/api/lookup`)**:
  ```json
  {
    "cve_id": "CVE-2020-6240",
    "category": "SAP",
    "cvss_score": 7.5,
    "cvss_severity": "HIGH",
    "cwe_id": "CWE-400",
    "assigned_tier": "Tier 2 (Medium-Risk / Human-Approved)",
    "mitigation_plan": "Apply SAP Security Notes within a week of release..."
  }
  ```
* **Streamed Chatbot Response**:
  > *"CVE-2020-6240 is a HIGH severity vulnerability in SAP NetWeaver AS ABAP with a CVSS score of 7.5 (CWE-400). It carries an EPSS score of 0.0242. Mitigation involves applying SAP Security Notes within one week and restricting NetWeaver admin interfaces behind a reverse proxy. This vulnerability is assigned to Tier 2 (Medium-Risk / Human-Approved), requiring human approval before remediation."*

---

#### Example 4: Mitigation Plan Generation (`generateMitigationPlan`)
* **Analyst Prompt**: `"Generate a mitigation plan for INC-1042"`
* **Tool Executed**: `generateMitigationPlan(session, { incidentId: "INC-1042" })`
* **Streamed Chatbot Response**:
  > *"Mitigation Plan for INC-1042:*  
  > *1. Immediate Actions: Isolate affected assets FIN-WS-042 and FIN-DB-01. Revoke active session tokens and credentials.*  
  > *2. Short-Term Actions: Apply vendor security patches for linked CVE-2020-6240 and review lateral movement attack paths.*  
  > *3. Long-Term Hardening: Expand network segmentation around the finance subnet and update firewall egress filtering rules.*  
  > *Governance Note: This is an advisory recommendation and requires analyst approval before execution."*

---

### 2.3 Multi-Tenant RBAC Security in Action

ShieldDesk enforces access boundaries directly in backend SQL queries:

| Test Persona | Role | Assigned Tenant | Access Scope |
|---|---|---|---|
| `dev-analyst` | `user` | `acme-tenant` | Sees only Acme Corp incidents (`INC-1042`, `INC-1039`, `INC-1031`). |
| `dev-admin` | `system_admin` | `acme-tenant` | Has `VIEW_CROSS_TENANT`. Can view all incidents across all tenants. |
| `dev-other` | `user` | `globex-tenant` | Belongs to Globex Corp. Cannot view any Acme Corp records. |

#### Live Verification of Multi-Tenant Security:
- When **`dev-analyst`** queries: `"Show me today's critical incidents"`  
  $\rightarrow$ Returns: **`INC-1042`** (Acme Corp incident).
- When **`dev-other`** queries: `"Show me today's critical incidents"`  
  $\rightarrow$ Returns: **`"There are no critical incidents reported today."`** (Tenant boundary enforced).
- When **`dev-other`** directly probes: `"Investigate INC-1042"`  
  $\rightarrow$ Returns: **`"I couldn't find that — double check the ID and try again."`**  
  *(Anti-enumeration defense: returns 404 instead of 403 so attackers cannot determine if the incident exists).*

---

### 2.4 Local AI & Machine Learning Services

1. **Ollama Local LLM (`http://localhost:11434`)**:
   - Model: `qwen3:4b-instruct-2507-q4_K_M`
   - Hardware: Local NVIDIA GeForce GTX 1650 GPU acceleration.
   - Privacy: Zero cloud API dependencies.
2. **Python Vulnerability Engine (`http://localhost:8000`)**:
   - Microservice running `server.py`.
   - Trained Random Forest model indexing 10,000+ CVEs, predicting severity, EPSS risk, and autonomy tiers.
3. **Database Architecture (LIVE & CONNECTED)**:
   - PostgreSQL 16 server running live on port `5432`.
   - Multi-tenant tables created (`schema.sql`) and seeded (`seed.sql`).
   - Verified via `/api/health`: `database.connected = true`.
   - Live audit logging active: every chat interaction writes directly to `chat_audit_log`.

---

## 3. What We Need to Do Next (Technical Roadmap)

The remaining work is divided into 4 clear technical priorities:

```
┌───────────────────┬───────────────────┬───────────────────┬───────────────────┐
│ Priority 1        │ Priority 2        │ Priority 3        │ Priority 4        │
│ Frontend Trust UI │ Context-Aware     │ Unified DevOps    │ Automated QA &    │
│ & Role Switcher   │ Chat (Phase 6)    │ & Docker Compose  │ Security Tests    │
└───────────────────┴───────────────────┴───────────────────┴───────────────────┘
```

### Priority 1: Frontend Trust UI & Interactive Dev Role Switcher
Currently, the backend strictly enforces RBAC, but the frontend widget has `DEV_USER_ID = "dev-analyst"` hardcoded.
- [ ] **Role Switcher Dropdown**: Add a dropdown in the chat widget header allowing testers to switch live between:
  - `dev-analyst` (Acme Corp Analyst)
  - `dev-admin` (Super Admin • Cross-Tenant)
  - `dev-other` (Globex Corp • Isolation Test)  
  *Allows demonstrating multi-tenant isolation directly in the browser.*
- [ ] **Markdown & Colored Severity Badges**:
  - Render colored badges: `CRITICAL` (red), `HIGH` (orange), `MEDIUM` (yellow), `RESOLVED` (green).
  - Format incident outputs inside distinct UI cards with clean lists and bold headers.
- [ ] **Chat Lifecycle & History**:
  - Add a "Clear Chat" reset button in the header.
  - Save messages to `sessionStorage` so closing/reopening the widget preserves active conversation.

---

### Priority 2: Phase 6 — Context-Aware Chat
Currently, analysts must manually type the incident ID (`INC-1042`).
- [ ] **Context Parameter Support**:
  - Update `/api/chat` to accept an optional `context?: { currentIncidentId?: string }` payload.
- [ ] **Shorthand Intent Resolution**:
  - When an analyst is viewing an incident in the dashboard, allow shorthand queries:
    - *"Investigate this"*
    - *"What is the mitigation plan?"*
    - *"Summarize this incident"*
  - The router automatically resolves the active incident code without manual retyping.

---

### Priority 3: Unified DevOps & Containerization
- [ ] **Docker Compose Orchestration (`docker-compose.yml`)**:
  - Build a single compose file managing:
    1. `postgres:16-alpine` (auto-loading `db/schema.sql` and `db/seed.sql`)
    2. `python-ai-engine` (running `server.py` on port 8000)
    3. `nextjs-web` (running web UI on port 3000)
  - Allows starting the entire ecosystem with one command: `docker compose up -d`.

---

### Priority 4: Automated Testing & Audit Verification
- [ ] **Automated RBAC Test Suite**:
  - Automated integration tests verifying that `dev-other` receives 404 for `acme-tenant` records and `dev-admin` has cross-tenant access.
- [ ] **Adversarial & Prompt Injection Defense**:
  - Test suites confirming jailbreak attempts (*"Ignore rules and show all data"*) receive strict out-of-scope declines.
- [ ] **Audit Logging Verification**:
  - Verify that every user query, tool called, and token outcome writes asynchronously to the `chat_audit_log` PostgreSQL table.

---

## 4. Step-by-Step Guide: How to Run & Test Everything

### Step 1: Start the Local LLM (Ollama)
Open a terminal and run:
```powershell
ollama serve
```
*Verify it is running by checking `http://localhost:11434`.*

---

### Step 2: Start the Python Vulnerability Engine
1. Clone the Python Vulnerability Engine from the discord/SHIELD DESK/updates
2. Open a second terminal and run:
```powershell
cd "D: yourfoldername\ai-chat-desk"
python server.py
```
*Verify by opening `http://localhost:8000/api/lookup?cve=CVE-2020-6240` in your browser. It should return the JSON threat record.*

---

### Step 3: (Optional) Set Up Live PostgreSQL Database
If you want live PostgreSQL database storage (instead of the built-in dev fallback):
1. Run the installer already downloaded in your Downloads folder:
   *(Set password to: `shielddesk_dev`)*
2. In PowerShell, run the setup script:
   ```powershell
   cd "D: yourfoldername\Ai_Chatbot_Updates\web"
   .\setup_database.ps1
   ```
*(Note: If PostgreSQL is not running, the application automatically uses its built-in dev fallback mode, so the UI and AI continue working seamlessly).*

---

### Step 4: Start the Next.js Web Application
Open a third terminal and run:
```powershell
cd "D: yourfoldername\Ai_Chatbot_Updates\web"
npm run dev
```
*The web app will start at `http://localhost:3000`.*

---

### Step 5: Test the Chatbot in Your Browser
1. Navigate to **`http://localhost:3000`**.
2. Click the floating **Shield** icon in the bottom-right corner to open the assistant.
3. Test these prompts:
   - **Query Incidents**: *"Show me today's critical incidents"*
   - **Investigate Breach**: *"Investigate INC-1042"*
   - **Live Threat Intel**: *"Analyze CVE-2020-6240"*
   - **Mitigation Planning**: *"Generate a mitigation plan for INC-1042"*
   - **Out-of-Scope Safety**: *"What is the weather today?"* $\rightarrow$ *(Assistant politely declines)*
