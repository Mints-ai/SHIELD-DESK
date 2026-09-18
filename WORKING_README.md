# ShieldDesk Autonomous SOC Assistant — Working Architecture & Run Guide

> **A plain-English guide to how the Chatbot, PostgreSQL Database, and Python Vulnerability Engine work together as an integrated system, and how to start and run the database and services.**

---

## 1. The Big Picture: How the 3 Pieces Connect

ShieldDesk connects three independent services behind a unified security gateway:

```
                      +----------------------------------------------------+
                      |               USER BROWSER / UI                    |
                      |        http://localhost:3000 (React 19)            |
                      +-------------------------+--------------------------+
                                                |
                                      POST /api/chat
                                                |
                                                v
                      +----------------------------------------------------+
                      |            NEXT.JS API ROUTER (Server)             |
                      |                 src/app/api/chat/                  |
                      |  1. Authenticates session (Tenant & Role)          |
                      |  2. Decides which tool to trigger                  |
                      +-------+--------------------+-------------------+---+
                              |                    |                   |
            Tool 1 & 2        |         Tool 3 & 4 |                   | SSE Streaming
            (Incidents/Assets)|         (Threats)  |                   | (Token-by-token)
                              v                    v                   v
      +-------------------------+    +-------------------+    +----------------------+
      |   POSTGRESQL DATABASE   |    | PYTHON AI ENGINE  |    |   LOCAL OLLAMA LLM   |
      |       Port: 5432        |    |    Port: 8000     |    |     Port: 11434      |
      +-------------------------+    +-------------------+    +----------------------+
      | • Multi-Tenant Tables   |    | • 10,000+ CVE KB  |    | • qwen3:4b (Local)   |
      | • Strict Tenant Scope   |    | • Random Forest ML|    | • NO direct DB access|
      | • Immutable Audit Logs  |    | • CVSS / EPSS /   |    | • Translates JSON    |
      |                         |    |   Autonomy Tiers  |    |   into plain English |
      +-------------------------+    +-------------------+    +----------------------+
```

---

## 2. How the Combined Architecture Works (Step-by-Step)

Here is what happens when you type a message in the chat widget:

### Step 1: The User Sends a Prompt
* You type: `"Show me today's critical incidents"` or `"Analyze CVE-2020-6240"`.
* The frontend sends an HTTP POST request to `/api/chat` with your message and your identity header (`X-ShieldDesk-User: dev-analyst`).

### Step 2: The Security Gateway Authenticates & Isolates
* The server determines your identity:
  - **User**: `dev-analyst`
  - **Tenant**: `acme-tenant` (Acme Corporation)
  - **Role**: `user` (Standard Analyst)
* **Security Rule**: The server enforces that you can **never** see or query records belonging to other companies (e.g. `globex-tenant`).

### Step 3: The Gateway Triggers the Appropriate Tool
The LLM is **never given direct database access**. Instead, the server calls one of four hardcoded backend tools:

| What you ask | Tool Triggered | Where it gets data |
|---|---|---|
| *"Show me incidents..."* | `getIncidents` | **PostgreSQL** (`SELECT ... WHERE tenant_id = $1`) |
| *"Investigate INC-1042"* | `investigateIncident` | **PostgreSQL** (Joins timeline events & affected assets) |
| *"Analyze CVE-2020-6240"* | `analyzeCve` | **Python AI Engine** (`GET http://localhost:8000/api/lookup`) |
| *"Mitigation plan for INC-1042"* | `generateMitigationPlan` | **PostgreSQL** (to find linked CVEs) + **Python AI** (to calculate remediation tiers) |

### Step 4: The Local LLM Formats the Answer
* The backend tool receives the raw data (JSON).
* It passes this JSON to the **Local Ollama LLM** (`qwen3:4b`).
* The LLM translates the raw data into clean, readable analyst notes.
* The response is streamed token-by-token using **Server-Sent Events (SSE)** directly to your chat window.

### Step 5: Immutable Audit Logging
* Before completing, the server writes a permanent record into the PostgreSQL `chat_audit_log` table:
  - Who asked (`dev-analyst`)
  - What tenant (`acme-tenant`)
  - Which tool was used (`getIncidents`)
  - The outcome (`authorized`)

---

## 3. Why This Architecture is Secure

1. **Zero Database Access for the AI**:
   The Ollama model has **no database credentials, connection strings, or SQL capabilities**. It cannot run `SELECT`, `DROP`, or `INSERT`.
2. **Server-Enforced Tenant Isolation**:
   The SQL query automatically appends `AND tenant_id = $1` on the server. Even if a user prompts *"Show me all companies' data"*, the server strictly limits results to the caller's assigned tenant.
3. **Anti-Enumeration 404 Protection**:
   If an analyst from `globex-tenant` attempts to inspect `INC-1042` (which belongs to `acme-tenant`), the system returns **404 Not Found** (not 403 Forbidden), so attackers cannot discover whether an incident code exists.
4. **100% On-Premises Privacy**:
   Both Ollama and the Python ML model run on your local machine. No incident, host, or vulnerability data ever crosses the internet.

---

## 4. How to Run the Updated Database (Port 5432)

The database setup script has been updated with **automatic start detection**. If PostgreSQL is not running when you run the script, it automatically launches PostgreSQL in the background.

### Option A: The One-Step Setup Script (Recommended)
Open PowerShell in the `web` folder and run:
```powershell
cd "D:\mario\mINTS\ShieldDesk\Chatbot\New folder\Ai_Chatbot_Updates\web"
.\setup_database.ps1
```

**What this script does automatically**:
1. Checks if PostgreSQL is listening on port `5432`.
2. If stopped, it automatically starts the PostgreSQL server in the background.
3. Creates the `shielddesk` user and database (idempotently).
4. Applies `db/schema.sql` (creates `incidents`, `events`, `assets`, `audit_log`).
5. Applies `db/seed.sql` (seeds test data and CVEs without duplicate errors).
6. Verifies connection and prints the active incidents table.

---

### Option B: Manual PostgreSQL Commands
If you ever want to start, stop, or check PostgreSQL manually:

* **Start PostgreSQL Server**:
  ```powershell
  & "D:\postgres\bin\pg_ctl.exe" -D "D:\mario\mINTS\ShieldDesk\Chatbot\New folder\Ai_Chatbot_Updates\web\pgdata" -l "D:\mario\mINTS\ShieldDesk\Chatbot\New folder\Ai_Chatbot_Updates\web\pgdata\server.log" start
  ```
* **Check Status**:
  ```powershell
  & "D:\postgres\bin\pg_ctl.exe" -D "D:\mario\mINTS\ShieldDesk\Chatbot\New folder\Ai_Chatbot_Updates\web\pgdata" status
  ```
* **Stop Server**:
  ```powershell
  & "D:\postgres\bin\pg_ctl.exe" -D "D:\mario\mINTS\ShieldDesk\Chatbot\New folder\Ai_Chatbot_Updates\web\pgdata" stop
  ```

---

## 5. Complete Daily Startup Guide (Running All Services)

To run the entire system, open 3 separate PowerShell terminals:

### Terminal 1: Start PostgreSQL & Next.js Web App
```powershell
cd "D:\mario\mINTS\ShieldDesk\Chatbot\New folder\Ai_Chatbot_Updates\web"

# 1. Initialize / start database (auto-starts PostgreSQL):
.\setup_database.ps1

# 2. Start web frontend & API router:
npm run dev
```
*Frontend runs at: `http://localhost:3000`*

---

### Terminal 2: Start Python Vulnerability Engine
```powershell
cd "D:\mario\mINTS\ShieldDesk\Chatbot\ai-chat-desk"
python server.py
```
*Vulnerability microservice runs at: `http://localhost:8000`*

---

### Terminal 3: Start Local Ollama LLM
```powershell
ollama serve
```
*Local LLM service runs at: `http://localhost:11434`*

---

## 6. How to Verify Everything is Working

1. **Check System Health**:
   Open in your browser: `http://localhost:3000/api/health`  
   Expected JSON output:
   ```json
   {
     "status": "ok",
     "ollama": { "baseUrl": "http://localhost:11434/v1", "reachable": true },
     "database": { "configured": true, "connected": true }
   }
   ```

2. **Open the Chatbot**:
   Navigate to `http://localhost:3000` and click the shield icon in the bottom-right corner.

3. **Try These Test Queries**:
   * **Database Read**: `"Show me today's critical incidents"` $\rightarrow$ Returns `INC-1042`.
   * **Database Investigation**: `"Investigate INC-1042"` $\rightarrow$ Joins timeline events and affected assets (`FIN-WS-042`).
   * **Python AI Threat Lookup**: `"Analyze CVE-2020-6240"` $\rightarrow$ Returns SAP NetWeaver CVSS 7.5 and Tier 2 Autonomy.
   * **Mitigation Planning**: `"Generate a mitigation plan for INC-1042"` $\rightarrow$ Synthesizes 3-horizon remediation.
   * **Audit Log Check**: Every question asked is automatically saved in PostgreSQL in the `chat_audit_log` table.
