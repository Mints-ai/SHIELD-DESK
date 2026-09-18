# ShieldDesk AI Chat Widget

Next.js frontend + server-side API for the **ShieldDesk Autonomous SOC Assistant**.

Powered by a **local Ollama LLM** running on GPU acceleration and a **local Python Vulnerability Intelligence Engine**. **No customer, threat, or incident data ever leaves your own infrastructure.**

---

## Architecture Overview

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

## Quick Start (Daily Startup)

To run the entire system, open 3 PowerShell windows:

### Terminal 1: PostgreSQL & Next.js Web App
```powershell
cd "D:\mario\mINTS\ShieldDesk\Chatbot\New folder\Ai_Chatbot_Updates\web"

# 1. Start / verify PostgreSQL (automatically wakes up port 5432):
.\setup_database.ps1

# 2. Start web application:
npm run dev
```
*Frontend runs at: `http://localhost:3000`*

### Terminal 2: Python Vulnerability Intelligence Engine
```powershell
cd "D:\mario\mINTS\ShieldDesk\Chatbot\ai-chat-desk"
python server.py
```
*Vulnerability microservice runs at: `http://localhost:8000`*

### Terminal 3: Local Ollama LLM
```powershell
ollama serve
```
*Local LLM service runs at: `http://localhost:11434`*

---

## System Verification

Visit **`http://localhost:3000/api/health`** to verify system readiness:

```json
{
  "status": "ok",
  "ollama": {
    "baseUrl": "http://localhost:11434/v1",
    "reachable": true
  },
  "database": {
    "configured": true,
    "connected": true
  }
}
```

---

## Security & Architecture Principles

### 1. Zero Direct Database Access for AI
The local LLM (Ollama) has **no database credentials, connection strings, or SQL capabilities**. It cannot execute arbitrary SQL (`SELECT`, `DROP`, `INSERT`). All interactions flow through the **Next.js Tool Gateway (`runTool`)**, which executes parameterized queries with strict server-enforced tenant filtering.

### 2. Multi-Tenant Role-Based Access Control (RBAC)
Tenant isolation and RBAC are enforced at the database level:
- **`system_admin`**: Holds `VIEW_CROSS_TENANT` permission; can inspect incidents across all tenants.
- **`user`**: Standard analyst; strictly isolated to their own `tenant_id`. Queries automatically enforce `WHERE tenant_id = $1`.

### 3. Anti-Enumeration 404 Protection
If an analyst from `globex-tenant` attempts to inspect `INC-1042` (belonging to `acme-tenant`), the system returns **404 Not Found** (not 403 Forbidden). This prevents malicious actors from enumerating whether an incident exists.

---

## The 4 Constrained SOC Tools

The model is strictly restricted to 4 allow-listed security tools defined in `src/lib/tools/shieldDeskChatTools.ts`:

1. **`getIncidents`**: Fetches incidents scoped to the caller's tenant, with optional filters for `severity` and `status`.
2. **`investigateIncident`**: Deep-dives into an incident code (e.g. `INC-1042`), joining timeline events and affected assets.
3. **`analyzeCve`**: Queries the Python AI Engine (`http://localhost:8000/api/lookup`) for real-time CVSS scores, exploit likelihood (EPSS), and autonomy remediation tiers.
4. **`generateMitigationPlan`**: Synthesizes 3-horizon remediation (Immediate containment, short-term patching, long-term segmentation).

---

## Project Structure

```
db/
├── schema.sql                 # Multi-tenant tables: users, incidents, events, assets, audit_log
└── seed.sql                   # Idempotent baseline test data and linked CVEs
src/
├── app/
│   ├── api/
│   │   ├── chat/route.ts      # Auth -> Fast-path regex -> Ollama routing -> runTool() -> SSE stream
│   │   └── health/route.ts    # Database & Ollama health check
│   └── layout.tsx             # Mounts floating <ChatWidget />
├── components/
│   └── ai-chat/ChatWidget.tsx # Chat interface, SSE stream reader, suggestions
├── lib/
│   ├── ai/ollama.ts           # Ollama client configured for qwen3:4b-instruct-2507-q4_K_M
│   ├── auth/session.ts        # Resolves user, tenant, and role from X-ShieldDesk-User header
│   ├── db/                    # PostgreSQL connection pool
│   ├── permissions.ts         # canAccess(role, permission) RBAC logic
│   └── tools/shieldDeskChatTools.ts  # The 4 SOC tools with live DB + Python engine queries
setup_database.ps1             # Automated PostgreSQL start & setup script
WORKING_README.md              # Detailed combined architecture and operations guide
SHIELDDESK_PROJECT_GUIDE.md    # Comprehensive technical guide and examples
```

---

## Next Roadmap Deliverables

1. **Frontend Dev Role Switcher**: Add a dropdown in the chat widget header allowing live switching between `dev-analyst`, `dev-admin`, and `dev-other` to demonstrate RBAC live in the browser.
2. **Visual Badges & Markdown**: Render colored severity badges (`CRITICAL`, `HIGH`, `RESOLVED`) and structured incident cards.
3. **Phase 6 Context-Aware Chat**: Pass active page context (`currentIncidentId`) so analysts can ask *"Investigate this"* without retyping the incident ID.
4. **Docker Compose**: Single-command containerized deployment (`docker compose up -d`).
