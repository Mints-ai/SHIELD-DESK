# ShieldDesk PostgreSQL Setup & Configuration Guide

This guide walks you through setting up, configuring, and verifying the PostgreSQL database for the ShieldDesk AI Chat application.

---

## 1. Quick Overview

The chat widget and backend service layer rely on PostgreSQL for:
- **Role-Based Access Control (RBAC) & Tenant Isolation**: Scoping queries to caller's tenant (`acme-tenant`, `globex-tenant`).
- **Incident Intelligence**: Tracking incidents (`incidents`, `incident_events`), impacted assets (`assets`, `incident_assets`), and CVE associations (`incident_cves`).
- **Audit Logging**: Persisting all user queries, tool invocations, and answers in `chat_audit_log`.

---

## 2. PostgreSQL Installation Options (Windows)

Choose either **Option A (Docker)** or **Option B (Native Windows Installer)**:

### Option A: Using Docker (Recommended & Fastest)

If Docker Desktop is installed, run a PostgreSQL container with one command:

```powershell
docker run --name shielddesk-postgres `
  -e POSTGRES_USER=shielddesk `
  -e POSTGRES_PASSWORD=shielddesk_dev `
  -e POSTGRES_DB=shielddesk `
  -p 5432:5432 `
  -d postgres:16-alpine
```

To stop or start the container later:
```powershell
docker stop shielddesk-postgres
docker start shielddesk-postgres
```

---

### Option B: Native Windows Installer

1. **Download PostgreSQL**:
   - Download the official Windows installer from [EnterpriseDB PostgreSQL Downloads](https://www.enterprisedb.com/downloads/postgres-postgresql-downloads) (PostgreSQL 15 or 16).
2. **Install**:
   - Run the installer.
   - Set the `postgres` superuser password (e.g. `postgres` or `shielddesk_dev`).
   - Default port: `5432`.
3. **Create User & Database**:
   Open **SQL Shell (psql)** or **pgAdmin** and run:
   ```sql
   CREATE USER shielddesk WITH PASSWORD 'shielddesk_dev';
   CREATE DATABASE shielddesk OWNER shielddesk;
   GRANT ALL PRIVILEGES ON DATABASE shielddesk TO shielddesk;
   ```

---

## 3. Environment Variable Configuration

Create or update `.env.local` inside `web/`:

```bash
# Path: web/.env.local

# --- Database (PostgreSQL) ---
DATABASE_URL=postgresql://shielddesk:shielddesk_dev@localhost:5432/shielddesk

# --- Local Ollama ---
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_MODEL=qwen3:4b-instruct-2507-q4_K_M

# --- Python AI Engine (Phase 5) ---
PYTHON_AI_SERVICE_URL=http://localhost:8000
```

> **Note**: If using default superuser credentials instead, set:  
> `DATABASE_URL=postgresql://postgres:<your_password>@localhost:5432/shielddesk`

---

## 4. Initializing Schema & Seed Data

Navigate to the `web/` directory and run the schema and seed scripts:

### Using `psql`:

```powershell
# 1. Apply Schema (tables, indexes, extensions)
psql -U shielddesk -d shielddesk -h localhost -p 5432 -f db/schema.sql

# 2. Apply Seed Data (sample incidents, dev users, assets, and CVE links)
psql -U shielddesk -d shielddesk -h localhost -p 5432 -f db/seed.sql
```

### Alternatively, using Docker `exec`:

```powershell
docker cp db/schema.sql shielddesk-postgres:/schema.sql
docker cp db/seed.sql shielddesk-postgres:/seed.sql
docker exec -it shielddesk-postgres psql -U shielddesk -d shielddesk -f /schema.sql
docker exec -it shielddesk-postgres psql -U shielddesk -d shielddesk -f /seed.sql
```

---

## 5. Verifying Database Setup

### Step 1: Check Next.js Health Check Endpoint
Start the web app:
```powershell
npm run dev
```

Visit **`http://localhost:3000/api/health`** in your browser or run:
```powershell
Invoke-RestMethod -Uri "http://localhost:3000/api/health"
```

**Expected JSON Response:**
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

### Step 2: Test from the Chatbot UI
1. Open `http://localhost:3000`.
2. Open the ShieldDesk chat widget (bottom right).
3. Test query: `"Show me today's critical incidents"`.
4. The system will query the real `incidents` table and Ollama will stream the response.

---

## 6. Seeded Test Records

The seed script loads the following baseline data:

### Dev Users (`users` table)
| User ID | Tenant | Role | Permissions |
|---|---|---|---|
| `dev-analyst` | `acme-tenant` | `user` | Standard analyst; scoped to `acme-tenant` |
| `dev-admin` | `acme-tenant` | `system_admin` | Full admin; has `VIEW_CROSS_TENANT` |
| `dev-other` | `globex-tenant` | `user` | Different tenant (for isolation tests) |

### Sample Incidents (`incidents` table)
- **`INC-1042`** (Critical): Lateral movement on `FIN-WS-042` toward `FIN-DB-01`. Linked to `CVE-2024-3400`.
- **`INC-1039`** (High): Multiple failed admin login attempts from external IP.
- **`INC-1031`** (Medium, Resolved): Outbound traffic to suspicious newly-registered domain.

---

## 7. Database Reset / Maintenance Commands

To reset the database cleanly at any time:

```sql
DROP DATABASE IF EXISTS shielddesk;
CREATE DATABASE shielddesk OWNER shielddesk;
```
Then re-apply `db/schema.sql` and `db/seed.sql`.
