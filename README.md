# ShieldDesk™ — Autonomous SOC Control Plane & AI Co-Pilot

[![Next.js](https://img.shields.io/badge/Next.js-16.3.5-black?style=flat&logo=next.js)](https://nextjs.org/)
[![React](https://img.shields.io/badge/React-19.2.8-blue?style=flat&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue?style=flat&logo=typescript)](https://www.typescriptlang.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-blue?style=flat&logo=postgresql)](https://www.postgresql.org/)
[![Sentry](https://img.shields.io/badge/Sentry-Enabled-362D59?style=flat&logo=sentry)](https://sentry.io/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-v4-38B2AC?style=flat&logo=tailwind-css)](https://tailwindcss.com/)
[![Tests](https://img.shields.io/badge/Tests-80%2F80_Passing-brightgreen?style=flat)]()
[![License](https://img.shields.io/badge/License-Proprietary-red?style=flat)]()

**ShieldDesk™** is an enterprise-grade, AI-assisted Security Operations Center (SOC) control plane designed to ingest and normalize security alerts, investigate incidents, simulate attack blast radius, formulate 3-horizon remediation plans, enforce dual-admin human governance, and dispatch cryptographically signed containment commands to an endpoint agent fleet.

---

## 1. What ShieldDesk Actually Does

Security Operations teams are overwhelmed by thousands of fragmented alerts across cloud hosts, firewalls, and endpoints. ShieldDesk unifies this workflow into a single, cohesive, production-hardened control plane:

1. **Alert Normalization & Secret Scrubbing**: Ingests high-throughput telemetry from CrowdStrike, Microsoft Defender, Wazuh, and custom webhooks. All payloads pass through a centralized regex engine (`src/lib/security/redactor.ts`) to scrub credentials, private keys, and PII before database storage.
2. **AI & Blast Radius Investigation**: Uses a local or private LLM co-pilot paired with a Python Vulnerability ML Engine to correlate CVEs, calculate EPSS exploitation probability, compute downstream asset dependencies, and simulate security posture degradation (`simulateBlastRadius`).
3. **3-Horizon Remediation Planning**: Generates actionable, versioned, database-persisted response plans (`mitigation_plans` and `mitigation_tasks`):
   - **Horizon 1 (Immediate)**: Isolate compromised hosts, flush ARP tables, revoke active session tokens.
   - **Horizon 2 (Short-Term)**: Apply verified vendor security patches, quarantine infected files.
   - **Horizon 3 (Long-Term)**: Deploy zero-trust microsegmentation and hardening firewall rules.
4. **4-Tier Human Governance**: Enforces Separation of Duties. Non-destructive actions run autonomously, while host isolation and destructive remediation require single or dual cryptographic SuperAdmin approvals (`check_separation_of_duties` at the DB level).
5. **Signed Fleet Dispatch**: Authorized containment commands are cryptographically signed with RSA-2048 keys (`RSA-SHA256`), verified against an emergency admin kill-switch and a Tier 1 blast-radius throttle (max 5 hosts / 5 min), and queued for remote endpoint daemons with a tamper-proof hash-chain audit ledger.

---

## 2. End-to-End Architecture & Data Flow

```mermaid
flowchart TD
    subgraph Ingestion ["1. Alert Ingestion & Normalization"]
        A[CrowdStrike / Defender / Wazuh / Webhook] -->|HMAC-SHA256 Signed POST| B["/api/ingest/webhooks"]
        B --> C[Validate API Key & Tenant ID]
        C --> D[PII / Secret Scrubbing: redactor.ts]
        D --> E[(PostgreSQL: Incidents & Events)]
    end
    subgraph Investigation ["2. AI & Blast Radius Investigation"]
        E --> F[SOC Console: /dashboard]
        F --> G["AI Copilot: /api/chat"]
        G --> H["Deterministic Tool Router (RBAC Scoped)"]
        H --> I["Python Vulnerability ML Engine (Port 8000)"]
        H --> J["Blast Radius Engine (CVSS / Attack Graph)"]
        J --> K["3-Horizon Mitigation Plan Generated"]
    end
    subgraph Governance ["3. Human-in-the-Loop Governance"]
        K --> L{Autonomy Tier Classification}
        L -->|Tier 0: Read-Only| M[Autonomous Visualization]
        L -->|Tier 1: Low-Risk| N[Pre-flight Snapshot + Automated Execution]
        L -->|Tier 2: Host Isolation / Patch| O[Human Sign-Off Token Required]
        L -->|Tier 3: Destructive / Break-Glass| P[Dual Named SuperAdmin Approval]
        O --> Q[(PostgreSQL: approval_tokens & Audit Ledger)]
        P --> Q
    end
    subgraph Execution ["4. Signed Fleet Dispatch"]
        Q -->|Approved Token| R["Fleet Controller: /api/fleet/[id]/command"]
        R --> S[Check Emergency Admin Kill Switch]
        S --> T[Check Tier 1 Blast-Radius Throttle: 5/5min]
        T --> U[RSA-SHA256 Cryptographic Signature Generated]
        U --> V[(agent_commands Queue & hash_chain_audit)]
        V --> W[Remote Host Agent Daemon]
        W --> X[Pre-flight LVM Snapshot -> Execute Action -> Report Signed Result]
    end
```

---

## 3. Autonomy Tiers & Governance Framework

Every remediation task in ShieldDesk is classified under a strict autonomy hierarchy (`src/lib/governance/autonomyTier.ts`) to eliminate the risk of accidental outages or rogue automated actions:

| Tier | Classification | Risk Level | Execution Policy | Approvers Required | Example Actions |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Tier 0** | Observation Only | None | Autonomous read & visualize | 0 (Autonomous) | Attack surface mapping, CVSS scoring, blast radius simulation |
| **Tier 1** | Low-Risk / Reversible | Low | Pre-flight snapshot + rate-throttled dispatch | 0 (Autonomous with 5/5min throttle) | Revoke user sessions, block outbound domain, blacklist IP on gateway |
| **Tier 2** | Medium-Risk / Human-Approved | Medium / High | **Human Sign-Off Required** (Separation of Duties enforced) | 1 (`responder` or `super_admin`) | Quarantine endpoint NIC, isolate database host, deploy OS patch |
| **Tier 3** | High-Risk / Break-Glass | Critical | **Dual Named SuperAdmin Sign-Off** (Break-Glass Protocol) | 2 distinct `super_admin` or `system_admin` | Fleet-wide credential rotation, kernel patch reboot, firewall wipe |

### Separation of Duties Constraint
Separation of duties is enforced at **both the application and database schema levels** (`db/schema.sql`):
```sql
CONSTRAINT check_separation_of_duties
  CHECK (approved_by IS NULL OR requested_by <> approved_by),
CONSTRAINT check_tier3_dual_approval_separation
  CHECK (secondary_approved_by IS NULL OR approved_by <> secondary_approved_by)
```
An analyst or admin who requests a remediation token cannot approve their own token. For Tier 3 actions, the secondary approver must be distinct from the primary approver.

---

## 4. Multi-Tenant RBAC & Security Isolation

ShieldDesk is built from the ground up for multi-tenancy. Every database query, fleet command, and AI context prompt is strictly bound to the authenticated caller's tenant:

### 6 Unified Roles (`src/lib/permissions.ts`)
- **`system_admin`**: Global platform administrator with cross-tenant visibility (`VIEW_CROSS_TENANT`), user management, and emergency fleet kill-switch rights.
- **`super_admin`**: Tenant organization administrator with Tier 3 dual-approval authority (`approve.tier3`).
- **`responder`**: Incident response engineer; signs off on Tier 2 approvals (`approve.tier2`) and dispatches containment commands.
- **`analyst`**: Security operations analyst; drafts mitigation tasks, investigates incidents, executes simulations, and approves Tier 1 low-risk auto-containment (`approve.tier1`).
- **`viewer`**: Read-only stakeholder; cannot approve tokens, cannot draft tasks (rejected with `403 Forbidden`), and cannot execute state-changing actions.
- **`user`**: Standard tenant operator with basic incident and CVE read/investigation permissions.

### Anti-Enumeration Defense
Probing resources (incidents, plans, agent telemetry) belonging to another tenant returns `404 Not Found` rather than `403 Forbidden`, denying attackers confirmation of resource existence across tenant boundaries.

### Unified Authentication Architecture
- **HMAC-SHA256 Session Tokens**: `src/lib/auth/token.ts` generates tamper-resistant, signed session cookies with constant-time cryptographic verification (`crypto.timingSafeEqual`).
- **Scrypt Password Hashing**: `src/lib/auth/password.ts` protects local credentials using Node.js `crypto.scrypt` with random 16-byte salts.
- **RFC 6238 TOTP Multi-Factor Authentication**: Native MFA enrollment and verification (`/api/auth/mfa/enroll`, `/api/auth/mfa/verify`) with replay protection (`last_totp_at`).
- **Supabase SSR Bridge**: Integrated alongside local authentication via `@supabase/ssr` (`src/lib/auth/session.ts`).
- **Retired Legacy Services**: The legacy standalone `services/iam/` microservice has been deprecated in favor of this native App Router authentication layer.

---

## 5. Cryptographic Fleet Dispatch & Tamper-Proof Audit Vault

### Command Signing (`src/lib/fleet/commandSigning.ts`)
All fleet actions dispatched to remote endpoint daemons are cryptographically signed using RSA-2048 keys (`RSA-SHA256`).
To avoid whitespace or serialization drift across runtimes (Node.js and Go), payloads are formatted into a canonical payload string:
```text
${agentId}|${command}|${nonce}|${tier}
```
The signature is verified by the remote host agent before any script, patch, or isolation command executes.

### Blast Radius Throttle (`src/lib/governance/blastRadiusThrottle.ts`)
To prevent cascading network disruption from runaway automation, Tier 1 commands are limited to a sliding window of **maximum 5 commands per 5 minutes per tenant**. If the threshold is exceeded, commands are rejected until the window resets.

### Emergency Fleet Kill Switch (`/api/fleet/kill-switch`)
Platform administrators can trigger an emergency kill switch that instantly revokes all pending commands across a tenant's fleet and marks agents as frozen.

### Cryptographic Hash-Chain Audit Ledger (`hash_chain_audit`)
Every command execution, approval decision, and containment event is recorded in a cryptographically chained audit vault (`db/schema.sql`):
```text
current_hash = SHA-256(prev_hash + tenant_id + event_type + actor_id + payload_json + created_at)
```
Any tampering or record deletion invalidates the chain, providing mathematically provable non-repudiation for SOC 2 and ISO 27001 compliance auditors.

---

## 6. Enterprise Error Tracking & Observability

ShieldDesk integrates `@sentry/nextjs` directly into its central observability pipeline:

- **Universal Instrumentation**: Configured across Client (`sentry.client.config.ts`), Server (`sentry.server.config.ts`), and Edge (`sentry.edge.config.ts`).
- **Context-Enriched Exception Logging**: The centralized tracker (`src/lib/observability/errorTracker.ts`) captures uncaught runtime exceptions and attaches:
  - Unique Incident `errorId` (e.g., `err_mumlf2zi_h184x`)
  - Authenticated `tenantId` & `userId`
  - Target `endpoint` and UI `component`
  - Stack trace & structured environment payload
- **API Guardrails**: Unhandled 500 exceptions in `/api/incidents`, `/api/chat`, `/api/scans`, and `/api/tasks` automatically dispatch to Sentry while returning clean, non-leaking JSON error payloads to users.
- **Activation**: Simply add your `SENTRY_DSN` to `.env.local` to stream events immediately.

---

## 7. Safety Boundaries: Demo Mode vs. Fail-Closed Policy

ShieldDesk implements explicit runtime safety boundaries (`src/lib/config/environment.ts`) to prevent demo simulations from ever executing in production:

- **`DEMO_MODE=true` (Development & Evaluation)**: Enables illustrative mock datasets, offline engine fallbacks, and dev persona switching (`dev-analyst`, `dev-admin`, `dev-other`) so teams can test all UX workflows without live agent connections.
- **`DEMO_MODE=false` & `APP_ENV=production` (Strict Production)**:
  - Dev persona header spoofing (`X-ShieldDesk-User`) is strictly blocked with `401 Unauthorized`.
  - Offline scanners (Trivy, Gitleaks, KMS) fail closed with `503 Service Unavailable`.
  - Patch applications and agent commands without live daemon handshakes fail closed with `503`.
  - Anomaly burst simulations are completely rejected.

---

## 8. System Port Map & Microservices

| Service | Port | Technology | Purpose & Source Location |
| :--- | :--- | :--- | :--- |
| **ShieldDesk Web Console** | `3000` | Next.js 16 / React 19 / Tailwind v4 | SOC console, Kanban task board, fleet controller, compliance, AI chat (`src/app/`) |
| **Python Vulnerability AI Brain** | `8000` | Python 3.10+ / Scikit-Learn Random Forest | Multi-target CVE/EPSS risk scoring, KEV catalog matching (`ai-chat-desk/server.py`) |
| **PostgreSQL Database** | `5432` | PostgreSQL 16+ (Alpine) | Multi-tenant schema, incidents, mitigation tasks, approval tokens, audit log (`db/schema.sql`) |
| **Local LLM Co-Pilot** | `11434` | Ollama (`qwen3:4b`) | Local conversational intent router & synthesis with zero data egress |
| **Distributed Cache & Throttle** | `6379` | Redis 7+ (Alpine) | Command throttle rate limiter (5 hosts / 5 min) and session caching |
| **Python Scan Microservice** | Internal / `8000` | Python FastAPI / Trivy / Gitleaks | Automated CVE scanning, secret detection, and patch orchestration (`services/scan/`) |
| **Go Threat Engine** | Worker | Go 1.21+ / NATS JetStream | High-speed telemetry consumer with YARA, Sigma, and anomaly detection (`services/threat/`) |
| **Go Ingestion Service** | `8080` | Go 1.21+ / gRPC / mTLS | High-throughput alert intake and webhook signature validation (`services/ingest/`) |
| **Python AI Advisor** | Internal | Python FastAPI / Claude / RAG | Specialized AI advisor microservice with vector store retrieval (`services/ai-advisor/`) |

---

## 9. Comprehensive API Route Catalog

All routes reside under `src/app/api/` and enforce strict session authentication and tenant isolation:

| Method | Endpoint | Authorization | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/chat` | Any authenticated role | AI Copilot conversational stream (SSE) with deterministic tool execution |
| `GET` | `/api/incidents` | `incident.read` | Lists tenant incidents with severity, status, and timeline |
| `GET` | `/api/incidents/[id]` | `incident.read` | Returns incident details, associated assets, and linked CVEs (404 on cross-tenant) |
| `GET` | `/api/tasks` | Any authenticated role | Returns tenant mitigation tasks grouped by horizon (`immediate`, `short_term`, `long_term`) |
| `POST` | `/api/tasks` | `analyst`, `responder`, `super_admin` | Drafts a new mitigation task (`viewer` rejected with `403 Forbidden`) |
| `GET` | `/api/plans` | Any authenticated role | Returns tenant 3-horizon mitigation plans |
| `POST` | `/api/approvals` | `approve.tier1/2/3` | Evaluates, approves, or rejects pending human approval tokens |
| `GET` | `/api/fleet` | Authenticated tenant user | Lists registered endpoint agents, telemetry (CPU/MEM/EPS), and status |
| `POST` | `/api/fleet/[id]/command` | `responder`, `super_admin` | Queues an RSA-2048 signed command to an agent after throttle & token check |
| `POST` | `/api/fleet/kill-switch` | `super_admin`, `system_admin` | Emergency tenant fleet kill switch; immediately freezes agent command queues |
| `GET` | `/api/scans` | Authenticated tenant user | Returns CVE and secret scan posture (fails closed with `503` in production) |
| `POST` | `/api/threats` | Authenticated tenant user | Telemetry bus for YARA/Sigma rules and anomaly monitoring |
| `POST` | `/api/ingest/webhooks` | HMAC / API Key | Validates signature, scrubs PII/secrets, and normalizes alerts into incidents |
| `GET` | `/api/compliance` | Authenticated tenant user | Generates SOC 2, ISO 27001, and NIST CSF compliance posture reports |
| `GET` | `/api/reports/scorecard` | Authenticated tenant user | Aggregates executive security risk scorecards |
| `POST` | `/api/auth/login` | Public | Authenticates credentials, hashes via `scrypt`, and sets HMAC session cookie |
| `POST` | `/api/auth/mfa/enroll` | Authenticated user | Generates TOTP secret and QR code for two-factor authentication |
| `POST` | `/api/auth/mfa/verify` | Authenticated user | Verifies 6-digit TOTP code and activates two-factor protection |

---

## 10. Database Schema Overview

The database (`db/schema.sql`) contains 15 core tables equipped with foreign key cascades, tenant indexes, and Row-Level Security (RLS) policies:

1. **`users`**: Tenant-bound user accounts, roles (`system_admin`, `super_admin`, `user`), scrypt password hashes, and TOTP MFA secrets.
2. **`incidents`**: Security incidents with severity (`critical`, `high`, `medium`, `low`) and status (`open`, `investigating`, `resolved`, `closed`).
3. **`incident_events`**: Chronological event timeline associated with an incident.
4. **`assets`**: Protected tenant infrastructure assets (hostnames, asset types).
5. **`incident_assets`**: Many-to-many junction linking incidents to affected assets.
6. **`incident_cves`**: Many-to-many junction linking incidents to specific CVE vulnerabilities.
7. **`mitigation_plans`**: Versioned 3-horizon remediation plans linked to incidents.
8. **`mitigation_tasks`**: Granular tasks categorized by horizon (`immediate`, `short_term`, `long_term`), autonomy tier, and status.
9. **`approval_tokens`**: Human-in-the-loop authorization tokens with DB-level Separation of Duties checks.
10. **`approval_audit_log`**: Detailed audit trail of approval requests, sign-offs, and rejections.
11. **`endpoint_agents`**: Enrolled agent daemons with OS type (`linux`, `windows`, `darwin`), version, heartbeat, and safety snapshot IDs.
12. **`agent_commands`**: RSA-signed command dispatch queue with delivery status (`queued`, `delivered`, `executed`, `failed`, `rolled_back`).
13. **`agent_command_logs`**: Execution output and historical logs for fleet commands.
14. **`hash_chain_audit`**: Cryptographically chained tamper-evident audit ledger (`prev_hash` + `current_hash`).
15. **`chat_audit_log`**: Comprehensive compliance record of AI copilot queries, tool executions, and responses.

---

## 11. Quick Start Guide

### Prerequisites
- **Node.js**: v20.x or v22.x
- **npm**: v10+
- **Python**: 3.10+
- **PostgreSQL**: 16+ (or use Docker Compose)
- **Optional**: [Ollama](https://ollama.com) with model `qwen3:4b`

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/Mints-ai/SHIELD-DESK.git
cd shielddesk
npm install
```

### 2. Configure Environment
```bash
cp .env.example .env.local
```
Edit `.env.local` with your configuration:
```env
# Database Connection
DATABASE_URL=postgresql://shielddesk:shielddesk@localhost:5432/shielddesk

# Application Environment & Safety Boundary
APP_ENV=development
DEMO_MODE=true

# Observability
SENTRY_DSN=https://your-key@o0.ingest.sentry.io/0

# Services
PYTHON_AI_SERVICE_URL=http://localhost:8000
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_MODEL=qwen3:4b
```

### 3. Launch Services

#### Option A: One-Command Dev Launcher (Recommended on Windows)
Launches Next.js UI, Python AI Brain, and Ollama together in one managed terminal session:
```powershell
.\start.ps1
```
*(Or run `npm run start:all`)*.

#### Option B: Docker Compose
Boot the complete infrastructure container stack:
```bash
docker compose up --build
```

#### Option C: Manual Startup
Open separate terminal tabs:
- **Terminal 1 (Next.js SOC Console)**:
  ```bash
  npm run dev
  ```
- **Terminal 2 (Python Vulnerability AI Brain)**:
  ```bash
  cd ai-chat-desk
  python server.py
  ```
- **Terminal 3 (Local LLM Co-Pilot)**:
  ```bash
  ollama serve
  ```

Visit **http://localhost:3000** to access the SOC console.

---

## 12. Automated Testing & Verification

ShieldDesk maintains a rigorous automated test suite with **80 passing unit and integration tests across 10 test suites**:

```bash
npm test
```

### Test Suite Coverage:
1. `tests/security-auth-hardening.test.ts`: Cryptographic HMAC session tokens, scrypt password hashing, timing-safe equality, and protected route 401 enforcement.
2. `tests/rbac.test.ts`: Multi-tenant isolation, anti-enumeration (404), cross-tenant view permissions, and tool execution least-privilege.
3. `tests/safety-boundary.test.ts`: Strict fail-closed policy validation (`503` offline errors, rejection of persona header spoofing in production).
4. `tests/agent-remediation-api.test.ts`: Remote agent command queueing, pre-flight snapshot requirements, and output reporting.
5. `tests/approval-tokens.test.ts`: Tier 2 single approval, Tier 3 dual named SuperAdmin approval, and Separation of Duties constraint enforcement.
6. `tests/compliance.test.ts`: Automated SOC 2, ISO 27001, and NIST CSF audit report generation.
7. `tests/fleet.test.ts`: Agent heartbeat tracking, RSA-2048 command signing verification, and emergency kill-switch activation.
8. `tests/ingest.test.ts`: Alert ingest HMAC signature validation and cross-tenant ingest spoofing defense.
9. `tests/security-injection.test.ts`: Adversarial prompt injection defense, SQL injection protection, and regex secret redactor verification.
10. `tests/tasks-and-observability.test.ts`: Task board database persistence, viewer role gating (`403 Forbidden`), and Sentry `trackError` instrumentation.

TypeScript static analysis validation:
```bash
npx tsc --noEmit
```

---

## 13. Repository Directory Structure

```text
shielddesk/
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   ├── auth/              # HMAC sessions, scrypt login, and TOTP MFA
│   │   │   ├── chat/              # AI copilot SSE stream & deterministic tool router
│   │   │   ├── incidents/         # Tenant-scoped incident investigation API
│   │   │   ├── tasks/             # PostgreSQL-backed SOC mitigation tasks API (GET, POST)
│   │   │   ├── plans/             # 3-horizon remediation plans index API
│   │   │   ├── approvals/         # Tier 2/3 human authorization & separation of duties
│   │   │   ├── fleet/             # Remote host telemetry, signed dispatch, & kill-switch
│   │   │   ├── scans/             # CVE & secret scanner integration (fail-closed)
│   │   │   ├── threats/           # YARA/Sigma rules & telemetry bus
│   │   │   ├── ingest/            # Authenticated alert webhook ingest
│   │   │   ├── compliance/        # Compliance posture reporting (SOC2, ISO27001)
│   │   │   └── reports/           # Executive risk scorecards
│   │   ├── dashboard/             # SOC operational interfaces
│   │   │   ├── tasks/             # Kanban board with tier-gated approvals
│   │   │   ├── plans/             # Remediation plan inspection & horizon breakdowns
│   │   │   ├── fleet/             # Endpoint agent fleet manager
│   │   │   ├── scanner/           # Vulnerability & secret leak posture
│   │   │   ├── threats/           # Threat detection & rule configuration
│   │   │   ├── compliance/        # Regulatory framework scorecards
│   │   │   └── risk-scorecard/    # Executive risk metrics
│   │   └── page.tsx               # Root SOC overview console
│   ├── components/                # React UI components (AI chat, governance, navigation)
│   └── lib/
│       ├── auth/                  # HMAC session tokens, scrypt passwords, Supabase SSR
│       ├── permissions.ts         # 6-tier RBAC matrix & tool execution gates
│       ├── governance/            # Approval tokens, blast radius throttle, autonomy tiers
│       ├── fleet/                 # RSA-2048 command signing & fleet management logic
│       ├── security/              # Centralized PII and secret redactor engine
│       ├── observability/         # Central errorTracker with Sentry integration
│       ├── config/environment.ts  # Safety boundaries (DEMO_MODE vs FAIL_CLOSED)
│       └── db/                    # PostgreSQL connection pool with lazy initialization
├── ai-chat-desk/                  # Python HTTP service & Random Forest ML model for CVE/EPSS
├── services/
│   ├── threat/                    # High-speed Go threat & anomaly worker with NATS
│   ├── scan/                      # FastAPI service for Trivy, Gitleaks, & patch orchestration
│   ├── ingest/                    # Go telemetry intake engine with gRPC and mTLS
│   ├── webhooks/                  # Go signed webhook dispatcher
│   ├── ai-advisor/                # FastAPI advisor with Claude & RAG vector store
│   └── iam/                       # [DEPRECATED] Retired in favor of native App Router auth
├── db/
│   ├── schema.sql                 # Complete DDL: 15 tables, constraints, RLS policies
│   └── seed.sql                   # Realistic multi-tenant incident and agent fixtures
├── tests/                         # Node.js native test harness (80 automated tests)
├── sentry.client.config.ts        # Client Sentry error and performance monitoring
├── sentry.server.config.ts        # Server Sentry error tracking
├── sentry.edge.config.ts          # Edge Sentry error tracking
├── docker-compose.yml             # Local multi-container development environment
└── start.ps1                      # Windows / PowerShell one-command full stack launcher
```

---

## 14. Useful Reference Documentation

- [WORKING_README.md](WORKING_README.md) — Detailed operational run guide, architecture diagrams, and state machines.
- [SHIELDDESK_PROJECT_GUIDE.md](SHIELDDESK_PROJECT_GUIDE.md) — AI Copilot intent routing, tool pipeline, and ML engine details.
- [BLAST_RADIUS_README.md](BLAST_RADIUS_README.md) — Attack graph algorithms, CVSS posture degradation, and blast radius models.
- [CHECKLIST.md](CHECKLIST.md) — Production readiness audit and feature delivery checklist.

---

## 15. Security & Responsible Disclosure

ShieldDesk is built for enterprise security environments. If you discover a vulnerability or security flaw, please do not file a public GitHub issue. Instead, report it directly to the security team at **security@mints.ai**.

---

## 16. License

Copyright © 2026 Mints Global IT & Advertisement. All rights reserved.  
Proprietary enterprise software. Unauthorized copying, modification, or distribution is strictly prohibited.
