# ShieldDesk™ — Autonomous SOC Control Plane & AI Co-Pilot

[![Next.js](https://img.shields.io/badge/Next.js-16.3.5-black?style=flat&logo=next.js)](https://nextjs.org/)
[![React](https://img.shields.io/badge/React-19.2.8-blue?style=flat&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue?style=flat&logo=typescript)](https://www.typescriptlang.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-blue?style=flat&logo=postgresql)](https://www.postgresql.org/)
[![Sentry](https://img.shields.io/badge/Sentry-Enabled-362D59?style=flat&logo=sentry)](https://sentry.io/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-v4-38B2AC?style=flat&logo=tailwind-css)](https://tailwindcss.com/)
[![Tests](https://img.shields.io/badge/Tests-80%2F80_Passing-brightgreen?style=flat)]()
[![License](https://img.shields.io/badge/License-Proprietary-red?style=flat)]()

**ShieldDesk™** is an enterprise-grade, AI-assisted Security Operations Center (SOC) control plane designed to triage security alerts, investigate incidents, simulate attack blast radius, formulate 3-horizon remediation plans, enforce dual-admin human governance, and dispatch cryptographically signed containment commands to an endpoint agent fleet.

---

## 1. What ShieldDesk Actually Does

Security Operations teams are overwhelmed by thousands of fragmented alerts across cloud hosts, firewalls, and endpoints. ShieldDesk unifies this workflow into a single, cohesive control plane:

1. **Alert Normalization & Secret Scrubbing**: Ingests high-throughput telemetry from CrowdStrike, Microsoft Defender, Wazuh, and custom webhooks. All payloads pass through a centralized regex engine to scrub credentials, private keys, and PII before database storage.
2. **AI & Blast Radius Investigation**: Uses a local or private LLM co-pilot paired with a Python Vulnerability ML Engine to correlate CVEs, calculate EPSS exploitation probability, compute downstream asset dependencies, and simulate security posture degradation.
3. **3-Horizon Remediation Planning**: Generates actionable, phased response plans:
   - **Horizon 1 (Immediate)**: Isolate compromised hosts, flush ARP tables, revoke active session tokens.
   - **Horizon 2 (Short-Term)**: Apply verified vendor security patches, quarantine infected files.
   - **Horizon 3 (Long-Term)**: Deploy zero-trust microsegmentation and hardening firewall rules.
4. **4-Tier Human Governance**: Enforces Separation of Duties. Non-destructive actions run autonomously, while host isolation and destructive remediation require single or dual cryptographic SuperAdmin approvals.
5. **Signed Fleet Dispatch**: Authorized containment commands are cryptographically signed with RSA-2048 keys, verified against an emergency kill-switch and blast-radius throttle (max 5 hosts / 5 min), and queued for remote endpoint daemons.

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
        U --> V[(agent_commands Queue)]
        V --> W[Remote Host Agent Daemon]
        W --> X[Pre-flight LVM Snapshot -> Execute Action -> Report Signed Result]
    end
```

---

## 3. Autonomy Tiers & Governance Framework

Every remediation task in ShieldDesk is classified under a strict autonomy hierarchy to eliminate the risk of accidental outages or rogue automated actions:

| Tier | Classification | Risk Level | Execution Policy | Example Actions |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 0** | Autonomous / Read-Only | None | Autonomous execution | Attack surface mapping, CVSS scoring, blast radius simulation |
| **Tier 1** | Low-Risk Autonomous | Low | Automated pre-flight snapshot + rate-throttled dispatch | Revoke user sessions, block outbound domain, blacklist IP on gateway |
| **Tier 2** | Gated Intervention | Medium / High | **Human Sign-Off Required** (Separation of Duties enforced) | Quarantine endpoint NIC, isolate database host, deploy OS patch |
| **Tier 3** | High-Impact / Destructive | Critical | **Dual Named SuperAdmin Sign-Off** (Break-Glass Protocol) | Fleet-wide credential rotation, kernel patch reboot, firewall wipe |

---

## 4. Multi-Tenant RBAC & Security Isolation

ShieldDesk is built for enterprise multi-tenancy. Every database query, fleet command, and AI context prompt is strictly bound to the authenticated caller's tenant:

- **6 Unified Roles**:
  - `system_admin`: Global platform administrator with cross-tenant visibility (`VIEW_CROSS_TENANT`) and emergency kill-switch rights.
  - `super_admin`: Tenant organization administrator with Tier 3 dual-approval authority.
  - `analyst`: Security operations analyst; drafts mitigation tasks, investigates incidents, executes simulations.
  - `responder`: Incident response engineer; signs off on Tier 2 approvals and dispatches agent commands.
  - `viewer`: Read-only stakeholder; cannot approve tokens, draft tasks (rejected with `403 Forbidden`), or execute actions.
  - `user`: Standard tenant operator.
- **Anti-Enumeration Protection**: Probing resources (incidents, plans, agent telemetry) belonging to another tenant returns `404 Not Found` rather than `403 Forbidden` to prevent asset enumeration.
- **Unified Authentication Architecture**:
  - Session tokens signed with HMAC-SHA256 (`src/lib/auth/token.ts`).
  - Passwords hashed with modern `crypto.scrypt` and timing-safe equality checks (`src/lib/auth/password.ts`).
  - Native RFC 6238 TOTP two-factor authentication challenge (`/api/auth/mfa/verify`).
  - The legacy standalone `services/iam/` microservice has been retired and consolidated into this native App Router layer.

---

## 5. Enterprise Error Tracking & Observability

ShieldDesk integrates `@sentry/nextjs` directly into its central observability pipeline:

- **Universal Instrumentation**: Configured across Client (`sentry.client.config.ts`), Server (`sentry.server.config.ts`), and Edge (`sentry.edge.config.ts`).
- **Context-Enriched Exception Logging**: The centralized tracker (`src/lib/observability/errorTracker.ts`) captures uncaught runtime exceptions and attaches:
  - Unique Incident `errorId` (e.g., `err_mumkw8po_redv6`)
  - Authenticated `tenantId` & `userId`
  - Target `endpoint` and UI `component`
  - Stack trace & structured environment payload
- **API Guardrails**: Unhandled 500 exceptions in `/api/incidents`, `/api/chat`, `/api/scans`, and `/api/tasks` automatically dispatch to Sentry while returning clean, non-leaking JSON error payloads to users.
- **Activation**: Simply add your `SENTRY_DSN` to `.env.local` to stream events immediately.

---

## 6. Safety Boundaries: Demo Mode vs. Fail-Closed Policy

ShieldDesk implements explicit runtime safety boundaries (`src/lib/config/environment.ts`) to prevent demo simulations from ever executing in production:

- **`DEMO_MODE=true` (Development & Evaluation)**: Enables illustrative mock datasets, offline engine fallbacks, and dev persona switching (`dev-analyst`, `dev-admin`, `dev-other`) so teams can test all UX workflows without live agent connections.
- **`DEMO_MODE=false` & `APP_ENV=production` (Strict Production)**:
  - Dev persona header spoofing (`X-ShieldDesk-User`) is strictly blocked with `401 Unauthorized`.
  - Offline scanners (Trivy, Gitleaks, KMS) fail closed with `503 Service Unavailable`.
  - Patch applications and agent commands without live daemon handshakes fail closed with `503`.
  - Anomaly burst simulations are completely rejected.

---

## 7. System Port Map & Services

| Service | Port | Technology | Purpose |
| :--- | :--- | :--- | :--- |
| **ShieldDesk Web Console** | `3000` | Next.js 16 / React 19 (TypeScript) | SOC console, Kanban task board, fleet controller, compliance, AI chat |
| **Python Vulnerability AI Brain** | `8000` | Python 3.10+ / FastAPI / Scikit-Learn | CVE/EPSS risk scoring, KEV catalog matching, blast radius simulation |
| **PostgreSQL Database** | `5432` | PostgreSQL 16+ (Alpine) | Multi-tenant schema, incidents, mitigation tasks, approval tokens, audit log |
| **Local LLM Co-Pilot** | `11434` | Ollama (`qwen3:4b`) | Local conversational intent router & synthesis (zero data egress) |
| **Distributed Cache & Throttle** | `6379` | Redis 7+ (Alpine) | Command throttle rate limiter (5 hosts / 5 min) and session caching |
| **Alert Webhook Ingest** | `8080` | Go 1.21+ / gRPC / HTTP | High-throughput alert ingestion and webhook signature validation |

---

## 8. Quick Start Guide

### Prerequisites
- **Node.js**: v20.x or v22.x (v21 supported)
- **npm**: v10+
- **Python**: 3.10+
- **PostgreSQL**: 15+ (or use Docker Compose)
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
Edit `.env.local` with your database credentials and optional Sentry DSN:
```env
DATABASE_URL=postgresql://shielddesk:shielddesk@localhost:5432/shielddesk
SENTRY_DSN=https://your-key@o0.ingest.sentry.io/0
```

### 3. Launch Services

#### Option A: One-Command Dev Launcher (Recommended)
Launches the Next.js UI, Python AI Brain, and Ollama together in one terminal:
```bash
npm run start:all
```
*(On Windows PowerShell, you can also run `.\start.ps1` directly).*

#### Option B: Docker Compose
Boot the complete infrastructure container stack:
```bash
docker compose up --build
```

#### Option C: Manual Startup
Open separate terminal tabs:
- **Terminal 1 (Next.js UI)**:
  ```bash
  npm run dev
  ```
- **Terminal 2 (Python AI Service)**:
  ```bash
  cd ai-chat-desk
  python server.py
  ```
- **Terminal 3 (Local LLM)**:
  ```bash
  ollama serve
  ```

Visit **http://localhost:3000** to access the SOC console.

---

## 9. Automated Testing & Verification

ShieldDesk includes a comprehensive, automated test suite covering authentication hardening, multi-tenant isolation, RBAC gating, injection defense, approval token separation of duties, and Sentry error tracking:

```bash
npm test
```

### Test Suite Summary:
```text
✔ S1: Dev persona quick-login is rejected with 401 in production
✔ S2: Cryptographic HMAC-SHA256 session token verification & anti-tampering
✔ S3: Password hashing via crypto.scrypt and timing-safe comparison
✔ S4: Protected route 401 enforcement across all fleet and compliance APIs
✔ S6: Alert ingest HMAC validation and cross-tenant spoofing rejection
✔ FR-1 to FR-4: Multi-tenant database query scoping and anti-enumeration (404)
✔ FR-5: Adversarial prompt injection and SQL injection defense
✔ Tasks & Governance: /api/tasks persistence, role gating (viewer 403), approval tokens
✔ Observability: Universal trackError error ID generation and Sentry dispatch
--------------------------------------------------------------------------------
Result: 80 tests passing across 10 suites (0 failures, duration ~3.2s)
```

Typecheck validation:
```bash
npx tsc --noEmit
```

---

## 10. Repository File Structure

```text
shielddesk/
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   ├── chat/              # AI copilot SSE stream & deterministic tool router
│   │   │   ├── incidents/         # Tenant-scoped incident investigation API
│   │   │   ├── tasks/             # PostgreSQL-backed SOC mitigation tasks API (GET, POST)
│   │   │   ├── plans/             # 3-horizon remediation plans index API
│   │   │   ├── approvals/         # Tier 2/3 human authorization & separation of duties
│   │   │   ├── fleet/             # Remote host telemetry & signed command queue
│   │   │   ├── scans/             # CVE & secret scanner integration (fail-closed)
│   │   │   ├── threats/           # YARA/Sigma rules & telemetry bus
│   │   │   └── ingest/            # Authenticated alert webhook ingest
│   │   ├── dashboard/             # SOC operational interfaces
│   │   │   ├── tasks/             # Kanban board with tier-gated approvals
│   │   │   ├── plans/             # Remediation plan inspection & horizon breakdowns
│   │   │   ├── fleet/             # Endpoint agent fleet manager
│   │   │   ├── scanner/           # Vulnerability & secret leak posture
│   │   │   └── threat-engine/     # Threat detection & rule configuration
│   │   └── page.tsx               # Root SOC overview console
│   ├── lib/
│   │   ├── auth/                  # HMAC session tokens, scrypt passwords, Supabase SSR
│   │   ├── permissions.ts         # 6-tier RBAC matrix & tool execution gates
│   │   ├── governance/            # Approval tokens, blast radius throttle, kill-switch
│   │   ├── security/              # Centralized PII and secret redactor engine
│   │   ├── observability/         # Central errorTracker with Sentry integration
│   │   ├── config/environment.ts  # Safety boundaries (DEMO_MODE vs FAIL_CLOSED)
│   │   └── db/                    # PostgreSQL connection pool with lazy initialization
├── ai-chat-desk/                  # Python FastAPI service for CVSS & EPSS scoring
├── services/
│   ├── threat/                    # High-speed Go threat & anomaly worker
│   ├── scan/                      # Trivy & Gitleaks vulnerability scanner pipeline
│   ├── ingest/                    # Go telemetry intake engine
│   └── iam/                       # [DEPRECATED] Retired in favor of native App Router auth
├── db/
│   ├── schema.sql                 # Complete DDL: incidents, tasks, plans, approval_tokens
│   └── seed.sql                   # Realistic multi-tenant incident and agent fixtures
├── tests/                         # Node.js native test harness (80 automated tests)
├── sentry.client.config.ts        # Client Sentry error and performance monitoring
├── sentry.server.config.ts        # Server Sentry error tracking
├── sentry.edge.config.ts          # Edge Sentry error tracking
├── docker-compose.yml             # Local multi-container development environment
└── start.ps1                      # Windows / PowerShell one-command full stack launcher
```

---

## 11. Useful Reference Documentation

- [WORKING_README.md](WORKING_README.md) — Detailed operational run guide, architecture diagrams, and state machines.
- [SHIELDDESK_PROJECT_GUIDE.md](SHIELDDESK_PROJECT_GUIDE.md) — AI Copilot intent routing, tool pipeline, and ML engine details.
- [BLAST_RADIUS_README.md](BLAST_RADIUS_README.md) — Attack graph algorithms, CVSS posture degradation, and blast radius models.
- [CHECKLIST.md](CHECKLIST.md) — Production readiness audit and feature delivery checklist.

---

## 12. Security & Responsible Disclosure

ShieldDesk is built for enterprise security environments. If you discover a vulnerability or security flaw, please do not file a public GitHub issue. Instead, report it directly to the security team at **security@mints.ai**.

---

## 13. License

Copyright © 2026 Mints Global IT & Advertisement. All rights reserved.  
Proprietary enterprise software. Unauthorized copying, modification, or distribution is strictly prohibited.
