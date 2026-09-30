# ShieldDesk™ — Evidence-Driven Security Operations & Remediation Platform

[![Next.js](https://img.shields.io/badge/Next.js-16.3.5-black?style=flat&logo=next.js)](https://nextjs.org/)
[![React](https://img.shields.io/badge/React-19.2.8-blue?style=flat&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue?style=flat&logo=typescript)](https://www.typescriptlang.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-blue?style=flat&logo=postgresql)](https://www.postgresql.org/)
[![Sentry](https://img.shields.io/badge/Sentry-Enabled-362D59?style=flat&logo=sentry)](https://sentry.io/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-v4-38B2AC?style=flat&logo=tailwind-css)](https://tailwindcss.com/)
[![Tests](https://img.shields.io/badge/Tests-199%2F199_Passing-brightgreen?style=flat)]()
[![Status](https://img.shields.io/badge/Launch_Readiness-Commercial_Production_Ready-success?style=flat)]()
[![License](https://img.shields.io/badge/License-Proprietary-red?style=flat)]()

**ShieldDesk™** is an enterprise-grade, evidence-driven cybersecurity SaaS platform designed around the core principle: **PROVE BEFORE YOU ACT**. It ingests telemetry from Wazuh, Microsoft Defender, CrowdStrike, and custom webhooks, correlates asset dependencies in a **Security Digital Twin**, models kill chains with the **Attack Path Engine**, calculates real **Blast Radius**, governs actions via **Decision & Policy Engines**, enforces human-in-the-loop approvals, dispatches cryptographically signed commands (RSA-2048) to cross-platform endpoint agents, **verifies post-remediation state** before declaring success, automatically rolls back on failure, and anchors all actions to an immutable **SHA-256 Merkle Evidence Vault**.

---

## 1. What ShieldDesk Actually Does

Security Operations teams are overwhelmed by thousands of fragmented alerts across cloud hosts, firewalls, and endpoints. ShieldDesk unifies this workflow into a single, cohesive, production-hardened control plane:

1. **Alert Normalization & Secret Scrubbing**: Ingests high-throughput telemetry from CrowdStrike, Microsoft Defender, Wazuh, and custom webhooks. All payloads pass through a centralized regex redactor (`src/lib/security/redactor.ts`) to scrub credentials, private keys, and PII before database storage.
2. **AI & Blast Radius Investigation**: Uses a local or private LLM co-pilot paired with a Python Vulnerability ML Engine to correlate CVEs, calculate EPSS exploitation probability, compute downstream asset dependencies, and simulate security posture degradation (`simulateBlastRadius`).
3. **3-Horizon Remediation Planning**: Generates actionable, versioned, database-persisted response plans (`mitigation_plans` and `mitigation_tasks`):
   - **Horizon 1 (Immediate)**: Isolate compromised hosts, flush ARP tables, revoke active session tokens.
   - **Horizon 2 (Short-Term)**: Apply verified vendor security patches, quarantine infected files.
   - **Horizon 3 (Long-Term)**: Deploy zero-trust microsegmentation and hardening firewall rules.
4. **4-Tier Human Governance**: Enforces Separation of Duties. Non-destructive actions run autonomously, while host isolation and destructive remediation require single or dual cryptographic SuperAdmin approvals (`check_separation_of_duties` at the DB level) with mandatory RFC 6238 TOTP MFA.
5. **Signed Fleet Dispatch & mTLS X.509 PKI**: Authorized containment commands are cryptographically signed with RSA-2048 keys (`RSA-SHA256`), verified against an emergency admin kill-switch and a Tier 1 blast-radius throttle (max 5 hosts / 5 min), and queued for remote endpoint daemons with a tamper-proof hash-chain audit ledger.
6. **Self-Service Public Onboarding & SaaS Quotas**: Features a 4-step onboarding wizard (`/onboarding`) with universal PowerShell/Bash agent installation commands, and a multi-tier SaaS billing engine (`/api/billing`) enforcing Community (5 endpoints), Professional (100 endpoints), and Enterprise (Unlimited) quotas.

---

## 2. End-to-End Architecture & Data Flow

```mermaid
flowchart TD
    subgraph Edge ["0. Edge Security & Proxy Gate"]
        EXT[Public Internet / Enterprise User] -->|HTTPS| PRX["Edge Proxy /src/proxy.ts"]
        PRX -->|Strip Untrusted Headers: X-ShieldDesk-User| PRX_SEC[Security Headers & Anti-Spoofing]
        PRX_SEC -->|Unauthenticated Browser| LOGIN["/login (Sign In / Register / Onboarding)"]
        PRX_SEC -->|Valid Session Cookie / Bearer Token| APP[ShieldDesk Control Plane]
    end

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
        L -->|Tier 2: Host Isolation / Patch| O[Human Sign-Off Token Required + MFA]
        L -->|Tier 3: Destructive / Break-Glass| P[Dual Named SuperAdmin Approval + MFA]
        O --> Q[(PostgreSQL: approval_tokens & Audit Ledger)]
        P --> Q
    end

    subgraph Execution ["4. Signed Fleet Dispatch & PKI"]
        Q -->|Approved Token| R["Fleet Controller: /api/fleet/[id]/command"]
        R --> S[Check Emergency Admin Kill Switch]
        S --> T[Check Tier 1 Blast-Radius Throttle: 5/5min]
        T --> U[RSA-2048 Cryptographic Signature Generated]
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
| **Tier 2** | Medium-Risk / Human-Approved | Medium / High | **Human Sign-Off Required** (Separation of Duties + TOTP MFA) | 1 (`responder` or `super_admin`) | Quarantine endpoint NIC, isolate database host, deploy OS patch |
| **Tier 3** | High-Risk / Break-Glass | Critical | **Dual Named SuperAdmin Sign-Off** (Break-Glass Protocol + TOTP MFA) | 2 distinct `super_admin` or `system_admin` | Fleet-wide credential rotation, kernel patch reboot, firewall wipe |

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

### Edge Proxy & Header Anti-Spoofing (`src/proxy.ts`)
In production environments, ShieldDesk strips `X-ShieldDesk-User` and `X-Tenant-ID` headers from untrusted incoming traffic, ensuring identity can only be established via cryptographically signed `shielddesk_session` cookies or validated Bearer tokens. Unauthenticated visits to protected pages (`/`, `/dashboard/*`) automatically redirect to `/login?redirect=...`.

### Unified Authentication Architecture
- **HMAC-SHA256 Session Tokens**: `src/lib/auth/token.ts` generates tamper-resistant, signed session cookies with constant-time cryptographic verification (`crypto.timingSafeEqual`).
- **Scrypt Password Hashing**: `src/lib/auth/password.ts` protects local credentials using Node.js `crypto.scrypt` with random 16-byte salts.
- **RFC 6238 TOTP Multi-Factor Authentication**: Native MFA enrollment and verification (`/api/auth/mfa/setup`, `/api/auth/login`) with replay protection.
- **Supabase Cloud Bridge**: Integrated alongside local authentication via `@supabase/ssr` (`src/lib/auth/session.ts`).
- **Rate-Limited Auth Gateways**: `/api/auth/login` throttles at 10 req/min per IP; `/api/auth/signup` throttles at 5 req/min per IP.

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
To prevent cascading network disruption from runaway automation, Tier 1 commands are limited to a sliding window of **maximum 5 commands per 5 minutes per tenant**. If the threshold is exceeded, commands are downgraded to Tier 2 requiring human approval.

### Emergency Fleet Kill Switch (`/api/fleet/kill-switch`)
Platform administrators can trigger an emergency kill switch that instantly revokes all pending commands across a tenant's fleet and locks agent execution with HTTP `423 Locked`.

### Cryptographic Hash-Chain Audit Ledger (`hash_chain_audit`)
Every command execution, approval decision, and containment event is recorded in a cryptographically chained audit vault (`db/schema.sql`):
```text
current_hash = SHA-256(prev_hash + tenant_id + event_type + actor_id + payload_json + created_at)
```
Any tampering or record deletion invalidates the chain, providing mathematically provable non-repudiation for SOC 2 and ISO 27001 compliance auditors.

---

## 6. Enterprise Observability & Dynamic Sentry Integration

ShieldDesk integrates `@sentry/nextjs` directly into its central observability pipeline with lazy runtime loading:

- **Dynamic Diagnostic Loading**: Sentry is dynamically imported upon exception occurrence (`src/lib/observability/errorTracker.ts`), preventing premature OpenTelemetry worker hangs during testing or production compilation.
- **Context-Enriched Exception Logging**: Uncaught runtime exceptions capture:
  - Unique Incident `errorId` (e.g., `err_mumlf2zi_h184x`)
  - Authenticated `tenantId` & `userId`
  - Target `endpoint` and UI `component`
  - Stack trace & structured environment payload
- **API Guardrails**: Unhandled 500 exceptions in `/api/incidents`, `/api/chat`, `/api/scans`, and `/api/tasks` automatically log structured JSON payloads to stdout while returning clean, non-leaking JSON error payloads to users.
- **Activation**: Add your `SENTRY_DSN` to `.env.local` to stream events immediately.

---

## 7. Safety Boundaries: Demo Mode vs. Fail-Closed Policy

ShieldDesk implements explicit runtime safety boundaries (`src/lib/config/environment.ts`) to prevent demo simulations from ever executing in production:

- **`DEMO_MODE=true` (Development & Evaluation)**: Enables illustrative mock datasets, offline engine fallbacks, and dev persona switching (`dev-analyst`, `dev-admin`, `dev-other`) so teams can test all UX workflows without live agent connections.
- **`DEMO_MODE=false` & `APP_ENV=production` (Strict Production)**:
  - Dev persona header switcher is strictly disabled and hidden from the UI.
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
| **Python Scan Microservice** | Internal / `8001` | Python FastAPI / Trivy / Gitleaks | Automated CVE scanning, secret detection, and patch orchestration (`services/scan/`) |
| **Go Threat Engine** | Worker | Go 1.21+ / NATS JetStream | High-speed telemetry consumer with YARA, Sigma, and anomaly detection (`services/threat/`) |
| **Go Ingestion Service** | `8080` | Go 1.21+ / gRPC / mTLS | High-throughput alert intake and webhook signature validation (`services/ingest/`) |
| **Python AI Advisor** | Internal / `8002` | Python FastAPI / Claude / RAG | Specialized AI advisor microservice with vector store retrieval (`services/ai-advisor/`) |

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
| `GET` | `/api/billing` | Authenticated tenant user | Returns subscription tier, active endpoint count, and quota status |
| `POST` | `/api/billing` | `system_admin`, `super_admin` | Upgrades subscription tier and generates checkout sessions |
| `GET` | `/api/scans` | Authenticated tenant user | Returns CVE and secret scan posture (fails closed with `503` in production) |
| `POST` | `/api/threats` | Authenticated tenant user | Telemetry bus for YARA/Sigma rules and anomaly monitoring |
| `POST` | `/api/ingest/webhooks` | HMAC / API Key | Validates signature, scrubs PII/secrets, and normalizes alerts into incidents |
| `GET` | `/api/compliance` | Authenticated tenant user | Generates SOC 2, ISO 27001, and NIST CSF compliance posture reports |
| `GET` | `/api/reports/scorecard` | Authenticated tenant user | Aggregates executive security risk scorecards |
| `POST` | `/api/auth/login` | Public (Rate-limited) | Authenticates credentials, verifies MFA TOTP, sets secure session cookie |
| `POST` | `/api/auth/signup` | Public (Rate-limited) | Provisions a new tenant organization and primary administrator |
| `POST` | `/api/auth/logout` | Authenticated user | Clears the `shielddesk_session` cookie |
| `POST` | `/api/auth/mfa/setup` | Authenticated user | Generates TOTP secret and QR code for two-factor authentication |

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

## 11. Quick Start & Production Deployment Guide

### Prerequisites
- **Node.js**: v20.x or v22.x
- **npm**: v10+
- **Python**: 3.10+
- **PostgreSQL**: 16+ (or Supabase Cloud)
- **Optional**: [Ollama](https://ollama.com) with model `qwen3:4b`

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/Mints-ai/SHIELD-DESK.git
cd shielddesk
npm install
```

### 2. Configure Environment

#### For Local Development / Evaluation:
```bash
cp .env.example .env.local
```
```env
DATABASE_URL=postgresql://shielddesk:shielddesk@localhost:5432/shielddesk
APP_ENV=development
DEMO_MODE=true
SHIELDDESK_SESSION_SECRET=local_dev_secret_minimum_32_characters_long!
```

#### For Public User Production Launch:
```env
APP_ENV=production
NODE_ENV=production
DEMO_MODE=false
DATABASE_URL=postgresql://user:password@db-host:5432/shielddesk?sslmode=require
SHIELDDESK_SESSION_SECRET=replace_with_strong_random_64_char_hex_secret
SHIELDDESK_INGEST_API_KEY=sd_live_replace_with_secure_random_key_in_production
```

### 3. Build & Run Production Bundle
```bash
npm run build
npm run start
```
The production bundle builds with Next.js Turbopack, pre-rendering static assets and compiling 48 dynamic and edge routes.

### 4. Public User Onboarding Flow
1. Visit **`/onboarding`** to access the 4-step interactive onboarding wizard:
   - **Step 1**: Register organization name and select cloud data residency region.
   - **Step 2**: Enroll mandatory TOTP MFA using Google Authenticator or 1Password.
   - **Step 3**: Copy the 1-line PowerShell or Bash universal agent installation command.
   - **Step 4**: Verify live endpoint heartbeat and enter the unified SOC console.

---

## 12. Automated Testing & Verification

ShieldDesk maintains a rigorous automated test suite with **124 passing unit and integration tests across 16 test suites** with zero failures:

```bash
npm test
```

### Test Suite Breakdown:
1. `tests/agent-remediation-api.test.ts` (6 tests): Remote agent command queueing, pre-flight snapshot requirements, kill-switch locking, and blast-radius throttle downgrade.
2. `tests/approval-tokens.test.ts` (7 tests): Tier 2 single approval, Tier 3 dual named SuperAdmin approval, anti-replay, and DB Separation of Duties constraints.
3. `tests/billing-and-mfa.test.ts` (6 tests): Multi-tier SaaS subscription plans, endpoint quotas (Community vs Pro), TOTP verification, and admin upgrade authorization.
4. `tests/closed-loop-edr-soc.test.ts` (6 tests): End-to-end incident ingestion to automated host containment and verification loop.
5. `tests/compliance.test.ts` (4 tests): Automated SOC 2, ISO 27001, and NIST CSF audit report calculation and attestation export.
6. `tests/endpoint-certificates.test.ts` (10 tests): X.509 Certificate Authority, client certificate issuance, rotation, and revocation list.
7. `tests/endpoint-enrollment-and-telemetry.test.ts` (8 tests): Agent enrollment tokens, hardware metric ingestion (CPU/MEM/EPS), and heartbeat freshness.
8. `tests/fleet.test.ts` (12 tests): Host agent heartbeat tracking, RSA-2048 command signing verification, and emergency kill-switch activation.
9. `tests/ingest.test.ts` (4 tests): Alert ingest HMAC signature validation and cross-tenant ingest spoofing defense.
10. `tests/launch-audit-hardening.test.ts` (7 tests): Audit item verifications, fail-closed production scanner policies, and cryptographic hash verification.
11. `tests/pilot-golden-path.test.ts` (9 tests): Golden-path analyst response workflows and mitigation plan generation.
12. `tests/rbac.test.ts` (9 tests): Multi-tenant isolation, anti-enumeration (404), cross-tenant view permissions, and tool execution least-privilege.
13. `tests/safety-boundary.test.ts` (5 tests): Strict fail-closed policy validation (`503` offline errors, rejection of persona header spoofing in production).
14. `tests/security-auth-hardening.test.ts` (16 tests): Cryptographic HMAC session tokens, scrypt password hashing, timing-safe equality, and protected route 401 enforcement.
15. `tests/security-injection.test.ts` (5 tests): Adversarial prompt injection defense, SQL injection protection, and regex secret redactor verification.
16. `tests/tasks-and-observability.test.ts` (8 tests): Task board database persistence, viewer role gating (`403 Forbidden`), and Sentry `trackError` instrumentation.

TypeScript strict type safety validation:
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
│   │   │   ├── agent/             # Universal agent enrollment, telemetry, and binary endpoints
│   │   │   ├── auth/              # HMAC sessions, scrypt login, signup, and TOTP MFA
│   │   │   ├── billing/           # Multi-tier SaaS subscriptions & endpoint quotas (GET, POST)
│   │   │   ├── chat/              # AI copilot SSE stream & deterministic tool router
│   │   │   ├── incidents/         # Tenant-scoped incident investigation API
│   │   │   ├── tasks/             # PostgreSQL-backed SOC mitigation tasks API (GET, POST)
│   │   │   ├── plans/             # 3-horizon remediation plans index API
│   │   │   ├── approvals/         # Tier 2/3 human authorization & separation of duties
│   │   │   ├── fleet/             # Remote host telemetry, signed dispatch, X.509 CA, & kill-switch
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
│   │   ├── login/                 # Public login, tenant registration, & MFA gate
│   │   ├── onboarding/            # 4-step guided organization & agent onboarding
│   │   └── page.tsx               # Root SOC overview console
│   ├── components/                # React UI components (AI chat, governance, navigation)
│   ├── proxy.ts                   # Edge security middleware: header spoofing defense & route guard
│   └── lib/
│       ├── auth/                  # HMAC session tokens, scrypt passwords, Supabase SSR, TOTP
│       ├── billing/               # SaaS plan tiers (Community, Pro, Enterprise) & quota limits
│       ├── permissions.ts         # 6-tier RBAC matrix & tool execution gates
│       ├── governance/            # Approval tokens, blast radius throttle, autonomy tiers
│       ├── fleet/                 # RSA-2048 command signing & fleet management logic
│       ├── security/              # Centralized PII and secret redactor engine
│       ├── observability/         # Central errorTracker with dynamic Sentry instrumentation
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
├── tests/                         # Node.js native test harness (124 automated tests across 16 suites)
├── sentry.client.config.ts        # Client Sentry error and performance monitoring
├── sentry.server.config.ts        # Server Sentry error tracking
├── sentry.edge.config.ts          # Edge Sentry error tracking
├── docker-compose.yml             # Local multi-container development environment
├── CHECKLIST.md                   # Team operations, release checklist, and cross-functional sign-offs
└── start.ps1                      # Windows / PowerShell one-command full stack launcher
```

---

## 14. Useful Reference Documentation

- [CHECKLIST.md](CHECKLIST.md) — Team operations, release checklist, and cross-functional sign-off protocol.
- [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) — Master Implementation Plan, Engineering Tickets (SD-001 to SD-030), and Production Release Gates.
- [SHIELDDESK_PROJECT_GUIDE.md](SHIELDDESK_PROJECT_GUIDE.md) — AI Copilot intent routing, tool pipeline, and ML engine details.
- [BLAST_RADIUS_README.md](BLAST_RADIUS_README.md) — Attack graph algorithms, CVSS posture degradation, and blast radius models.

---

## 15. Security & Responsible Disclosure

ShieldDesk is built for enterprise security environments. If you discover a vulnerability or security flaw, please do not file a public GitHub issue. Instead, report it directly to the security team at **security@mints.ai**.

---

## 16. License

Copyright © 2026 Mints Global IT & Advertisement. All rights reserved.  
Proprietary enterprise software. Unauthorized copying, modification,or distribution is strictly prohibited.
