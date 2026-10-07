# ShieldDesk™ — Evidence-Driven Security Operations & Remediation Platform

[![Next.js](https://img.shields.io/badge/Next.js-16.3.5-black?style=flat&logo=next.js)](https://nextjs.org/)
[![React](https://img.shields.io/badge/React-19.2.8-blue?style=flat&logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue?style=flat&logo=typescript)](https://www.typescriptlang.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-blue?style=flat&logo=postgresql)](https://www.postgresql.org/)
[![Sentry](https://img.shields.io/badge/Sentry-Enabled-362D59?style=flat&logo=sentry)](https://sentry.io/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-v4-38B2AC?style=flat&logo=tailwind-css)](https://tailwindcss.com/)
[![Trivy](https://img.shields.io/badge/Trivy-v0.74.0_Integrated-007acc?style=flat&logo=aqua)]()
[![Gitleaks](https://img.shields.io/badge/Gitleaks-v8.30.1_Integrated-0052cc?style=flat&logo=git)]()
[![Status](https://img.shields.io/badge/Launch_Readiness-Validation_In_Progress-orange?style=flat)]()
[![License](https://img.shields.io/badge/License-Proprietary-red?style=flat)]()

**ShieldDesk™** is an **Evidence-Driven Security Operations & Remediation** platform built around **Prove Before You Act**. It ingests security telemetry, models assets and prioritizes attack paths from available evidence, evaluates decisions and policy, supports approval workflows, and includes signed command, verification, and audit-evidence components. Deployment readiness and endpoint rollback behavior still require validation in representative production infrastructure.

---

## 1. What ShieldDesk Actually Does

Security Operations teams are overwhelmed by thousands of fragmented alerts across cloud hosts, firewalls, and endpoints. ShieldDesk unifies this workflow in a single security operations and remediation control plane:

1. **Alert Normalization & Secret Scrubbing**: Ingests high-throughput telemetry from CrowdStrike, Microsoft Defender, Wazuh, and custom webhooks. All payloads pass through a centralized regex redactor (`src/lib/security/redactor.ts`) to scrub credentials, private keys, and PII before database storage.
2. **AI & Blast Radius Investigation**: Uses a local or private LLM co-pilot paired with a Python Vulnerability ML Engine to correlate CVEs, calculate EPSS exploitation probability, compute downstream asset dependencies, and simulate security posture degradation (`simulateBlastRadius`).
3. **3-Horizon Remediation Planning**: Generates actionable, versioned, database-persisted response plans (`mitigation_plans` and `mitigation_tasks`):
   - **Horizon 1 (Immediate)**: Isolate compromised hosts, flush ARP tables, revoke active session tokens.
   - **Horizon 2 (Short-Term)**: Apply verified vendor security patches, quarantine infected files.
   - **Horizon 3 (Long-Term)**: Deploy zero-trust microsegmentation and hardening firewall rules.
4. **4-Tier Human Governance**: Enforces fine-grained governance and Separation of Duties. Non-destructive actions run autonomously (Tier 0). For Tier 1 and Tier 2 containment tasks, System Administrators can self-approve actions even if requested by them for zero-delay response. Analysts cannot approve any remediation actions under any circumstances (`approve.*` revoked). Critical and destructive actions (Tier 3) strictly enforce dual named SuperAdmin approval (`check_separation_of_duties` at the DB level) with mandatory RFC 6238 TOTP MFA.
5. **Signed Fleet Dispatch & mTLS X.509 PKI**: Authorized containment commands are cryptographically signed with RSA-2048 keys (`RSA-SHA256`), verified against an emergency admin kill-switch and a Tier 1 blast-radius throttle (max 5 hosts / 5 min), and queued for remote endpoint daemons with a tamper-proof hash-chain audit ledger.
6. **Self-Service Public Onboarding & SaaS Quotas**: Features a 4-step onboarding wizard (`/onboarding`) with universal PowerShell/Bash agent installation commands, and a multi-tier SaaS billing engine (`/api/billing`) enforcing Community (5 endpoints), Professional (100 endpoints), and Enterprise (Unlimited) quotas.
7. **Vulnerability & Secret Scanning Integration**: Includes native integrations with Aqua Security Trivy for deep CVE vulnerability assessment and Gitleaks for detecting committed credentials, API tokens, and secret exposures across git history and repository filesystems.

## Capability status

| Capability | Status | Evidence and limit |
|---|---|---|
| Decision, policy, approval, signed dispatch, and tenant authorization modules | IMPLEMENTED | Present in the application and protected by automated tests. |
| Action verification and simulated failure handling | TESTED | Automated unit/integration tests use simulated evidence; they do not validate real host restoration. |
| Certificate and command security checks | TESTED | Automated tests cover signatures, replay controls, tenant binding, freshness, and kill-switch behavior. |
| Customer production rollout, external security testing, and endpoint rollback | PRODUCTION-VALIDATED: not yet | Requires real infrastructure and independent or customer validation. |

No feature is represented here as production-validated. Automated tests establish behavior in their test environment only.

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
| **Tier 1** | Low-Risk / Reversible | Low | Pre-flight snapshot + rate-throttled dispatch | 1 (`system_admin`, `super_admin`, or `responder`; **Admin self-approval permitted**; **Analyst cannot approve**) | Revoke user sessions, block outbound domain, blacklist IP on gateway |
| **Tier 2** | Medium-Risk / Containment | Medium / High | **Human Sign-Off Required** (TOTP MFA) | 1 (`system_admin`, `super_admin`, or `responder`; **Admin self-approval permitted**; **Analyst cannot approve**) | Quarantine endpoint NIC, isolate database host, deploy OS patch |
| **Tier 3** | High-Risk / Break-Glass | Critical | **Dual Named SuperAdmin Sign-Off** (Strict Separation of Duties + TOTP MFA) | 2 distinct `super_admin` or `system_admin` (**No self-approval permitted**) | Fleet-wide credential rotation, kernel patch reboot, firewall wipe |

### Separation of Duties & Tier Approval Constraints
Separation of duties is enforced at **both the application and database schema levels** (`db/schema.sql`):
```sql
CONSTRAINT check_separation_of_duties
  CHECK (approved_by IS NULL OR tier IN ('Tier 1', 'Tier 2') OR requested_by <> approved_by),
CONSTRAINT check_tier3_dual_approval_separation
  CHECK (secondary_approved_by IS NULL OR approved_by <> secondary_approved_by)
```
- **System Admin Self-Approval (Tier 1 & Tier 2)**: For reversible and medium-risk containment tasks (e.g. host quarantine, session revocation), a System Administrator (`system_admin` or `super_admin`) is authorized to sign off and execute a task even if created by them, avoiding operational deadlocks during active incidents.
- **Analyst Zero-Approval Rule**: Analysts (`analyst` and `user` roles) have **zero sign-off authority under any circumstance**. They can discover threats, investigate root causes, and draft/assign tasks, but cannot authorize remediation execution.
- **Tier 3 Break-Glass Separation**: For destructive actions (e.g. credential revocation, fleet reboot), strict dual-authorization is mandatory: an administrator cannot approve their own Tier 3 request, and two distinct administrators must independently sign off.

---

## 3.1 Remediation Task Management & UI Block Architecture

The **Task Board** (`/dashboard/tasks`) coordinates the end-to-end lifecycle of security remediation tasks from analyst discovery to signed endpoint execution.

### The Requester vs. Approver Lifecycle (Governance Rules)
- **Who can Draft Tasks?**: Any operational user or analyst (`analyst`, `responder`, `system_admin`, `super_admin`) can draft custom or AI-suggested remediation tasks.
- **Who can Approve Tasks?**: Only authorized administrators and responders (`system_admin`, `super_admin`, `responder`). **Analysts cannot approve tasks under any circumstances.**
- **Admin Self-Approval for Containment (Tier 1 & 2)**: To ensure immediate incident response, System Administrators can approve and dispatch Tier 1 and Tier 2 tasks they drafted themselves without requiring peer hand-offs.
- **Tier 3 Dual-Approval Enforcement**: For high-impact Tier 3 break-glass tasks, self-approval is rejected (`Separation of Duties Violation (403)`), requiring a second distinct administrator to sign off.

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as SOC Analyst (Requester)
    participant Board as Task Board (/dashboard/tasks)
    participant DB as PostgreSQL
    actor Admin as SOC Lead / Admin (Approver)
    participant Agent as Endpoint Agent Daemon

    Analyst->>Board: Draft New Remediation Task (e.g. Isolate FIN-WS-042)
    Board->>DB: INSERT INTO mitigation_tasks (status='pending', requested_by=Analyst)
    DB-->>Board: Lands in "Pending Authorization" lane
    Admin->>Board: Clicks "Sign Off Now"
    Admin->>Board: Reviews Blast Radius & AI Confidence -> Clicks "Approve & Execute"
    Board->>DB: UPDATE approval_tokens (status='approved', approved_by=Admin)
    DB-->>Board: Moves to "Authorized & Queued" lane
    Admin->>Board: Clicks "Dispatch to Agent"
    Board->>DB: Status transitions to "Executing" (in_progress)
    Board->>Agent: RSA-2048 Signed Command Dispatched
    Agent-->>Board: Pre-flight Snapshot Verified -> Command Executed -> Result Signed
    Board->>DB: Status transitions to "Executed & Verified" (completed)
```

---

### Detailed Breakdown of Every Task Module Block

#### 1. Kanban Board Lanes (Operational Lifecycle)
| Lane | State | Description & Purpose |
| :--- | :--- | :--- |
| **Pending Authorization** | `pending` | Newly created tasks requiring governance approval before any agent command can be dispatched. Non-approver analysts can inspect, edit, or delete tasks here. |
| **Authorized & Queued** | `approved` | Tasks that have successfully passed human sign-off with a valid cryptographic approval token. Ready for the SOC team to dispatch to the targeted endpoint. |
| **Executing** | `in_progress` | Active execution phase. Shows live spinners and progress indicators while the agent daemon creates a safety snapshot and runs the remediation script. |
| **Executed & Verified** | `completed` | Finished actions. Confirmed and recorded in the tamper-evident hash-chain audit ledger with terminal logs and endpoint return codes. |

---

#### 2. Task Card & Detail Drawer Component Blocks

| Block Name | UI Element | Operational Necessity & Why It Exists |
| :--- | :--- | :--- |
| **Status Block** | Badge (`Pending`, `Approved`, `Executing`, `Executed`) | Provides instantaneous visibility into where the task sits in the governance pipeline, preventing premature or duplicate action attempts. |
| **Horizon Block** | Horizon Tag (`Immediate`, `Short-term`, `Long-term`) | Categorizes remediation urgency: <br>• **Immediate**: Emergency triage & active containment (e.g. isolate host).<br>• **Short-term**: Vulnerability remediation (e.g. deploy patch).<br>• **Long-term**: Architectural posture hardening (e.g. firewall microsegmentation). |
| **Autonomy Tier Block** | Interactive Selector (`Tier 1`, `Tier 2`, `Tier 3`) | **Critical Governance Gate**: Dictates whether this task can run autonomously (Tier 1), requires one authorized human approver (Tier 2), or mandates dual SuperAdmin sign-off (Tier 3). Can be re-classified dynamically by authorized operators. |
| **Blast Radius Block** | Text Tag (`Host Scope`, `Subnet Scope`, `Global`) | Defines the expected blast radius and network impact zone. Informs the approver of potential operational disruption prior to approving containment. |
| **Description & Mitigation Scope** | Text Block | Detailed instructions and rationale explaining why the action was recommended by the AI advisor or SOC analyst. |
| **Incident Context & Plan Switcher** | Incident Box & Dropdown | Explicitly anchors the task to its parent security incident (e.g. `INC-4223`) and allows analysts to re-assign tasks between incident mitigation plans dynamically. |
| **Governance Sign-Off History** | Token List & Audit Table | **Regulatory & Audit Evidence**: Displays the unique UUID token, active requester, verified approver, approval timestamp, and rejection reason if denied. Guarantees non-repudiation. |
| **Agent Dispatch Logs** | Terminal Console Output | Real-time CLI standard out / standard error captured directly from the endpoint daemon (e.g., PowerShell or Linux bash execution output) proving that the remediation command actually executed. |
| **Dispatch to Agent** | Primary CTA Button (Golden Theme) | Cryptographically signs the task payload and transmits it over mTLS to the endpoint daemon with automatic fallback and snapshot validation. |
| **Delete Task** | Destructive Action Button (Crimson) | Allows analysts to prune obsolete, rejected, or duplicate remediation tasks with foreign-key cascade cleanup. |

---

## 4. Multi-Tenant RBAC & Security Isolation

ShieldDesk is built from the ground up for multi-tenancy. Every database query, fleet command, and AI context prompt is strictly bound to the authenticated caller's tenant:

### 6 Unified Roles (`src/lib/permissions.ts`)
- **`system_admin`**: Global platform administrator with cross-tenant visibility (`VIEW_CROSS_TENANT`), user management, emergency fleet kill-switch rights, and self-approval authority for Tier 1 & Tier 2 containment tasks.
- **`super_admin`**: Tenant organization administrator with Tier 3 dual-approval authority (`approve.tier3`).
- **`responder`**: Incident response engineer; signs off on Tier 1 and Tier 2 containment tasks (`approve.tier1`, `approve.tier2`) and dispatches containment commands.
- **`analyst`**: Security operations analyst; drafts mitigation tasks (`task.assign`), investigates incidents, and simulates attack graphs. **Strictly restricted from approving any remediation actions (`approve.*` permissions revoked).**
- **`viewer`**: Read-only stakeholder; cannot approve tokens, cannot draft tasks (rejected with `403 Forbidden`), and cannot execute state-changing actions.
- **`user`**: Standard tenant operator with basic incident and CVE read/investigation permissions; zero approval rights.

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
This provides a cryptographically tamper-evident audit trail. It does not, by itself, establish non-repudiation or SOC 2 or ISO 27001 compliance.

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

## 8. Real-Time Aqua Trivy Vulnerability Scanner & Gitleaks Secret Detection

The **Security Scanner & Remediation Center** (`/dashboard/scanner`) integrates dual enterprise scanning engines for both CVE vulnerability assessment and credential leak detection:

### Aqua Security Trivy (v0.74.0) — CVE Vulnerability Scanner (`src/lib/trivy.ts`)
- **100% Live Real-Time Findings**: Clicking **"Trigger Trivy Scan"** directly spawns `trivy.exe fs` (or `trivy` on Linux) against local workspaces, Go modules, npm dependencies, and OS packages. It returns real-time CVEs with actual installed versions, fixed versions, NVD CVSS v3 severity scores, and upgrade instructions.
- **Clean Initial State**: Upon entering the scanner tab, CVE findings and metrics start blank (`0` Critical, `0` High) until an explicit scan is triggered by the analyst.
- **Dynamic Risk Metrics**: Metric cards (`Critical CVEs`, `High CVEs`, `Active CVEs`) compute live via `useMemo` dynamically reflecting the current scan findings count.
- **Severity Filtering**: Immediate interactive filtering pills (`ALL`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) allow SOC teams to triage severe disclosures instantly.
- **Security & Reliability Guards**:
  - **CWE-78 Command Injection Defense**: Uses Node.js `execFile` with an immutable argument vector (no shell interpolation).
  - **CLI Option Injection Guard**: Rejects targets starting with hyphens or argument flags.
  - **Safe Path Normalization**: Resolves non-existent container paths (e.g., `/app`) gracefully to the project root.
  - **Buffer Limit**: Enforces a 30 MB `maxBuffer` to prevent child process termination on massive repository dependency graphs.
- **One-Command CLI Setup**:
  ```bash
  npm run setup:trivy
  ```
  Automatically downloads and extracts the official Aqua Security Trivy v0.74.0 binary directly into `tools/trivy/` with cross-platform validation.
- **Continuous Integration (CI/CD)**: GitHub Actions workflow (`.github/workflows/ci.yml`) automatically installs Aqua Trivy on Ubuntu runners during CI test execution to guarantee zero regressions.

### Gitleaks (v8.30.1) — High-Performance Secret Detection (`src/lib/gitleaks.ts`)
- **Deep Git History & Filesystem Scans**: Dispatches `gitleaks.exe git` or `gitleaks.exe dir` to detect committed API keys, tokens, AWS credentials, database passwords, private keys, and high-entropy secrets across commit history or working tree files.
- **Automatic Output Redaction**: Strictly enforces the `--redact` flag and SHA-1 secret hashing so raw secret materials are never exposed in JSON responses, server logs, or UI dashboards.
- **Actionable Remediation Workflows**: Detected secrets provide automated remediation options (`Rotate AWS Key`, `Revoke GitHub PAT`, `Invalidate Secret Token`) with auditable dispatch via `/api/gitleaks/mitigate`.
- **Policy & Allowlist Configuration**: Automatically detects `.gitleaks.toml` configuration at the repository root or `tools/gitleaks/` to support custom regex rules, path allowlists, and entropy thresholds.
- **Security & Safety Guards**:
  - **CWE-78 Command Injection Defense**: Executes via Node.js `execFile` with an immutable argument array (no shell expansion).
  - **Fail-Closed Safety Policy**: In production (`APP_ENV=production` & `DEMO_MODE=false`), queries fail closed with `503 Service Unavailable` if the binary is absent, preventing silent false negatives.
  - **Memory & Timeout Protection**: Enforces an 8 MB buffer ceiling and configurable execution timeout (default: 120s).
- **One-Command CLI Setup**:
  ```bash
  npm run setup:gitleaks
  ```
  Automatically downloads Gitleaks v8.30.1 from official GitHub releases, verifies archive integrity, unpacks into `tools/gitleaks/gitleaks.exe`, syncs `.gitleaks.toml` to the project root, and validates binary execution.

---

## 9. Go Threat Detection & Statistical Anomaly Engine (Go 1.27)

The **Threat Intelligence & Containment Engine** (`/dashboard/threats` and `services/threat/`) is a dedicated high-performance backend microservice written in **Go 1.27** running on port `8003`. It provides multi-tenant telemetry evaluation, detection rule execution, rolling 3-sigma statistical baseline scoring, and autonomous IP containment.

### Core Detection Architecture

1. **High-Speed Dual-Stack Architecture**:
   - **Frontend BFF Gateway**: The Next.js App Router route (`/api/threats`) validates session tokens, enforces tenant context, and delegates authoritative threat state queries to `http://localhost:8003`.
   - **Go HTTP REST Engine (`services/threat/http_server.go`)**: Implements an in-memory concurrent thread-safe store (`sync.RWMutex`) maintaining sliding-window telemetry buffers and tenant-scoped containment records.

2. **Detection Rule Framework**:
   - **YARA Signature Matcher**: Inspects filesystem and process memory payloads against signatures including webshell backdoors (PHP C99/b374k), ransomware extensions (.lockbit, .blackcat), and Cobalt Strike malleable C2 reflective DLL loader memory patterns.
   - **Sigma Behavioral Log Matcher**: Analyzes Windows and Linux audit streams for attacker tradecraft: encoded PowerShell execution bypasses, distributed SSH credential brute-forcing, and Volume Shadow Copy deletion (`vssadmin.exe delete shadows`).

3. **3σ Autonomic Gaussian Statistical Anomaly Engine**:
   - Computes rolling event rates across a **60-second sliding window**:
     - **Failed Authentications / Min**: Historical mean $\mu = 4.2$, StdDev $\sigma = 2.1$, Threshold: $10.5$ attempts/min ($3\sigma$).
     - **Outbound Network Egress Rate**: Historical mean $\mu = 84.5$ MB/min, StdDev $\sigma = 65.2$, Threshold: $215.0$ MB/min ($2\sigma$).
     - **Sudo Execution Frequency**: Historical mean $\mu = 1.1$ exec/min, StdDev $\sigma = 0.8$, Threshold: $3.5$ exec/min ($3\sigma$).
   - **Zero False Noise**: At rest, rates reflect exact, honest 60-second sliding-window activity (showing `0.0` when idle). When real login failures or endpoint agent events occur, rates immediately increment and naturally expire after 60 seconds.
   - **Incident Drills**: Clicking **"Simulate Anomaly Burst"** injects a synthetic multi-stream burst (18+ auth failures, 380+ MB egress, 8+ sudo executions), driving metrics into the critical red state (`3 ANOMALIES ACTIVE`) with one-click restoration via **"Reset Baseline"**.

4. **Multi-Tenant IP Containment & Leak Prevention**:
   - **Tenant Partitioning**: Blocked IPs and security alerts are strictly partitioned by tenant ID (`map[string]map[string]*BlockedIPRecord`).
   - **Zero Cross-Tenant Leakage**: Tenant A (e.g. Acme Corp) cannot see, query, or unblock Tenant B's (e.g. Globex Corp) contained IPs. Probing `is-blocked` returns `false` across tenant boundaries.
   - **Autonomous Containment**: Automatically blocks any source IP that exceeds 5 consecutive invalid authentication attempts within the detection window.

5. **Role-Based Persona Access Control**:
   - **Company System Admin (`dev-admin` / `system_admin`)**: Full operational authority to view live authentication security alerts, trigger anomaly burst simulations, and execute **Block IP / Unblock IP** actions.
   - **Globex Analyst (`dev-other`)**: External developer persona with a clean, blank view. User login alerts and IP containment are completely hidden, and containment modifications return `403 Forbidden: IP unblocking restricted`.

### Go Threat Service API Catalog (`:8003`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Service health, version (`1.0.0`), and Go runtime metadata |
| `GET` | `/api/threats/state?tenant_id=...` | Returns tenant-scoped YARA rules, Sigma rules, live anomaly baselines, and blocked IPs |
| `POST` | `/api/threats/containment` | Executes tenant-bound `block_ip` or `unblock_ip` actions |
| `POST` | `/api/threats/simulate` | Injects synthetic anomaly telemetry bursts (`auth_failure`, `sudo_burst`, `egress_spike`, or `all`) |
| `POST` | `/api/threats/reset` | Resets active anomaly sliding windows back to nominal baseline |
| `GET` | `/api/threats/is-blocked?tenant_id=...&ip=...` | Ultra-fast containment verification lookup |

### Local Development & Testing

```bash
cd services/threat
go test -v .          # Runs full suite (6 automated tests, 100% passing)
go build -o threat.exe .
.\threat.exe          # Starts the HTTP daemon on port 8003
```

---

## 10. System Port Map & Microservices

| Service | Port | Technology | Purpose & Source Location |
| :--- | :--- | :--- | :--- |
| **ShieldDesk Web Console** | `3000` | Next.js 16 / React 19 / Tailwind v4 | SOC console, Kanban task board, fleet controller, compliance, AI chat (`src/app/`) |
| **Python Vulnerability AI Brain** | `8000` | Python 3.10+ / Scikit-Learn Random Forest | Multi-target CVE/EPSS risk scoring, KEV catalog matching (`ai-chat-desk/server.py`) |
| **Go Threat & Anomaly Engine** | `8003` | Go 1.27 / HTTP REST / NATS | Authoritative YARA, Sigma, 3σ statistical anomaly detection, and tenant-isolated IP containment (`services/threat/`) |
| **PostgreSQL Database** | `5432` | PostgreSQL 16+ (Alpine) | Multi-tenant schema, incidents, mitigation tasks, approval tokens, audit log (`db/schema.sql`) |
| **Local LLM Co-Pilot** | `11434` | Ollama (`qwen3:4b`) | Local conversational intent router & synthesis with zero data egress |
| **Distributed Cache & Throttle** | `6379` | Redis 7+ (Alpine) | Command throttle rate limiter (5 hosts / 5 min) and session caching |
| **Python Scan Microservice** | Internal / `8001` | Python FastAPI / Trivy / Gitleaks | Automated CVE scanning, secret detection, and patch orchestration (`services/scan/`) |
| **Go Ingestion Service** | `50051` / `8004` | Go 1.27 / gRPC / mTLS / HTTP | High-throughput alert intake and webhook signature validation (`services/ingest/`) |
| **Python AI Advisor** | Internal / `8002` | Python FastAPI / Claude / RAG | Specialized AI advisor microservice with vector store retrieval (`services/ai-advisor/`) |

---

## 11. Comprehensive API Route Catalog

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
| `GET` | `/api/scans` | `cve.read` | Returns scanner status, engine mode, and cached or clean initial CVE posture |
| `POST` | `/api/scans` | `cve.read` | Executes live Aqua Trivy scan on codebase/container (`action: "cve_scan"`) or Gitleaks scan |
| `GET` | `/api/gitleaks/scan` | `cve.read` | Returns Gitleaks scanner status, engine mode, and cached secret leak findings |
| `POST` | `/api/gitleaks/scan` | `cve.read` | Triggers live Gitleaks secret detection across git commit history or working tree |
| `POST` | `/api/gitleaks/mitigate` | `responder`, `super_admin` | Dispatches credential rotation, revocation, or quarantine workflows for detected secrets |
| `GET`, `POST` | `/api/threats` | Authenticated tenant user | BFF gateway delegating to Go Threat Engine (:8003) for authoritative rules, 3σ baselines, and containment |
| `POST` | `/api/ingest/webhooks` | HMAC / API Key | Validates signature, scrubs PII/secrets, and normalizes alerts into incidents |
| `GET` | `/api/compliance` | Authenticated tenant user | Generates SOC 2, ISO 27001, and NIST CSF compliance posture reports |
| `GET` | `/api/reports/scorecard` | Authenticated tenant user | Aggregates executive security risk scorecards |
| `POST` | `/api/auth/login` | Public (Rate-limited) | Authenticates credentials, verifies MFA TOTP, sets secure session cookie |
| `POST` | `/api/auth/signup` | Public (Rate-limited) | Provisions a new tenant organization and primary administrator |
| `POST` | `/api/auth/logout` | Authenticated user | Clears the `shielddesk_session` cookie |
| `POST` | `/api/auth/mfa/setup` | Authenticated user | Generates TOTP secret and QR code for two-factor authentication |

---

## 12. Database Schema Overview

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

## 13. Quick Start & Production Deployment Guide

### Prerequisites
- **Node.js**: v20.x or v22.x
- **npm**: v10+
- **Go**: 1.22+ (Go 1.27 recommended)
- **Python**: 3.10+
- **PostgreSQL**: 16+ (or Supabase Cloud)
- **Aqua Security Trivy**: v0.74.0 (installed automatically via `npm run setup:trivy`)
- **Gitleaks**: v8.30.1 (installed automatically via `npm run setup:gitleaks`)
- **Optional**: [Ollama](https://ollama.com) with model `qwen3:4b`

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/Mints-ai/SHIELD-DESK.git
cd shielddesk
npm install
```

### 2. Setup Local Scanner Binaries (Trivy & Gitleaks)

ShieldDesk provides one-step automated installation scripts for both enterprise scanner engines:

```bash
# 2a. Download & verify Aqua Security Trivy (CVE scanner v0.74.0)
npm run setup:trivy

# 2b. Download & verify Gitleaks (Secret scanner v8.30.1)
npm run setup:gitleaks
```

- `setup:trivy`: Downloads and unpacks official Aqua Security Trivy into `tools/trivy/` and validates binary execution.
- `setup:gitleaks`: Downloads official Gitleaks v8.30.1 into `tools/gitleaks/gitleaks.exe`, syncs `.gitleaks.toml` configuration to the project root, and verifies CLI availability.

### 3. Configure Environment

#### For Local Development / Evaluation:
```bash
cp .env.example .env.local
```
```env
DATABASE_URL=postgresql://shielddesk:shielddesk@localhost:5432/shielddesk
APP_ENV=development
DEMO_MODE=true
SHIELDDESK_SESSION_SECRET=local_dev_secret_minimum_32_characters_long!
THREAT_SERVICE_URL=http://localhost:8003
```

#### For Public User Production Launch:
```env
APP_ENV=production
NODE_ENV=production
DEMO_MODE=false
DATABASE_URL=postgresql://user:password@db-host:5432/shielddesk?sslmode=require
SHIELDDESK_SESSION_SECRET=replace_with_strong_random_64_char_hex_secret
SHIELDDESK_INGEST_API_KEY=sd_live_replace_with_secure_random_key_in_production
THREAT_SERVICE_URL=http://localhost:8003
```

### 4. Build & Run Services
```bash
# Run the full stack with Go Threat microservice via PowerShell:
.\start.ps1

# Or run individual components:
npm run build && npm run start              # Next.js web application (:3000)
cd services/threat && go run .             # Go Threat Engine (:8003)
```

---

## 14. Automated Testing & Verification

ShieldDesk maintains rigorous automated test suites across both TypeScript/Node.js and Go:

```bash
# 1. Run TypeScript Test Suite (204 automated tests across 32 suites)
npm test

# 2. Run Go Threat Engine Test Suite (6 tests, 100% passing)
cd services/threat
go test -v .
```

### Test Suite Highlights:
- `services/threat/http_server_test.go` (6 tests): Health endpoint validation, tenant-isolated state containment, 60-second sliding-window anomaly calculation, HTTP containment block/unblock, cross-tenant isolation enforcement (`TestIsIPBlockedAndAlerts`), and detection engine pipeline.
- `tests/trivy.test.ts` (5 tests): Deterministic binary discovery, CWE-78 CLI flag injection prevention, nonexistent filesystem path guards, live filesystem scan execution, and container `/app` path normalization.
- `tests/agent-remediation-api.test.ts` (6 tests): Remote agent command queueing, pre-flight snapshot requirements, kill-switch locking, and blast-radius throttle downgrade.
- `tests/approval-tokens.test.ts` (7 tests): Tier 2 single approval, Tier 3 dual named SuperAdmin approval, anti-replay, and DB Separation of Duties constraints.
- `tests/billing-and-mfa.test.ts` (6 tests): Multi-tier SaaS subscription plans, endpoint quotas (Community vs Pro), TOTP verification, and admin upgrade authorization.
- `tests/closed-loop-edr-soc.test.ts` (6 tests): End-to-end incident ingestion to automated host containment and verification loop.
- `tests/compliance.test.ts` (4 tests): Automated SOC 2, ISO 27001, and NIST CSF audit report calculation and attestation export.
- `tests/endpoint-certificates.test.ts` (10 tests): X.509 Certificate Authority, client certificate issuance, rotation, and revocation list.
- `tests/endpoint-enrollment-and-telemetry.test.ts` (8 tests): Agent enrollment tokens, hardware metric ingestion (CPU/MEM/EPS), and heartbeat freshness.
- `tests/fleet.test.ts` (12 tests): Host agent heartbeat tracking, RSA-2048 command signing verification, and emergency kill-switch activation.
- `tests/ingest.test.ts` (4 tests): Alert ingest HMAC signature validation and cross-tenant ingest spoofing defense.
- `tests/launch-audit-hardening.test.ts` (7 tests): Audit item verifications, fail-closed production scanner policies, and cryptographic hash verification.
- `tests/pilot-golden-path.test.ts` (9 tests): Golden-path analyst response workflows and mitigation plan generation.
- `tests/rbac.test.ts` (9 tests): Multi-tenant isolation, anti-enumeration (404), cross-tenant view permissions, and tool execution least-privilege.
- `tests/safety-boundary.test.ts` (5 tests): Strict fail-closed policy validation (`503` offline errors, rejection of persona header spoofing in production).
- `tests/security-auth-hardening.test.ts` (16 tests): Cryptographic HMAC session tokens, scrypt password hashing, timing-safe equality, and protected route 401 enforcement.
- `tests/security-injection.test.ts` (5 tests): Adversarial prompt injection defense, SQL injection protection, and regex secret redactor verification.
- `tests/tasks-and-observability.test.ts` (8 tests): Task board database persistence, viewer role gating (`403 Forbidden`), and Sentry `trackError` instrumentation.

TypeScript strict type safety validation:
```bash
npx tsc --noEmit
```

---

## 15. Repository Directory Structure

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
│   │   │   ├── gitleaks/          # Gitleaks secret scanning and mitigation routes
│   │   │   ├── scans/             # Live Aqua Trivy & secret scanner integration
│   │   │   ├── threats/           # YARA/Sigma rules & telemetry bus
│   │   │   ├── ingest/            # Authenticated alert webhook ingest
│   │   │   ├── compliance/        # Compliance posture reporting (SOC2, ISO27001)
│   │   │   └── reports/           # Executive risk scorecards
│   │   ├── dashboard/             # SOC operational interfaces
│   │   │   ├── tasks/             # Kanban board with tier-gated approvals
│   │   │   ├── plans/             # Remediation plan inspection & horizon breakdowns
│   │   │   ├── fleet/             # Endpoint agent fleet manager
│   │   │   ├── scanner/           # Live Trivy vulnerability & secret leak posture
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
│       ├── gitleaks.ts            # Gitleaks secret scanner execution engine & parser
│       ├── trivy.ts               # Aqua Trivy vulnerability scanner execution engine & parser
│       ├── security/              # Centralized PII and secret redactor engine
│       ├── observability/         # Central errorTracker with dynamic Sentry instrumentation
│       ├── config/environment.ts  # Safety boundaries (DEMO_MODE vs FAIL_CLOSED)
│       └── db/                    # PostgreSQL connection pool with lazy initialization
├── tools/
│   ├── gitleaks/                  # Local Gitleaks v8.30.1 binary & configuration directory
│   └── trivy/                     # Local Aqua Security Trivy binary installation directory
├── scripts/
│   ├── setup_gitleaks.ps1         # Automated Gitleaks secret scanner setup & download script
│   └── setup_trivy.ps1            # Automated cross-platform Trivy setup & download script
├── .gitleaks.toml                 # Repository-wide Gitleaks detection rules & allowlist config
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
│   └── seed.sql                   # Endpoint agent and audit fixtures
├── tests/                         # Node.js native test harness (204 automated tests across 32 suites)
├── sentry.client.config.ts        # Client Sentry error and performance monitoring
├── sentry.server.config.ts        # Server Sentry error tracking
├── sentry.edge.config.ts          # Edge Sentry error tracking
├── docker-compose.yml             # Local multi-container development environment
├── CHECKLIST.md                   # Team operations, release checklist, and cross-functional sign-offs
└── start.ps1                      # Windows / PowerShell one-command full stack launcher
```

---

## 16. Useful Reference Documentation

- [CHECKLIST.md](CHECKLIST.md) — Team operations, release checklist, and cross-functional sign-off protocol.
- [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) — Master Implementation Plan, Engineering Tickets (SD-001 to SD-030), and Production Release Gates.
- [SHIELDDESK_PROJECT_GUIDE.md](SHIELDDESK_PROJECT_GUIDE.md) — AI Copilot intent routing, tool pipeline, and ML engine details.
- [BLAST_RADIUS_README.md](BLAST_RADIUS_README.md) — Attack graph algorithms, CVSS posture degradation, and blast radius models.

---

## 17. Security & Responsible Disclosure

ShieldDesk is built for enterprise security environments. If you discover a vulnerability or security flaw, please do not file a public GitHub issue. Instead, report it directly to the security team at **security@mints.ai**.

---

## 18. License

Copyright © 2026 Mints Global IT & Advertisement. All rights reserved.  
Proprietary enterprise software. Unauthorized copying, modification, or distribution is strictly prohibited.
