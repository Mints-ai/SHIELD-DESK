# ShieldDesk User Guide

> **Version:** 1.0 | **Product:** ShieldDesk Autonomous SOC | **By:** Mints Global

---

## Table of Contents

1. [What is ShieldDesk?](#1-what-is-shielddesk)
2. [Getting Started](#2-getting-started)
3. [Navigating the Platform](#3-navigating-the-platform)
4. [Your Role and What You Can Do](#4-your-role-and-what-you-can-do)
5. [Incident Queue](#5-incident-queue)
6. [Mitigation Plans](#6-mitigation-plans)
7. [Task Board](#7-task-board)
8. [Fleet and Host Management](#8-fleet-and-host-management)
9. [Security Scanner](#9-security-scanner)
10. [Threat Detection Engine](#10-threat-detection-engine)
11. [ISO 27001 Compliance Audit](#11-iso-27001-compliance-audit)
12. [Risk Scorecard](#12-risk-scorecard)
13. [AI Assistant](#13-ai-assistant)
14. [Approval Workflow](#14-approval-workflow)
15. [Account and Session Security](#15-account-and-session-security)
16. [Glossary](#16-glossary)
17. [Getting Help](#17-getting-help)

---

## 1. What is ShieldDesk?

**ShieldDesk** is an autonomous Security Operations Centre (SOC) platform powered by artificial intelligence. It helps your security team detect threats, investigate incidents, contain attacks, and prove compliance — all from a single web interface.

Think of it as your 24/7 digital SOC analyst that:

- Monitors your entire endpoint fleet for suspicious activity
- Automatically classifies and triages incoming security incidents
- Proposes step-by-step remediation plans that your team reviews and approves
- Tracks compliance against ISO 27001 controls
- Gives you a real-time picture of your organisation's risk posture

ShieldDesk is **tenant-isolated**: your data is fully separated from every other organisation on the platform. No other company can ever see your incidents, assets, or plans.

---

## 2. Getting Started

### Signing In

Navigate to your ShieldDesk URL (e.g. `https://yourdomain.shielddesk.io`) and you will see the login screen.

You have three ways to authenticate:

| Method | When to use |
|--------|-------------|
| **Email and Password** | Standard login with your organisation's credentials |
| **Supabase / OAuth** | SSO via your identity provider (Google Workspace, Azure AD, etc.) |
| **Register** | Create a new operator account for your organisation |

#### Multi-Factor Authentication (MFA)

If MFA is enabled, you will be prompted for a 6-digit code from your authenticator app (Google Authenticator, Authy, 1Password, etc.) after your password is accepted.

MFA codes refresh every 30 seconds. If your login fails, wait for the next code and try again.

#### Redirect After Login

If you were sent a direct link to an incident or page, ShieldDesk will redirect you there automatically after login.

---

### First-Time Onboarding

Click **"Setting up a new SOC team? Follow Guided Fleet Onboarding"** on the login screen.

The 4-step wizard guides you through:

| Step | What Happens |
|------|--------------|
| **1. Org Setup** | Name your organisation and choose your compliance baseline |
| **2. Enrol Endpoints** | Run the ShieldDesk agent on your servers, workstations, and VMs |
| **3. MFA Setup** | Scan a QR code to enable MFA for your admin account |
| **4. Launch** | Confirm setup and open the SOC dashboard |

#### Enrolling an Endpoint

Run the installer on each machine you want to monitor:

**Linux / macOS:**

```bash
curl -sSL https://control.shielddesk.io/install.sh | sudo bash -s -- \
  --control-plane "https://control.shielddesk.io" --token "YOUR_ENROL_TOKEN"
```

**Windows (PowerShell):**

```powershell
Invoke-WebRequest -Uri "https://control.shielddesk.io/install-windows.ps1" `
  -OutFile "install.ps1"; .\install.ps1 -EnrollToken "YOUR_ENROL_TOKEN"
```

The agent appears in your **Fleet and Host** dashboard within a few minutes.

---

## 3. Navigating the Platform

The top navigation bar gives you access to all modules:

```
ShieldDesk | Incident Queue | Mitigation Plans | Task Board | Fleet and Host
           | Security Scanner | Threat Engine | ISO 27001 Audit | Risk Scorecard
                                              [Approvals]     [Health Indicators]
```

### Health Indicators (top-right)

Live status dots show the state of backend services:

| Indicator | What it means |
|-----------|---------------|
| **DB** | PostgreSQL database is connected and accepting queries |
| **Supabase** | Cloud auth and storage is reachable |
| **Ollama** | Local AI language model is loaded and responding |
| **AI Engine** | Python threat-analysis service is online |

A grey dot means that service is temporarily unreachable. ShieldDesk continues in degraded mode with a visible warning.

### Approvals Button

Shows a red badge when security actions are pending human sign-off. Click it to review and approve or reject. See [Section 14](#14-approval-workflow) for details.

---

## 4. Your Role and What You Can Do

Your administrator assigns you a role when your account is created. Higher roles inherit all permissions from roles below them.

| Role | Who it is for | What they can do |
|------|---------------|------------------|
| **Viewer** | Executives, auditors | Read-only: view incidents and CVE intelligence |
| **Analyst** | Junior SOC analysts | Investigate incidents, read CVEs, approve Tier 1 containment |
| **Responder** | Senior SOC engineers | All Analyst actions + Tier 2 (host isolation, patching) |
| **Super Admin** | SOC managers / team leads | Full team management, Tier 1-3 approvals (no cross-tenant) |
| **System Admin** | Platform administrators | All actions + cross-tenant visibility for multi-org oversight |

> If you see a **403 Forbidden** message, your role does not permit that action. Contact your Super Admin.

---

## 5. Incident Queue

**URL:** `/` (main dashboard)

This is your primary workspace. It shows every active security incident for your organisation.

### Layout

- **Right sidebar** — Incident Queue: scrollable list of all active incidents for your tenant
- **Left panel** — Incident Detail: full investigation view for the selected incident

### The Incident Queue Sidebar

Each card shows:

- **Incident Code** (e.g. `INC-1042`) — a unique reference ID
- **Severity badge** — CRITICAL (red), HIGH (amber), MEDIUM (grey), LOW (green)
- **Title** — one-line summary of the threat
- **Status** — `open`, `investigating`, `resolved`, or `closed`
- **Detection time**

**Filtering:** Use the pill buttons (`ALL` / `CRITICAL` / `HIGH` / `MEDIUM`) to filter the list instantly.

**Selecting:** Click any card to load its detail. The active card gets a green border.

### Incident Detail Panel

#### Header Strip

- Incident Code and Severity Badge
- Current Status (updates live as investigation progresses)
- Action buttons:
  - **Investigate with AI** — opens AI chat pre-loaded with this incident
  - **Plan Mitigation** — asks AI to generate a full remediation plan
  - **View Plans** — jumps to the Mitigation Plans page
  - **Inspect Mitigation Plan** — direct link to an existing plan (shown when one exists)

#### Incident Title and Description

Plain-English summary of what happened, which systems were involved, and initial attack indicators.

#### Impacted Assets

Every server, workstation, or cloud instance confirmed within the blast radius. Shows hostname and asset type (e.g. `edge-router-01` / `network_device`).

#### Attack Timeline

Chronological event log, oldest to newest, so you can trace the full kill chain. Each entry shows a precise timestamp and what was observed.

#### Linked Threat Intelligence

When a CVE is correlated with the incident:

- **CVSS Score** — severity (e.g. 7.5 / HIGH)
- **Autonomy Gate** — which approval tier is required before containment
- **CWE Classification** — root vulnerability class (e.g. CWE-400 Resource Exhaustion)
- **Remediation SLA** — your organisation's time limit for this severity
- **Deep Threat Analysis** — click to have the AI explain the CVE in plain English

---

## 6. Mitigation Plans

**URL:** `/dashboard/plans`

AI-generated remediation plans follow the **3-Horizon framework**:

| Horizon | Timeframe | Focus |
|---------|-----------|-------|
| **H1 — Containment** | Hours | Isolate hosts, revoke sessions, block IPs |
| **H2 — Eradication** | Days | Patch systems, rotate credentials, scan for persistence |
| **H3 — Recovery** | Weeks | Restore operations, harden defences, update runbooks |

Click any plan to view individual tasks, approval requirements, and progress. To create a plan, click **"Plan Mitigation"** from the Incident Queue — the AI generates it automatically.

---

## 7. Task Board

**URL:** `/dashboard/tasks`

Tracks every action item across all mitigation plans.

### Task Lifecycle

```
Draft  →  Pending Approval  →  Approved  →  In Progress  →  Completed
                           ↘  Rejected
```

### Creating a Task

Analysts and above can create tasks:

1. Click **New Task**
2. Select a tier (Tier 1 / 2 / 3) based on the action's risk
3. Describe the action and assign it to a team member
4. Submit — Tier 2 and 3 tasks enter the approval queue automatically

> **Viewers cannot create tasks.** If "New Task" is absent or greyed out, your role is Viewer.

### Task Tiers

| Tier | Risk Level | Who Must Approve |
|------|------------|-----------------|
| **Tier 1** | Low-risk, reversible | Analyst or above |
| **Tier 2** | Host isolation, patching | Responder or above |
| **Tier 3** | Break-glass / destructive | Super Admin or above |

---

## 8. Fleet and Host Management

**URL:** `/dashboard/fleet`

Shows every enrolled endpoint agent.

### Agent Cards

Each card displays:

- **Hostname** and **IP address**
- **OS / Platform** (Windows Server, Ubuntu, macOS, etc.)
- **Agent Status** — `online`, `offline`, `compromised`, or `isolated`
- **CPU and Memory** — current utilisation
- **Last Seen** timestamp

Agents marked **COMPROMISED** or **ISOLATED** are highlighted red. Investigate immediately.

### Issuing Remote Commands

Click an agent to open its detail panel. In the **Command Panel**:

1. Choose a command (e.g. `take_safety_snapshot`, `isolate_host`, `run_vulnerability_scan`)
2. Select a **Tier** — determines the approval requirement
3. Optionally enter a **Token ID** to reference a pre-issued approval token
4. Click **Execute Command**

Results appear in the **Command Log** with timestamp, status (`succeeded` / `failed` / `executing`), and full output.

### Kill Switch

Emergency network isolation of **all enrolled agents** simultaneously. This is a Tier 3 action requiring Super Admin approval.

> **Warning:** Engaging the kill switch disconnects every endpoint from the network. Use only during a confirmed active breach.

---

## 9. Security Scanner

**URL:** `/dashboard/scanner`

Runs on-demand vulnerability assessments.

1. Select a **scan profile** (Quick Scan, Full CVE Scan, Compliance Check)
2. Choose the **target scope** — all agents, a group, or individual hosts
3. Click **Start Scan**

Results show CVE IDs, CVSS severity, affected package and version, and a recommended action with a link to generate a mitigation plan.

**Severity colour coding:**

- **Critical** — patch immediately; likely actively exploited in the wild
- **High** — patch within 7 days per your SLA
- **Medium** — patch in next maintenance window
- **Low / Info** — monitor; patch at your discretion

---

## 10. Threat Detection Engine

**URL:** `/dashboard/threats`

Four tabs:

### 3-Sigma ML Anomaly Engine

Models a statistical baseline (Gaussian distribution) per metric per tenant. If any metric exceeds 3 standard deviations above normal (3σ), an alert fires automatically.

**Tracked metrics:**
- Failed authentication rate (brute-force indicator)
- Network egress bandwidth (data exfiltration indicator)
- Process spawn rate (malware execution indicator)

Each metric card shows current value vs. threshold, a progress bar (red when anomalous), and the baseline mean (μ) and deviation (σ).

**Status:** `NOMINAL` (green) or `SPIKE ANOMALY` (red — threshold exceeded, alert dispatched).

Click **"Simulate Anomaly Burst"** to test your alerting integrations. Click **"Reset Baseline"** to restore normal state.

### YARA Malware Rules

Scan file artefacts and process memory for known malware signatures. Cards show rule name, category, severity, and daily match count.

### Sigma Behavioral Detection

Detect suspicious log patterns such as lateral movement, privilege escalation, and living-off-the-land attacks. Cards show title, severity, detection logic in plain English, log source, and daily match count.

### gRPC Ingestion and HMAC Webhooks

**Ingest pipeline:** mTLS v1.3 with X.509 certificates, 10,000 events/min per tenant, automatic PII scrubbing before storage.

**Webhook dispatcher:** Click **"Dispatch Test Webhook"** to send a signed payload to Slack, PagerDuty, or any configured endpoint. All payloads carry an HMAC-SHA256 signature. Failed deliveries retry with exponential backoff.

---

## 11. ISO 27001 Compliance Audit

**URL:** `/dashboard/compliance`

Tracks your posture against ISO/IEC 27001:2022 controls, grouped by clause (A.5 Organisational Controls, A.8 Technological Controls, etc.).

| Status | Meaning |
|--------|---------|
| Compliant | Evidence collected; control implemented |
| Partial | Some evidence; gaps need addressing |
| Non-Compliant | Control not yet implemented |
| Pending Review | Awaiting auditor sign-off |

Use the **horizon filter** to view controls relevant to your current remediation phase (H1, H2, or H3).

Click **"Export Audit Evidence"** to download a structured JSON report suitable for external auditors or GRC platforms.

> **Tip:** Export before every quarterly audit review to capture a point-in-time snapshot.

---

## 12. Risk Scorecard

**URL:** `/dashboard/risk-scorecard`

An executive-level view of your security posture in business language.

| Metric | What it shows |
|--------|--------------|
| **Overall Risk Score** | Composite 0-100 score (incident severity + CVEs + compliance gaps) |
| **Mean Time to Detect (MTTD)** | Average time from attack start to ShieldDesk alert |
| **Mean Time to Respond (MTTR)** | Average time from alert to containment |
| **Estimated Risk Exposure** | Financial impact estimate based on open incidents and asset criticality |
| **Compliance Coverage** | Percentage of ISO 27001 controls with satisfactory evidence |

Trend arrows (up / down) show week-over-week movement. Click **"Print / Export PDF"** for board reports.

---

## 13. AI Assistant

Available as a floating chat panel on every page in the platform.

### Opening the Chat

- Click the **chat icon** in the bottom-right corner, or
- Click **"Investigate with AI"** or **"Plan Mitigation"** from the Incident Queue (pre-loads context automatically)

### What You Can Ask

The AI understands natural language. Examples:

```
Investigate INC-1042 and tell me what happened
Generate a mitigation plan for the VPN exploitation
Analyze CVE-2024-3400 and explain the risk to our environment
What is the blast radius if CVE-2020-6240 hits our fleet?
Show me all critical incidents from this week
```

### Autonomy Tiers

When the AI recommends an action it assigns a tier:

| Tier | Label | What happens |
|------|-------|--------------|
| **Tier 1** | Auto-Containment | Queued for execution after Analyst confirmation |
| **Tier 2** | Human Sign-off Required | Sent to Approvals; a Responder or above must approve |
| **Tier 3** | Break-Glass | Super Admin must explicitly approve before execution |

### AI Guardrails

The AI is hardened against manipulation:

- Refuses prompt injection and role-override attempts
- Will not output credentials, private keys, or PII
- All AI-generated actions require human approval before affecting real systems

---

## 14. Approval Workflow

ShieldDesk enforces **human-in-the-loop** for all consequential actions. No command, isolation, or network change executes without a qualified human approving it first.

### How It Works

1. An action is proposed (by the AI, an analyst, or an automated rule)
2. An approval token is created — nothing executes yet
3. The red badge on the **Approvals** button increments
4. The reviewer clicks Approvals to open the modal
5. The reviewer approves or rejects with a justification
6. The decision is written to an immutable audit trail

### Who Can Approve What

| Token Tier | Minimum Role Required |
|------------|----------------------|
| Tier 1 | Analyst |
| Tier 2 | Responder |
| Tier 3 | Super Admin |

### The Approval Modal

Shows:

- Action type and the targeted agent or host
- Who proposed the action
- Tier and justification
- The exact JSON payload that will be sent to the fleet agent
- Approve and Reject buttons

---

## 15. Account and Session Security

### Session Management

- Sessions are stored in a cryptographically signed, HttpOnly cookie (`shielddesk_session`)
- Tampered tokens are immediately rejected — sessions cannot be forged
- Default idle timeout: 8 hours
- Use **Sign Out** from the user menu to invalidate your session server-side

### Multi-Factor Authentication (MFA)

MFA is strongly recommended for all accounts and required for Responder roles and above.

1. Request setup via your administrator
2. Scan the QR code with your authenticator app
3. Enter the 6-digit code to confirm setup

### Passwords

- Minimum 12 characters including uppercase, lowercase, a number, and a special character
- Stored using `scrypt` (memory-hard hash) — your plaintext password is never stored or logged

---

## 16. Glossary

| Term | Definition |
|------|-----------|
| **Autonomy Gate** | The tier-based approval requirement for an AI-recommended action |
| **Blast Radius** | Assets affected or potentially affected by a vulnerability or incident |
| **CVE** | Common Vulnerabilities and Exposures — a standard security flaw ID |
| **CVSS** | Common Vulnerability Scoring System — a 0-10 severity score |
| **CWE** | Common Weakness Enumeration — the root class of a flaw |
| **gRPC** | Protocol for agent-to-server communication, encrypted with mTLS |
| **HMAC** | Hash-based Message Authentication Code — a cryptographic webhook signature |
| **ISO 27001** | International standard for information security management systems |
| **Kill Switch** | Emergency action that simultaneously isolates all enrolled agents |
| **mTLS** | Mutual TLS — both agent and server verify each other via certificates |
| **NATS** | Message bus carrying events from endpoints to the detection engine |
| **PII** | Personally Identifiable Information — automatically redacted before storage |
| **RBAC** | Role-Based Access Control — permissions are tied to your assigned role |
| **Sigma Rule** | Vendor-neutral format for detecting suspicious log patterns |
| **SOC** | Security Operations Centre |
| **SLA** | Service Level Agreement — the time limit for remediating a finding |
| **Tenant** | Your organisation's isolated workspace in ShieldDesk |
| **TOTP** | Time-based One-Time Password — 6-digit code from your authenticator app |
| **YARA Rule** | Pattern-matching rule for detecting malware in files or process memory |
| **3σ (Three-Sigma)** | Statistical threshold: 3 standard deviations above baseline — used to flag anomalies |

---

## 17. Getting Help

The fastest help is the **AI assistant** — ask it anything about your environment or the platform.

### Common Issues

| Issue | Solution |
|-------|---------|
| Login fails | Check credentials; MFA codes refresh every 30 seconds — wait for the next one |
| Approvals badge not showing | Your role may not be in the approval chain; contact your Super Admin |
| Incident queue is empty | All incidents may be resolved, or a severity filter is active — reset to ALL |
| Agent shows as "offline" | The host may be powered off; check it directly |
| 403 Forbidden error | Your role lacks permission for that action; contact your Super Admin |
| AI chat unresponsive | Ollama or AI Engine health dot may be grey; contact your administrator |
| Compliance export fails | Ensure the `DATABASE_URL` environment variable is configured correctly |

### Reporting a Security Vulnerability

Report platform security issues directly to your system administrator or the Mints Global security team. Do not post security issues in public channels or community forums.

---

*ShieldDesk is a product of Mints Global. This document is intended for authorised users of the platform only.*
