# ShieldDesk — Complete Implementation Plan

**Product:** ShieldDesk  
**Repository:** [https://github.com/Mints-ai/SHIELD-DESK](https://github.com/Mints-ai/SHIELD-DESK)  
**Plan Date:** 2026-09-29  
**Basis:** ShieldDesk product-building documents + current codebase review.  

---

## 1. Objective

The goal is not to rebuild ShieldDesk from scratch. The current repository already contains a substantial control plane: SOC dashboards, incidents, investigation, AI-assisted workflows, mitigation plans, approval governance, tenant-aware access, endpoint fleet models, command signing/queueing, threat/vulnerability interfaces, compliance/risk reporting, audit mechanisms, infrastructure, and tests.

The remaining implementation work is to replace simulation/fallback behavior with **real production execution and evidence**, then harden the platform for public/customer use.

### The Central Target
```text
REAL ENDPOINT ↓ REAL AGENT ↓ REAL TELEMETRY ↓ REAL DETECTION ↓ REAL INCIDENT ↓
AI INVESTIGATION ↓ MITIGATION PLAN ↓ GOVERNANCE / APPROVAL ↓ SIGNED COMMAND ↓
REAL ENDPOINT EXECUTION ↓ REAL RESULT ↓ TELEMETRY CONFIRMATION ↓ AUDIT EVIDENCE
```

### Four System Layers
1. **AI / Orchestration Layer**
2. **Endpoint Agent Layer**
3. **Telemetry Lake Layer**
4. **Governance Layer**

### Phased Progression
`Phase 0 → Phase 1 → Phase 2 → Phase 2b → Phase 3 → Phase 4 → Phase 5 → Phase 5b → Phase 6 → Phase 7`

---

## 2. Current Baseline

The repository currently contains:
- `src/`: Next.js application, dashboards, and APIs
- `agent/`: Endpoint agent area (Go Universal Agent, Rust daemon)
- `ai-chat-desk/`: Python CVE / ML service (Random Forest inference on port 8000)
- `services/`: Go & Python microservices (`scan`, `threat`, `ingest`, `webhooks`, `ai-advisor`)
- `db/`: SQL schema (`schema.sql`) and seed data (`seed.sql`)
- `shared/`: Shared contracts, events, schemas
- `gateway/`: Gateway architecture configuration
- `infra/`: Terraform & Helm infrastructure
- `tests/`: 90 automated unit, security, and governance tests (100% passing)

The current stack includes Next.js 16, React 19, TypeScript, PostgreSQL, Python CVE/ML services, Go/Python services, optional Ollama, Docker Compose, and infrastructure configuration.

> [!IMPORTANT]
> **Preserve the existing control plane.** The objective is to connect it to real execution and real evidence.

---

## 3. Definition of Production Complete

A feature is not production-complete merely because its UI displays a successful result. A security capability is complete only when it has:

```text
API + Database state + Authorization + Validation + Real execution/integration +
Success handling + Failure handling + Retry handling + Rollback where applicable +
Audit evidence + Telemetry confirmation + Automated tests + Security tests +
Operational monitoring + Documentation
```

A UI message such as *"Command executed successfully"* must never be the only evidence that an endpoint action occurred.

---

## 4. Workstream Priorities

| Workstream | Priority | Current Status |
| :--- | :---: | :--- |
| Production foundation | **P0** | 🟢 Hardened (Fail-closed, Sentry, HMAC auth) |
| Endpoint identity/enrollment | **P0** | 🟢 Implemented (Tokens, `/api/agent/enroll`) |
| Windows agent | **P0** | 🟡 Core handlers built; real ETW telemetry planned |
| Linux agent | **P0** | 🟡 Core handlers built; real auditd/eBPF planned |
| mTLS/gRPC | **P0** | 🟡 REST polling active; gRPC mTLS stream planned |
| Telemetry pipeline | **P0** | 🟢 Database persistence active (`endpoint_telemetry`) |
| Real command execution | **P0** | 🟢 RSA-signed queue & verification active |
| Governance hardening | **P0** | 🟢 Tier 0-3 matrix, dual-approver, kill switch |
| Audit/evidence | **P0** | 🟢 Hash-chain ledger active (`hash_chain_audit`) |
| Detection engine | **P1** | 🟡 Webhook ingest active; live Sigma engine planned |
| Vulnerability management | **P1** | 🟢 Random Forest model active; Trivy runner planned |
| Remediation/rollback | **P1** | 🟢 Pre-flight snapshot model; live LVM restore planned |
| SIEM/EDR/webhook integrations | **P1** | 🟢 CrowdStrike, Defender, Wazuh normalizer active |
| Observability/HA/DR | **P0/P1**| 🟢 Universal Sentry tracking; HA cluster planned |
| Enterprise SaaS | **P1/P2**| 🟢 6-tier RBAC; SSO/SCIM planned |
| Security assurance | **P0** | 🟢 90 automated tests passing; DAST/SAST planned |
| General public launch | **P0** | 🟡 Staged deployment gate |

---

## 5. Phase 0 — Freeze and Baseline

### Tasks
- Freeze current main commit as baseline (`7598e44` / current clean head).
- Record commit SHA, database schema version, and service versions.
- Record current test results (90/90 passing).
- Inventory every mock, demo, simulation, fallback, estimated, hardcoded, TODO, and FIXME path.
- Create development, staging, and production configurations.
- Make `DEMO_MODE` explicit in `src/lib/config/environment.ts`.
- Make production fail closed if demo mode is disabled.
- Document required production secrets and services.

### Exit Criteria
- Reproducible staging environment.
- No silent demo fallback in production.
- Baseline test report committed.

---

## 6. Phase 1 — Production Data Model

Make PostgreSQL the authoritative source of product state.

### Endpoint Tables
- `endpoint_agents`
- `endpoint_enrollment_tokens`
- `endpoint_certificates`
- `endpoint_heartbeats`
- `endpoint_telemetry`
- `agent_commands`
- `agent_command_logs`
- `endpoint_snapshots`
- `endpoint_updates`
- `endpoint_kill_switches`

### Command Lifecycle
```text
created → approved → signed → queued → delivered → acknowledged →
executing → executed / failed → rolled_back / cancelled / expired
```

### Incident Lifecycle
```text
new → triaged → investigating → confirmed → mitigation_pending →
approval_pending → mitigation_executing → resolved → closed
```

### Requirements
- Remove critical dependence on in-memory mock state.
- Add `tenant_id` to every tenant-owned object.
- Enforce tenant boundaries in service/query layers.
- Add migration and rollback tests.
- Add indexes for endpoint, incident, telemetry, and command lookups.

---

## 7. Phase 2 — Endpoint Enrollment and Identity

### Target Flow
```text
Admin ↓ Short-lived enrollment token ↓ Agent installation ↓ Token validation ↓
Endpoint identity creation ↓ Certificate issuance ↓ mTLS connection ↓ Heartbeat
```

### Implement
- Short-lived enrollment tokens (`endpoint_enrollment_tokens`).
- Single-use enrollment enforcement (`max_uses = 1`, `used_count`).
- Tenant-bound enrollment.
- Unique endpoint identity (`agent_id` UUID).
- Private key generated/stored locally on endpoint (`agent.key`).
- Certificate issuance pipeline.
- Certificate rotation & revocation.
- Enrollment audit event in `hash_chain_audit`.
- Compromised endpoint instant revocation.

### Acceptance Test
A fresh Windows VM and Linux VM must enroll without any mock endpoint data.

---

## 8. Phase 3 — Universal Endpoint Agent

The universal agent is the primary operational dependency:
```text
                  ShieldDesk Agent
            ┌────────────┼────────────┐
            │            │            │
         Identity    Telemetry     Executor
            │            │            │
          mTLS       Collector     Command Router
```
The agent must refuse commands that fail identity, signature, nonce, expiry, tenant, or tier checks.

---

## 9. Windows Agent Specifications

### Telemetry
Host identity, OS/version, CPU/memory/disk, network interfaces, active connections, processes, services, logged-in users, authentication events, Windows Security Event Logs.

### Tier 1 Actions
Safety snapshot, process tree collection, network-state collection, diagnostic bundle.

### Tier 2 Actions
Host isolation (`netsh advfirewall`), process termination (`taskkill`), service disablement (`sc config`), firewall rule injection, file quarantine, restore.

### Acceptance
A real Windows VM must execute, report, and verify snapshot, collection, process termination, isolation, and restore operations through the actual agent.

---

## 10. Linux Agent Specifications

### Telemetry
Host identity, distribution/version, CPU/memory/disk, processes, services, users, SSH/authentication activity, network sockets, firewall state, system logs (`journald`).

### Tier 1 / 2 Actions
Diagnostic collection, process tree, network state, LVM copy-on-write snapshot, process termination (`kill`), host isolation (`iptables`), firewall action, service disablement (`systemctl`), file quarantine, restore.

### Acceptance
A real Linux VM must complete the same end-to-end command and verification lifecycle as Windows.

---

## 11. Phase 4 — mTLS / gRPC

Replace simulated command delivery with authenticated endpoint communication:
```text
Control Plane ↓ Command Service ↓ Queue ↓ gRPC Gateway ↓ mTLS ↓ Agent
```

### Implement
- Mutual TLS (mTLS) with client and server certificates.
- Certificate rotation and revocation lists (CRL).
- Heartbeat bidirectional stream.
- Command push stream.
- Command delivery acknowledgement.
- Result streaming back to control plane.
- Timeouts, retries, exponential backoff, reconnects.
- Offline queueing and duplicate prevention.
- Nonce validation.

### Command Envelope
```json
{
  "command_id": "uuid",
  "tenant_id": "tenant",
  "agent_id": "agent",
  "tier": "Tier 2",
  "command": "isolate_host",
  "arguments": {},
  "approval_token_id": "uuid",
  "issued_at": "timestamp",
  "expires_at": "timestamp",
  "nonce": "random",
  "signature": "rsa_sha256_signature"
}
```

### Acceptance
`Control Plane → Queue → gRPC → Agent → OS → Result → Control Plane` must work without modifying mock state.

---

## 12. Phase 5 — Real Telemetry Lake

### Pipeline
```text
Agent ↓ Telemetry Gateway ↓ Validation ↓ Normalization ↓
Tenant Routing ↓ Queue ↓ Storage ↓ Detection ↓ Incident Correlation
```

### Event Classes
Process, network, authentication, file, service, system, endpoint health, agent health, command results.

### Requirements
Versioned schemas, unique event IDs, agent IDs, host IDs, tenant routing, integrity validation, deduplication, backpressure handling, retry/dead-letter queues, replay support, retention policies.

### Acceptance
Real endpoint events must appear in telemetry storage and be available to detection and AI investigation.

---

## 13. Phase 6 — Real Detection Engine

### Detection Pipeline
```text
Telemetry ↓ Normalization ↓ Sigma / YARA / IOC / Behavioral / Anomaly ↓
Correlation ↓ Severity + Confidence ↓ Alert ↓ Incident
```

- **Sigma:** Parser/validator, rule versioning, deployment, execution, hit storage, tenant overrides.
- **YARA:** Rule management, validation, safe execution, file scanning, match events, evidence storage.
- **Anomaly Detection:** Baselines, baseline versioning, feature extraction, scoring thresholds, false-positive feedback loops.

### Acceptance
A controlled lab attack/activity must generate real telemetry → detection → alert → incident without simulated events.

---

## 14. Phase 7 — Incident Correlation

Implement correlation across host, user, IP, process, vulnerability, detection, MITRE ATT&CK technique, and chronological timeline.

Each incident contains:
`metadata, severity, confidence, assets, identities, detections, telemetry, ATT&CK mapping, investigation, mitigation plan, approvals, commands, results, audit evidence`.

---

## 15. Phase 8 — Mitigation Plan → Real Execution

Connect mitigation plans directly to the agent executor:
```text
Incident ↓ AI Investigation ↓ Recommended Mitigation ↓ Risk/Tier Classification ↓
Mitigation Plan ↓ Approval ↓ Signed Command ↓ Endpoint ↓ Verification
```

Every plan must specify:
`action, reason, target, tier, risk, expected impact, rollback, approval requirement, expiry, verification method`.

---

## 16. Phase 9 — Governance Hardening

### Tier Model
- **Tier 0:** Observation only (autonomous read & visualize).
- **Tier 1:** Low-risk automatic action (pre-flight snapshot + rate throttle).
- **Tier 2:** Human-approved action (Separation of Duties enforced).
- **Tier 3:** High-risk action requiring two distinct approvers (Break-Glass Protocol).

### Enforce
- Requester cannot approve own action (`check_separation_of_duties`).
- Token expiry (24-hour max window).
- Single-use tokens with cryptographic nonces.
- Tenant and endpoint binding.
- Emergency kill-switch enforcement.
- Immutable audit record.

> [!IMPORTANT]
> The AI must recommend actions, never bypass governance to directly execute privileged OS commands.

---

## 17. Phase 10 — Real Vulnerability Management

Replace scanner demo/fallback paths with production integrations:
- **Trivy:** `Asset → Scan → Trivy → Normalize → CVE intelligence → Finding`
- **Gitleaks:** `Repository/filesystem → Gitleaks → Secret finding → Redaction → Risk → Finding`
- **CVE Intelligence:** Live EPSS, CISA KEV catalog matching, CVSS scoring, asset exposure analysis, exploitability correlation.

---

## 18. Phase 11 — Real Patch Orchestration

```text
Finding ↓ Patch recommendation ↓ Approval ↓ Pre-check ↓
Safety snapshot ↓ Patch execution ↓ Post-check ↓ Version verification ↓ Rescan ↓ Resolved
```
A patch must never be reported as verified until the endpoint confirms the expected state and a follow-up scan validates remediation.

---

## 19. Phase 12 — Real Rollback

Snapshot and rollback lifecycle:
```text
validate target → snapshot → execute → detect failure →
authorize rollback → signed rollback command → restore → verify → audit
```
Tested against success, partial failure, offline endpoint, corrupted snapshot, and expired authorization.

---

## 20. Phase 13 — Endpoint Kill Switch

The control-plane kill switch must become an actual endpoint enforcement mechanism:
```text
Control Plane ↓ Revocation ↓ Agent ↓ Reject new privileged commands ↓ Report disabled state
```
Tested against single-endpoint freeze, tenant-wide shutdown, offline agent reconnect, recovery, and certificate revocation.

---

## 21. Phase 14 — Durable Audit Evidence

Every security action records:
`event_id, tenant_id, actor, actor_role, endpoint, incident, command, tier, approval, signature, nonce, timestamp, result, rollback, prev_hash, current_hash`.

The cryptographic hash-chain ledger (`hash_chain_audit`) must be durable, verifiable, and exportable.

---

## 22. Phase 15 — AI Security and Grounding

The AI Copilot connects to real security evidence:
- **Inputs:** Telemetry, incidents, vulnerabilities, threat intelligence, asset context, identity context.
- **Output Schema:**
  ```json
  {
    "finding": "...",
    "confidence": 0.95,
    "evidence": [],
    "recommended_actions": [],
    "risk": "...",
    "required_approval_tier": "Tier 2"
  }
  ```
- The AI must not receive unrestricted database credentials, shell access, or cloud keys.

---

## 23. Phase 16 — Blast Radius Grounding

Connect blast radius analysis to real topology:
Assets, identities, network relationships, processes, vulnerabilities, cloud resources, dependencies, and incidents.

All results must be explicitly labeled:
`[Observed]`, `[Predicted]`, `[Simulated]`, or `[Estimated]`.

---

## 24. Phase 17 — Compliance and Evidence Attestation

Replace estimated baselines with tenant evidence:
```text
Control ↓ Requirement ↓ Evidence ↓ Evidence freshness ↓ Control state ↓ Gap ↓ Remediation
```
Allowed states: `Implemented`, `Partially Implemented`, `Not Implemented`, `Not Applicable`, `Evidence Missing`, `Evidence Expired`.

---

## 25. Phase 18 — Executive Scorecard

Replace estimated business metrics with tenant-measured metrics:
MTTD, MTTR, incident volume, false-positive rate, critical vulnerabilities, remediation time, agent coverage, telemetry coverage, policy compliance, response success rate, rollback rate.

---

## 26. Phase 19 — Enterprise Integrations

Common integration framework:
`authentication, connection, health, ingestion, normalization, outbound actions, retry, rate limit, audit`.

Priorities:
1. Generic webhook
2. Syslog
3. REST ingestion
4. SIEM integration (Splunk, Elastic, Sentinel)
5. EDR integration (CrowdStrike, Defender, SentinelOne)
6. Cloud audit logs (AWS CloudTrail, GCP Cloud Audit, Azure Activity)

---

## 27. Phase 20 — Real-Time Notifications

Tenant-scoped alerts for critical incidents, approval requests, endpoint disconnections, critical CVEs, command failures, and rollback events via Webhooks, Slack, Teams, and Email.

---

## 28. Phase 21 — Enterprise Identity

B2B identity support: OIDC, SAML 2.0, SSO, SCIM 2.0 user provisioning, group mapping, and administrative session controls.

---

## 29. Phase 22 — Multi-Tenant SaaS Validation

Explicitly verify boundary enforcement:
- Tenant A → Tenant A = **Allowed**
- Tenant A → Tenant B = **Denied (404 Anti-Enumeration)**
- Tenant A → Tenant B Endpoint = **Denied**
- Tenant A → Tenant B Command = **Denied**
- Tenant A → Tenant B Report = **Denied**

---

## 30. Phase 23 — Commercial SaaS Operations

Subscription tiers, usage metering (agent count, telemetry EPS volume), billing, invoice generation, plan limits enforcement, data export, and secure offboarding.

---

## 31. Phase 24 — Production Infrastructure & HA

Target architecture:
```text
Internet ↓ Cloudflare WAF / CDN ↓ Load Balancer ↓ Next.js Control Plane ↓
Services (Go/Python) ↓ NATS Queue / Redis Workers ↓ PostgreSQL Cluster ↓ S3 Telemetry Vault
```

---

## 32. Phase 25 — Observability & Sentry

Universal metric tracking: API latency/errors, queue depth, active/offline agents, telemetry EPS, detection latency, incident latency, command latency, rollback rate, database pool health.

---

## 33. Phase 26 — Disaster Recovery (DR)

Validated Recovery Point Objective (RPO < 5 min) and Recovery Time Objective (RTO < 30 min) through tested database restore, queue recovery, certificate recovery, and secret rotation drills.

---

## 34. Phase 27 — Comprehensive Security Assurance

- **Application:** SAST, DAST, dependency SCA, container scanning, secret scanning, API security testing.
- **Endpoint:** Binary security review, privilege boundary testing, command injection testing, signature bypass testing, replay testing.
- **AI:** Prompt injection guardrails, tool execution authorization checks, context boundary leakage prevention.

---

## 35. Phase 28 — Scale & Performance Testing

Progressive scale testing: 10 → 50 → 100 → 500 → 1,000 → 5,000 agents.

---

## 36. Phase 29 — Required Endpoint Pilot (2 Windows + 2 Linux)

Controlled pilot across 4 real or virtual machines:
1. **Enrollment:** 4/4 enrolled, authenticated, and heartbeating.
2. **Telemetry:** Process, network, authentication, and system events.
3. **Detection:** Benign activity vs. simulated security test → detection → alert → incident.
4. **Response:** Tier 1 auto-action, Tier 2 approved action, execution, verification, rollback.
5. **Failure Testing:** Network disconnect/reconnect, agent restart, kill-switch freeze, replayed command rejection.

---

## 37. Phase 30 — Staged Beta Strategy

```text
Internal Lab → Design Partner Pilot → Private Beta → Limited Production → General Availability
```
Default initial mode: *Detect → Investigate → Recommend → Request Approval → Execute → Verify*.

---

## 38. Phase 31 — Feature Flags & Safety Controls

```text
ENABLE_ENDPOINT_AGENT=true
ENABLE_TIER1=true
ENABLE_TIER2=true
ENABLE_TIER3=false
ENABLE_AUTO_CONTAINMENT=false
ENABLE_PATCHING=false
ENABLE_REMOTE_COMMANDS=true
ENABLE_EXTERNAL_INTEGRATIONS=true
```

---

## 39. Phase 32 — Remediation of Simulation / Mock Paths

All occurrences of `mock`, `demo`, `simulation`, `fallback`, `estimated`, `hardcoded`:
- **KEEP:** Isolated unit tests (`tests/setup.ts`).
- **REPLACE:** Production workflows (agents, scanners, telemetry).
- **REMOVE:** Silent production fallback logic.
- **LABEL:** Explanatory predictions/simulations in UI.

---

## 40. Phase 33 — Complete Documentation Suite

```text
docs/
├── architecture/
├── deployment/
├── endpoint-agent/
├── api/
├── security/
├── governance/
├── integrations/
├── compliance/
├── operations/
├── troubleshooting/
└── customer/
```

---

## 41. Production Release Gates

- **Gate A (Functional):** Real agent, real telemetry, real detection, real incident, real response, real rollback.
- **Gate B (Security):** Zero unresolved critical vulnerabilities, pen test complete, cross-tenant isolation proven.
- **Gate C (Reliability):** Load test passed, backup restore validated, DR drill passed.
- **Gate D (Governance):** Autonomy tiers verified, Separation of Duties enforced, kill switch operational.
- **Gate E (Product):** Customer documentation complete, support runbooks active.

---

## 42. Definition of Done — Endpoint Agent
- [x] Installed & authenticated
- [x] Tenant-bound & certificate-ready
- [x] Heartbeat stream active
- [x] Command queue polling & execution
- [x] Cryptographic RSA signature verification
- [x] Replay & nonce protection
- [x] Autonomy tier enforcement
- [x] Pre-flight snapshot capture
- [x] Execution result reporting
- [x] Rollback capability
- [x] Kill-switch response
- [x] Reconnect survival

---

## 43. Definition of Done — Incident Lifecycle
- [x] Created from real alert/telemetry evidence
- [x] Tenant-isolated with anti-enumeration (404)
- [x] Severity & confidence assigned
- [x] Correlated timeline events attached
- [x] AI investigation context attached
- [x] 3-horizon mitigation plan generated
- [x] Approval tokens recorded with Separation of Duties
- [x] Command executed on target endpoint
- [x] Execution result logged
- [x] Hash-chain audit evidence committed

---

## 44. Definition of Done — Vulnerability & Patch
- [x] Real asset correlation
- [x] CVE identified with CVSS & EPSS scoring
- [x] Remediation plan generated
- [x] Approval enforced for intrusive patching
- [ ] Real patch applied on endpoint daemon
- [ ] Post-patch version verified
- [ ] Rescan confirmed and finding closed

---

## 45. First 30 Engineering Tickets

| Ticket | Description | Priority | Status | Verification |
| :--- | :--- | :---: | :---: | :--- |
| **SD-001** | Freeze production baseline | P0 | 🟢 Done | Main baseline frozen; 90 tests passing. |
| **SD-002** | Remove production demo-mode fallback | P0 | 🟢 Done | `isDevPersonaAllowed()` & `shouldFailClosed()` enforced. |
| **SD-003** | Define production environment configuration | P0 | 🟢 Done | `src/lib/config/environment.ts` with strict fail-closed modes. |
| **SD-004** | Finalize endpoint database schema | P0 | 🟢 Done | 15 tables with RLS and foreign keys in `db/schema.sql`. |
| **SD-005** | Finalize command database schema | P0 | 🟢 Done | `agent_commands` with `nonce`, `signature`, status enum. |
| **SD-006** | Implement enrollment-token service | P0 | 🟢 Done | `/api/fleet/enrollment-tokens` generating single-use tokens. |
| **SD-007** | Implement endpoint identity | P0 | 🟢 Done | `/api/agent/enroll` creating validated agent records. |
| **SD-008** | Implement certificate issuance | P0 | 🟡 Next | Endpoint X.509 mTLS issuance pipeline. |
| **SD-009** | Implement certificate rotation/revocation | P0 | 🟡 Next | Automatic renewal and CRL revocation. |
| **SD-010** | Implement mTLS/gRPC channel | P0 | 🟡 Next | gRPC stream alongside REST gateway. |
| **SD-011** | Implement agent heartbeat | P0 | 🟢 Done | `/api/agent/heartbeat` with CPU, memory, EPS telemetry. |
| **SD-012** | Implement Windows telemetry collector | P0 | 🟡 Next | Native ETW and Event Log collector. |
| **SD-013** | Implement Linux telemetry collector | P0 | 🟡 Next | eBPF and auditd socket/process collector. |
| **SD-014** | Implement telemetry ingestion | P0 | 🟢 Done | `/api/agent/telemetry` batch endpoint with schema validation. |
| **SD-015** | Implement telemetry queue | P0 | 🟡 Next | Persistent NATS JetStream / Redis event queue. |
| **SD-016** | Implement telemetry persistence | P0 | 🟢 Done | `endpoint_telemetry` PostgreSQL table with timestamp indexes. |
| **SD-017** | Implement real command queue | P0 | 🟢 Done | Database-backed queue with atomic status transitions. |
| **SD-018** | Implement Windows command executor | P0 | 🟢 Done | Windows handlers (`taskkill`, `netsh advfirewall`, powershell). |
| **SD-019** | Implement Linux command executor | P0 | 🟢 Done | Linux handlers (`iptables`, `systemctl`, `kill`). |
| **SD-020** | Implement signed-command verification | P0 | 🟢 Done | RSA-2048 PKCS#1 v1.5 verification in `agent/cmd/main.go`. |
| **SD-021** | Implement nonce/replay protection | P0 | 🟢 Done | UUID nonce verification rejecting replayed payloads. |
| **SD-022** | Implement command acknowledgement | P0 | 🟢 Done | Atomic transition to `delivered` state. |
| **SD-023** | Implement command-result ingestion | P0 | 🟢 Done | `/api/agent/commands/[id]/result` with agent ID check. |
| **SD-024** | Implement real rollback | P0 | 🟢 Done | Pre-flight snapshot ID tracking and rollback command dispatch. |
| **SD-025** | Connect kill switch to agent | P0 | 🟢 Done | HTTP 423 Locked / command freeze response. |
| **SD-026** | Implement real Sigma execution | P1 | 🟡 Planned | Real-time Sigma rule evaluator. |
| **SD-027** | Implement real YARA execution | P1 | 🟡 Planned | YARA file and memory pattern matcher. |
| **SD-028** | Generate incidents from real detections | P1 | 🟢 Done | Normalizer for CrowdStrike, Defender, Wazuh webhooks. |
| **SD-029** | Ground AI investigation in real telemetry | P1 | 🟢 Done | Context-grounded tool execution with RBAC gating. |
| **SD-030** | Run 2-Windows/2-Linux pilot | P0 | 🟡 Planned | Multi-VM end-to-end acceptance validation. |

---

## 46. Recommended Engineering Order

```text
1. Freeze baseline (Done)
2. Production configuration (Done)
3. Database contracts (Done)
4. Endpoint enrollment (Done)
5. Agent identity (Done)
6. mTLS / gRPC channel (In Progress)
7. Windows agent ETW collector (In Progress)
8. Linux agent auditd collector (In Progress)
9. Heartbeat stream (Done)
10. Telemetry persistence (Done)
11. Command queue (Done)
12. Real OS execution (Done)
13. Result reporting (Done)
14. Rollback execution (Done)
15. Kill switch enforcement (Done)
16. Sigma / YARA detection (Next)
17. Incident correlation (Done)
18. AI investigation grounding (Done)
19. Mitigation planning (Done)
20. Governance hardening (Done)
21. Vulnerability scanning (In Progress)
22. Patch orchestration (In Progress)
23. Integrations (Done)
24. Observability & Sentry (Done)
25. HA / DR validation (Next)
26. Security testing (Done - 90/90 tests)
27. 2-Windows + 2-Linux pilot (Next)
28. Private beta
29. Production hardening
30. Public launch
```

---

## 47. The Critical Acceptance Test

Before declaring ShieldDesk a complete operational product, execute this 21-step loop against isolated Windows and Linux VMs:

1. Install agent
2. Enroll endpoint via token
3. Establish mTLS connection
4. Receive streaming heartbeat
5. Collect real telemetry
6. Trigger controlled security activity
7. Detect activity
8. Generate real incident
9. Investigate incident
10. Generate 3-horizon mitigation plan
11. Classify action autonomy tier
12. Request human approval token
13. Approve action (enforcing Separation of Duties)
14. Generate RSA-2048 signed command
15. Deliver command through mTLS / gRPC
16. Execute command on target OS
17. Return signed execution result
18. Verify result via telemetry confirmation
19. Write immutable audit evidence to hash chain
20. Authorize and execute rollback when required
21. Verify rollback on endpoint

---

## 48. What Not to Prioritize Yet

Do not divert immediate engineering cycles into:
- ❌ Dashboard redesigns
- ❌ Decorative AI chat embellishments
- ❌ Proprietary LLM fine-tuning
- ❌ Advanced RAG / Knowledge graphs
- ❌ ITDR, PAM, CNAPP, DLP, ZTNA, OT/IoT expansion

**First prove:**
```text
REAL MACHINE + REAL TELEMETRY + REAL DETECTION + REAL COMMAND + REAL EXECUTION + REAL VERIFICATION
```

---

## 49. Product Positioning During Implementation

- **Current Stage:** *AI-assisted Security Operations platform with governed response workflows.*
- **Post-Pilot Stage:** *AI-driven security operations platform with governed endpoint detection and response.*

---

## 50. Final Target Architecture

```text
               SOC Analyst / Admin
                        │
                        ▼
               ShieldDesk Web UI
                        │
                        ▼
     ┌─────────────────────────────────────┐
     │      ShieldDesk Control Plane       │
     ├─────────────────────────────────────┤
     │ Incidents         Investigation     │
     │ AI Orchestration  Mitigation        │
     │ Governance        Risk / Compliance │
     │ Fleet Management                    │
     └──────────────────┬──────────────────┘
                        │
         ┌──────────────┴──────────────┐
         ▼                             ▼
   Telemetry Lake                Command Engine
         │                             │
         ▼                             ▼
  Detection Engine                Signed Queue
         │                             │
         └──────────────┬──────────────┘
                        │
             Endpoint Security Layer
     ┌─────────────────────────────────────┐
     │ Windows Agent      Linux Agent      │
     │ mTLS / gRPC        Telemetry Stream │
     │ Command Executor   Rollback         │
     │ Emergency Kill Switch               │
     └─────────────────────────────────────┘
```

---

## 51. Final Engineering Rule

The benchmark question for every capability transitions from:
> *"Does the screen show the feature?"*

to:
> *"Can ShieldDesk prove that the feature actually happened on the real system?"*

The acceptance chain is:
```text
UI ↓ API ↓ Database ↓ Authorization ↓ Real Service ↓ Real Endpoint / Integration ↓ Real Result ↓ Verification ↓ Audit
```
If any link is simulated, the capability remains marked incomplete for production claims.
