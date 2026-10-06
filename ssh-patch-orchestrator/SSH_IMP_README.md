# ShieldDesk SSH Patch Orchestrator with LVM Snapshot Rollback
## Implementation Reference & Operational Guide (`SSH_IMP_README.md`)

This document serves as the implementation guide for the **ShieldDesk SSH Patch Orchestrator**. It details the Go microservice implementation, Next.js frontend integration, state machine safety guarantees, API specifications, and operational execution flows.

---

## 1. Executive Summary

The SSH Patch Orchestrator is an automated, fail-safe remediation system designed to apply security patches to Linux fleet infrastructure over SSH while guaranteeing **zero data loss** through Copy-on-Write (CoW) Logical Volume Manager (LVM) snapshots.

Unlike basic remote execution scripts, this system enforces:
- **Strict Pre-flight Checks**: Confirms OS compatibility, active LVM volume groups, CoW free space (>20%), and records pre-patch baseline versions.
- **Verification Gate Before Execution**: Enforces that no package manager or patch command can execute unless an LVM snapshot exists in an active, non-invalid (`swi-a-s---`) state.
- **Post-Patch Verification**: Does not treat `exit 0` as remediation. Performs semantic version comparison and daemon health checks to confirm vulnerability resolution.
- **Automated & Manual LVM Rollback**: Merges snapshots and handles deferred reboots cleanly if patching or validation fails.
- **Zero-Mock UI Integration**: Directly wired to the ShieldDesk Security Scanner console with real-time log streaming and manual rollback controls.

---

## 2. System Architecture

```text
                                 +-----------------------------------------------+
                                 |          ShieldDesk Web Console               |
                                 |  (Next.js 16 UI - /dashboard/scanner#patch)  |
                                 +-----------------------+-----------------------+
                                                         |
                                        HTTP JSON Proxy  | POST /api/patch/jobs
                                        (Next.js API)    | GET  /api/patch/jobs/:id
                                                         v
                                 +-----------------------------------------------+
                                 |         SSH Patch Orchestrator Engine         |
                                 |       (Go Microservice on Port 8004)          |
                                 +-----------------------+-----------------------+
                                                         |
                   +-------------------+-----------------+-------------------+
                   |                   |                                     |
                   v                   v                                     v
       +-----------------------+ +-----------------------+ +-----------------------+
       |   State Machine &     | |    SSH Connection     | |     Append-Only       |
       |  Pipeline Coordinator | |     Manager &         | |    Audit Writer       |
       |  (Strict Transitions) | |  SHA256 FP Verifier   | |   (JSONL Artifacts)   |
       +-----------+-----------+ +-----------+-----------+ +-----------------------+
                   |                         |
                   +------------+------------+
                                |
                   Target Host  | Paramiko/Crypto SSH (Port 22)
                                v
       +---------------------------------------------------------------------------+
       |                        Target Linux Host (LVM Root)                       |
       |                                                                           |
       |  1. Precheck      --> OS Detection, vgdisplay free PE check, baseline ver |
       |  2. Snapshot Gate --> lvcreate -s -L 2G -n snap_prepatch /dev/vg0/root   |
       |  3. Patch         --> apt-get install / dnf update (Allowlisted vectors)  |
       |  4. Validate      --> dpkg-query / rpm -q version readback check          |
       |  5. Rollback (Opt)--> lvconvert --merge / reboot if verification fails    |
       +---------------------------------------------------------------------------+
```

---

## 3. Directory & Codebase Structure

The orchestrator code is organized under `ssh-patch-orchestrator/`:

```text
ssh-patch-orchestrator/
├── cmd/
│   └── orchestrator/
│       ├── main.go            # Entry point: handles "server", "run", "version" subcommands
│       ├── server.go          # HTTP API Server (port 8004), in-memory job store, log streaming
│       └── cli.go             # Standalone CLI runner for direct execution
├── configs/
│   └── example.yaml           # Deployment configuration template
├── internal/
│   ├── approval/              # Human approval policy evaluator (Auto / Stage / Human Review)
│   ├── audit/                 # Append-only JSONL audit writer & in-memory stream buffer
│   ├── models/                # Domain models: Job, Asset, Plan, Audit, Snapshot, Precheck, Validation
│   ├── orchestrator/          # State machine, legal transition matrix, pipeline coordinator
│   ├── patch/                 # Controlled package managers (apt, dnf, yum adapters)
│   ├── precheck/              # Host diagnostics (OS, LVM space, network baseline)
│   ├── rollback/              # LVM snapshot merging, deferred reboot detection & restore verifier
│   ├── security/              # Shell injection prevention, strict single-quote escaping, redaction
│   ├── snapshot/              # LVM snapshot creation, lv_attr parser, verification gate
│   ├── ssh/                   # Strict crypto/ssh client, SHA256 host key fingerprint enforcement
│   └── validation/            # Semantic version comparators & daemon health checkers
├── go.mod
├── go.sum
└── orchestrator.exe           # Compiled 64-bit production binary
```

---

## 4. State Machine & Safety Invariants

The orchestrator enforces a strictly deterministic state machine (`internal/orchestrator/state.go`). Invalid transitions return immediate errors and halt the pipeline.

```text
  [DETECTED]
      │
      ▼
  [AWAITING_APPROVAL] ──(Rejected)──► [CANCELLED]
      │
      ▼
  [PRECHECKING] ──(Precheck Fail)──► [PRECHECK_FAILED] ──► [HUMAN_REVIEW]
      │
      ▼
  [READY_FOR_SNAPSHOT]
      │
      ▼
  [SNAPSHOT_CREATING] ──(Creation Fail)──► [SNAPSHOT_FAILED] ──► [HUMAN_REVIEW]
      │
      ▼
  [SNAPSHOT_VERIFIED] ◄── [VERIFICATION GATE: Patching is ONLY possible from here]
      │
      ▼
  [PATCHING] ──(Command Drop / Fail)──┐
      │                               │
      ▼                               │
  [VALIDATING] ──(Version Mismatch)───┤
      │                               │
      │ (Success)                     ▼
      │                      [ROLLBACK_REQUIRED]
      │                               │
      │                               ▼
      │                       [ROLLING_BACK]
      │                               │
      │                               ▼
      │                      [VERIFYING_RESTORE]
      │                               ├──(Verify Pass)──► [ROLLED_BACK_HUMAN_REVIEW]
      │                               └──(Verify Fail)──► [ESCALATED_URGENT]
      ▼
  [REMEDIATED]
```

### Critical Invariants Enforced:
1. **Gate to Patching**: `PATCHING` can **only** be entered from `SNAPSHOT_VERIFIED`. Attempting to patch without a verified snapshot is structurally impossible in the code.
2. **True Remediation over Exit Codes**: A successful `exit 0` from `apt` or `dnf` does not mark a job as `REMEDIATED`. Validation must query the package manager directly and confirm that `installed_version >= target_version`.
3. **No Blind Command Execution**: Raw shell string execution is prohibited. All commands are dispatched via predefined argument vectors (e.g., `["apt-get", "install", "-y", "--only-upgrade", "pkg"]`). Arguments are sanitized and single-quote escaped.
4. **No Hidden Rollback Failures**: If an LVM snapshot merge fails or the post-rollback baseline check does not match, the system transitions to `ESCALATED_URGENT` and exits with an error code to alert operators.

---

## 5. API Reference (Go HTTP Service — Port 8004)

The Go microservice runs on port `8004` and provides the following REST API endpoints:

### 1. `GET /health`
Returns orchestrator service status and version.
```json
{
  "service": "ssh-patch-orchestrator",
  "status": "ok",
  "time": "2026-10-06T12:00:00Z",
  "version": "1.0.0"
}
```

### 2. `GET /api/v1/jobs`
Lists all active and historical patch jobs managed by the runtime.

### 3. `POST /api/v1/jobs`
Creates and asynchronously launches a patch pipeline job.

**Request Body:**
```json
{
  "host": "192.168.1.50",
  "port": 22,
  "user": "ubuntu",
  "private_key_pem": "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
  "host_key_fingerprint": "SHA256:abc123xyz...",
  "package": "openssl",
  "target_version": "1.1.1f-1ubuntu2.20",
  "restart_services": ["openssl", "nginx"]
}
```

**Response (201 Created):**
```json
{
  "job_id": "job_1728212400000",
  "message": "Job accepted and running. Poll GET /api/v1/jobs/job_1728212400000 for status and logs.",
  "state": "DETECTED"
}
```

### 4. `GET /api/v1/jobs/{id}`
Returns real-time execution state, chronological command logs, and structured audit events.
```json
{
  "job": {
    "job_id": "job_1728212400000",
    "state": "REMEDIATED",
    "outcome": "REMEDIATED",
    "vulnerability_status": "FIXED"
  },
  "logs": [
    "[12:00:01] Job job_1728212400000 created: upgrading openssl on ubuntu@192.168.1.50:22",
    "[12:00:02] Establishing SSH connection to 192.168.1.50...",
    "[12:00:03] → precheck.os_detect",
    "[12:00:03]   ✓ precheck.os_detect: Ubuntu 22.04 LTS",
    "[12:00:04] → snapshot.create",
    "[12:00:05]   ✓ snapshot.create: Logical volume \"snap_prepatch_openssl\" created",
    "[12:00:06] → patch.upgrade",
    "[12:00:10]   ✓ patch.upgrade: Setting up openssl (1.1.1f-1ubuntu2.20)...",
    "[12:00:11] → validation.version_query",
    "[12:00:11]   ✓ validation.version_query: 1.1.1f-1ubuntu2.20",
    "[12:00:12] [DONE] Final state: REMEDIATED | Outcome: REMEDIATED | Vulnerability: FIXED"
  ],
  "audit": [...]
}
```

### 5. `POST /api/v1/jobs/{id}/rollback`
Triggers an emergency manual rollback for the given job.

---

## 6. Next.js Integration Layer

Next.js communicates with the Go microservice through the following authenticated API proxy routes:

1. **`src/app/api/patch/jobs/route.ts`**
   - Handles `GET` (list jobs) and `POST` (create job).
   - Validates user sessions and enforces the `cve.read` permission.
   - Forwards JSON payloads to `http://localhost:8004/api/v1/jobs`.

2. **`src/app/api/patch/jobs/[id]/route.ts`**
   - Handles `GET` (poll job state + logs) and `POST` (trigger rollback).
   - Forwards requests to `http://localhost:8004/api/v1/jobs/[id]`.

### UI Console (`src/app/dashboard/scanner/page.tsx`)
The **Patch** tab in the Security Scanner provides:
- **Service Online/Offline Badge**: Live polling of port 8004 with visual indicator.
- **SSH Credentials & Target Form**: Inputs for target host, port, SSH user, host key fingerprint, private key (PEM), target package, version, and restart services.
- **Live Terminal Console**: Polls every 2 seconds during active runs, displaying color-coded pipeline logs:
  - Yellow: `[SNAPSHOT]` operations
  - Green: `✓` success and `REMEDIATED` states
  - Red: `[ERROR]` and failed validations
  - Orange: `[ROLLBACK]` and LVM restore merges
  - Cyan: `[DONE]` state transitions
- **Emergency Rollback Action**: Dispatches an instant rollback request to the active job.

---

## 7. How to Run & Verify

### One-Command Full Stack (Recommended)
From the project root:
```powershell
npm run start:all
```
This runs `start.ps1`, which launches all 5 platform services:
1. **Ollama LLM** (Port 11434)
2. **Python CVE Brain** (Port 8000)
3. **Go Threat Engine** (Port 8003)
4. **SSH Patch Orchestrator** (Port 8004)
5. **Next.js UI Console** (Port 3000)

### Running Standalone (CLI Mode)
You can run the Go binary directly against a server without the web interface:
```powershell
cd ssh-patch-orchestrator
.\orchestrator.exe run `
  -host "192.168.1.50" `
  -port 22 `
  -user "ubuntu" `
  -key "C:\Users\admin\.ssh\id_ed25519" `
  -hostkey-fp "SHA256:abc123xyz..." `
  -package "openssl" `
  -target-version "1.1.1f-1ubuntu2.20" `
  -audit-log "audit.jsonl"
```

### Running Standalone (HTTP Server Mode)
```powershell
cd ssh-patch-orchestrator
.\orchestrator.exe server --port 8004 --audit-dir .
```

---

## 8. Test Suite & Verification

All internal components include comprehensive unit and integration tests with mocked SSH runners:

```powershell
cd ssh-patch-orchestrator
go test -v ./...
```

### Test Coverage Highlights:
- **`internal/orchestrator`**: Verifies valid transitions and asserts illegal state skipping (e.g., trying to jump straight to `PATCHING` without a verified snapshot fails).
- **`internal/snapshot`**: Tests `lvcreate` argument formulation, `lvs` attribute parsing (`swi-a-s---` vs invalid `swi-I-s---`), and free extent validation.
- **`internal/patch`**: Tests package name validation, allowlisted operations, and package manager adapters (`apt` and `dnf`).
- **`internal/validation`**: Tests Debian and RPM version comparisons (e.g., `8.9p1-3ubuntu0.10` >= `8.9p1-3ubuntu0.1`).
- **`internal/rollback`**: Tests immediate and deferred reboot merges (`lvconvert --merge`).
- **`internal/ssh`**: Verifies strict SHA256 host key fingerprint matching, command timeouts, and single-quote argument escaping.
