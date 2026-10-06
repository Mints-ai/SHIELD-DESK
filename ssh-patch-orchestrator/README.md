# ShieldDesk — SSH Patch Orchestrator (Go Implementation)

> Production-grade implementation in Go of the ShieldDesk SSH Patch Orchestrator with LVM snapshot-based rollback.

## Architecture & Package Structure

```text
ssh-patch-orchestrator/
├── cmd/
│   └── orchestrator/
│       └── main.go         # CLI Entry point & flags
├── internal/
│   ├── models/             # Domain entities: Job, Asset, Plan, Audit, Snapshot, Precheck, Validation
│   ├── orchestrator/       # State Machine and central Job Orchestrator
│   ├── ssh/                # Connection Manager, strict host key checking, Runner interface
│   ├── precheck/           # Precheck Engine (OS, LVM, disk space, baseline capture)
│   ├── snapshot/           # LVM Snapshot Manager & Phase 4 Verification Gate
│   ├── patch/              # Controlled patch execution & package manager adapters (apt, dnf)
│   ├── validation/         # Post-patch validation & version comparison
│   ├── rollback/           # Snapshot merge, deferred reboot, and restore verification
│   ├── approval/           # Policy decision & approval evaluation stub
│   ├── audit/              # Append-only structured audit trail writer
│   └── security/           # Shell metacharacter prevention & secret redaction
├── configs/
│   └── example.yaml        # Safe configuration template (placeholders only)
├── go.mod
└── orchestrator.exe        # Compiled binary
```

## Safety Rules Enforced

1. **Never patch without a verified recovery point**: The state machine forbids transitioning to `PATCHING` from any state other than `SNAPSHOT_VERIFIED`.
2. **Never treat patch command success as proof of remediation**: Validation must explicitly read back the installed package version and check that it meets or exceeds the required target.
3. **Never execute unrestricted AI-generated shell commands**: Commands are dispatched exclusively as typed argument vectors from an allowlist (`pkg.upgrade`, `pkg.install`, `service.restart`).
4. **Never hide rollback failures**: Rollback or restore verification failure triggers immediate transition to `ESCALATED_URGENT`.
5. **Never report a vulnerability as fixed unless validation confirms it**: If a patch fails or is rolled back, the reported vulnerability status remains `PRESENT` and the outcome is recorded as `RESTORED_VULNERABILITY_REMAINS`.

## Running Tests

All unit tests and mocked integration flows can be executed via:

```powershell
go test -v ./...
```
