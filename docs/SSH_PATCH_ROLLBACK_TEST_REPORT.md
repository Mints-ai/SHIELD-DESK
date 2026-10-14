# ShieldDesk™ — SSH Patch Orchestrator & Governed Rollback Test Report

**Report Version:** 1.0.0  
**Audit & Test Date:** 2026-10-13  
**Target Systems:** ShieldDesk SSH Patch Orchestrator (`ssh-patch-orchestrator`), Governed Rollback Engine, Linux LVM Storage Driver  
**Compliance & Governance Standard:** ShieldDesk Product Invariant Rule 3 (**PROVE BEFORE YOU ACT**) / SOC 2 Type II Security Controls / OWASP ASVS 4.0  
**Test Engine Coverage:** Go Orchestrator Suite (`go test -v ./...`), TypeScript Failure-Injection Harness (`tests/rollback-failure-injection.test.ts`), Verification Engine (`tests/verification-and-rollback-engine.test.ts`)  

---

## 1. Executive Summary & Purpose

Remediation operations executed across enterprise Linux servers carry operational hazards: package manager deadlocks, broken dependency trees, kernel crashes, or unexpected service degradation.

In adherence to ShieldDesk's foundational tenet—**PROVE BEFORE YOU ACT (Rule 3)**—the ShieldDesk SSH Patch Orchestrator mandates that:
1. **No Patch Without Validated Rollback Gate:** A target volume cannot enter `PATCHING` unless an active, verified Copy-On-Write (COW) LVM snapshot exists (`lv_attr` active snapshot flag verified).
2. **Exit Code 0 Is NOT Proof of Remediation:** A successful exit code from `apt-get` or `dnf` only signals package manager process termination. Remediation is verified **only** when post-patch semantic versioning and systemd daemon health checks pass.
3. **Rollback Truth in Advertising:** An automated rollback deterministically restores the system to its pre-patch state. It is recorded as `RESTORED_VULNERABILITY_REMAINS` and its vulnerability status is locked at `PRESENT` (never falsely reported fixed).
4. **No Hidden Rollback Failures:** Any failure during snapshot merge, deferred-reboot reconnect, or baseline restoration triggers immediate transition to `ESCALATED_URGENT`.

This document establishes the authoritative **SSH Patch Error Taxonomy**, defines the **Automated LVM Rollback & Verification Mechanics**, and archives the **Automated Test Results** verifying end-to-end resilience.

---

## 2. Orchestrator State Machine & Safety Invariants

```mermaid
flowchart TD
    DETECTED[DETECTED] -->|Fix Available| FIX_AVAILABLE[FIX_AVAILABLE]
    DETECTED -->|No Known Fix| HUMAN_REVIEW[HUMAN_REVIEW]
    FIX_AVAILABLE -->|Policy Check| PRECHECKING[PRECHECKING]
    FIX_AVAILABLE -->|Requires Dual-Custody| AWAITING_APPROVAL[AWAITING_APPROVAL]
    AWAITING_APPROVAL -->|Signed Token Approved| PRECHECKING
    
    PRECHECKING -->|Precheck Passed| READY_FOR_SNAPSHOT[READY_FOR_SNAPSHOT]
    PRECHECKING -->|Precheck Failed| PRECHECK_FAILED[PRECHECK_FAILED]
    PRECHECK_FAILED --> HUMAN_REVIEW
    
    READY_FOR_SNAPSHOT -->|lvcreate -s| SNAPSHOT_CREATING[SNAPSHOT_CREATING]
    SNAPSHOT_CREATING -->|Verification Gate Passed| SNAPSHOT_VERIFIED[SNAPSHOT_VERIFIED]
    SNAPSHOT_CREATING -->|Snapshot Failed| SNAPSHOT_FAILED[SNAPSHOT_FAILED]
    SNAPSHOT_FAILED --> HUMAN_REVIEW
    
    SNAPSHOT_VERIFIED -->|INVARIANT 1: Execute Allowlisted Patch| PATCHING[PATCHING]
    
    PATCHING -->|Command Non-Zero / Timeout| ROLLBACK_REQUIRED[ROLLBACK_REQUIRED]
    PATCHING -->|Command Success (Exit 0)| VALIDATING[VALIDATING]
    
    VALIDATING -->|INVARIANT 2: Target Ver >= Min & Svc Active| REMEDIATED[REMEDIATED]
    VALIDATING -->|Ver Mismatch / Svc Degraded| ROLLBACK_REQUIRED
    
    ROLLBACK_REQUIRED -->|Trigger Merging| ROLLING_BACK[ROLLING_BACK]
    
    ROLLING_BACK -->|lvconvert --merge| VERIFYING_RESTORE[VERIFYING_RESTORE]
    ROLLING_BACK -->|Merge / Reboot Command Error| ESCALATED_URGENT[ESCALATED_URGENT]
    
    VERIFYING_RESTORE -->|INVARIANT 3: Baseline Restored| ROLLED_BACK_HUMAN_REVIEW[ROLLED_BACK_HUMAN_REVIEW]
    VERIFYING_RESTORE -->|INVARIANT 4: Verification Mismatch| ESCALATED_URGENT
```

### Safety Invariant Summary
- **Invariant 1 (`SNAPSHOT_VERIFIED` Gate):** The `PATCHING` state is strictly barred from all states except `SNAPSHOT_VERIFIED`. If a snapshot fails creation or attribute validation, patching cannot execute.
- **Invariant 2 (`Exit 0` Non-Proof):** Command completion is decoupled from vulnerability remediation. Validation checks test `installed_version >= target_version` and confirm daemon `is-active`.
- **Invariant 3 (Honest Vulnerability Accounting):** Reversion to pre-patch state leaves the asset in `ROLLED_BACK_HUMAN_REVIEW` with `outcome: RESTORED_VULNERABILITY_REMAINS` and `vulnerability_status: PRESENT`.
- **Invariant 4 (Zero Silent Failures):** Any inconsistency during snapshot reversion or baseline restore verification escalates to `ESCALATED_URGENT`.

---

## 3. SSH Patch Error Taxonomy

The orchestrator classifies failures across five discrete lifecycle boundaries:

| Error Code | Phase | Trigger Condition | System Defense / Handling | Terminal State |
| :--- | :--- | :--- | :--- | :--- |
| `ERR_PRECHECK_OS_UNSUPPORTED` | Precheck | Target OS is not an enterprise Linux distribution (Ubuntu, Debian, RHEL, CentOS, Rocky) | Halts before creating snapshots or invoking package managers | `HUMAN_REVIEW` |
| `ERR_PRECHECK_NO_PKG_MGR` | Precheck | Neither `apt`, `dnf`, nor `yum` detected on target | Halts pipeline immediately | `HUMAN_REVIEW` |
| `ERR_PRECHECK_NO_SUDO` | Precheck | User lacks passwordless `sudo` or `root` permissions | Blocks execution; emits audit security event | `HUMAN_REVIEW` |
| `ERR_PRECHECK_PKG_LOCKED` | Precheck | Dpkg lock (`/var/lib/dpkg/lock-frontend`) or RPM lock held by another process | Fail-safe stop; avoids competing with running package managers | `HUMAN_REVIEW` |
| `ERR_PRECHECK_INSUFFICIENT_COW_SPACE` | Precheck | Free extent space in Volume Group is `< 1024 MB` (insufficient for COW delta) | Snapshot creation avoided to prevent volume group exhaustion | `HUMAN_REVIEW` |
| `ERR_PRECHECK_NON_LVM_STATE` | Precheck | Proposed patch touches `/boot`, EFI partitions, or non-LVM mounted filesystems | Fails closed; LVM snapshot cannot roll back non-LVM storage | `HUMAN_REVIEW` |
| `ERR_SNAPSHOT_GATE_VIOLATION` | Snapshot Gate | Snapshot created but `lvs` attribute is not snapshot (`s`), not active (`a`), or COW usage `> 85%` | Cleans up orphaned snapshot and stops before patch dispatch | `HUMAN_REVIEW` |
| `ERR_PATCH_EXEC_NONZERO` | Patching | Package upgrade exited with code `!= 0` (e.g., dependency break, lock conflict, script error) | Automatically triggers governed rollback | `ROLLED_BACK_HUMAN_REVIEW` |
| `ERR_PATCH_EXEC_TIMEOUT` | Patching | Package operation exceeded operation deadline (default 10 minutes) | Process terminated; rollback automatically triggered | `ROLLED_BACK_HUMAN_REVIEW` |
| `ERR_VAL_VERSION_MISMATCH` | Validation | Package exit was 0, but installed package version remains `< target_version` or `== baseline` | Automatic rollback triggered to prevent indeterminate partial states | `ROLLED_BACK_HUMAN_REVIEW` |
| `ERR_VAL_SERVICE_DEGRADED` | Validation | Service post-patch `systemctl is-active` returned `failed`, `inactive`, or `degraded` | Automatic rollback triggered to protect service availability | `ROLLED_BACK_HUMAN_REVIEW` |
| `ERR_ROLLBACK_MERGE_FAILED` | Rollback | `lvconvert --merge /dev/vg/sd_...` command returned non-zero error code | Immediate operational escalation | `ESCALATED_URGENT` |
| `ERR_ROLLBACK_REBOOT_TIMEOUT` | Rollback | Root volume deferred merge initiated reboot, but host failed to resume SSH ping within 3m | Escalates urgently for Out-of-Band (IPMI/console) rescue | `ESCALATED_URGENT` |
| `ERR_RESTORE_VERIFY_FAILED` | Verification | Host reachable, but package version does not match pre-patch baseline or snapshot still exists in `lvs` | Escalates urgently; prevents silent reversion corruption | `ESCALATED_URGENT` |

---

## 4. Governed Rollback & Recovery Mechanics

### 4.1 LVM Snapshot Architecture
When a patch job begins, the orchestrator calculates the exact Volume Groups (`VG`) and Origin Logical Volumes (`OriginLV`) mapped to the files being modified.
1. **Naming Standard:** Snapshots are named deterministically with `sd_<job_id>_<origin_lv>` (e.g. `sd_job_patch_001_root`).
2. **Pre-Allocation:** 2,048 MB (default) or calculated COW reservation is allocated.
3. **Verification Gate:** Attributes queried via `lvs -o lv_name,vg_name,origin,lv_attr,data_percent,lv_uuid`.
   - First character must be `s` (snapshot).
   - Fifth character must be `a` (active).
   - If fifth character is `I` / `i` / `d`, snapshot is flagged `INVALID` and rejected.

### 4.2 Snapshot Merging (`lvconvert --merge`)
When rollback is initiated:
```bash
sudo lvconvert --merge /dev/<vg_name>/sd_<job_id>_<origin_lv>
```
Two execution pathways exist:
- **Immediate Merge (Non-Root / Inactive Volumes):** The snapshot chunks are merged synchronously into origin. The snapshot LV is automatically destroyed upon completion.
- **Deferred Merge (Root Volume / In-Use Origin):** Linux kernel responds:
  `Merging will occur on next activation of logical volume`
  The orchestrator detects this string, sets `MergeDeferred = true`, and executes a coordinated reboot:
  ```bash
  sudo systemctl reboot
  ```
  The orchestrator waits for the host to complete reboot and re-establish SSH connectivity (`op:reboot.ping` deadline 3 minutes).

### 4.3 Post-Reversion Verification Sequence
Before an asset is declared recovered, three independent tests must pass:
1. **Snapshot Elimination Check:** Running `sudo lvs /dev/<vg_name>/<snapshot_lv>` must return non-zero exit code (verifying the snapshot was merged and deleted).
2. **Package Version Baseline Check:** Querying `dpkg-query -W -f='${Version}' <pkg>` or `rpm -q` must match the exact baseline version captured during precheck.
3. **Service State Active Check:** Querying `systemctl is-active <service>` must match the exact service state recorded before patching.

---

## 5. Automated Test Evidence & Verification Logs

### 5.1 Go Orchestrator Test Suite Execution (`go test -v ./...`)
The Go test suite tests state transitions, snapshot gating, patch failure rollbacks, and deferred merge reboot handling:

```
=== RUN   TestEndToEndHappyPathRemediation
--- PASS: TestEndToEndHappyPathRemediation (0.00s)
=== RUN   TestEndToEndPatchFailureTriggersRollbackAndHumanReview
--- PASS: TestEndToEndPatchFailureTriggersRollbackAndHumanReview (0.00s)
=== RUN   TestPrecheckFailureStopsBeforeSnapshotOrPatch
--- PASS: TestPrecheckFailureStopsBeforeSnapshotOrPatch (0.00s)
=== RUN   TestLegalTransitions
    --- PASS: TestLegalTransitions/SNAPSHOT_VERIFIED_->_PATCHING (0.00s)
    --- PASS: TestLegalTransitions/PATCHING_->_ROLLBACK_REQUIRED (0.00s)
    --- PASS: TestLegalTransitions/VALIDATING_->_ROLLBACK_REQUIRED (0.00s)
    --- PASS: TestLegalTransitions/ROLLBACK_REQUIRED_->_ROLLING_BACK (0.00s)
    --- PASS: TestLegalTransitions/ROLLING_BACK_->_VERIFYING_RESTORE (0.00s)
    --- PASS: TestLegalTransitions/ROLLING_BACK_->_ESCALATED_URGENT (0.00s)
    --- PASS: TestLegalTransitions/VERIFYING_RESTORE_->_ROLLED_BACK_HUMAN_REVIEW (0.00s)
    --- PASS: TestLegalTransitions/VERIFYING_RESTORE_->_ESCALATED_URGENT (0.00s)
--- PASS: TestLegalTransitions (0.00s)
=== RUN   TestPatchingOnlyFromSnapshotVerified
--- PASS: TestPatchingOnlyFromSnapshotVerified (0.00s)
=== RUN   TestTerminalStatesHaveNoOutgoingTransitions
--- PASS: TestTerminalStatesHaveNoOutgoingTransitions (0.00s)
=== RUN   TestRollbackImmediateMergeAndRestoreSuccess
--- PASS: TestRollbackImmediateMergeAndRestoreSuccess (0.00s)
=== RUN   TestRollbackDeferredMergeWithReboot
--- PASS: TestRollbackDeferredMergeWithReboot (2.00s)
=== RUN   TestRestoreVerificationFailureEscalatesUrgently
--- PASS: TestRestoreVerificationFailureEscalatesUrgently (0.00s)
=== RUN   TestValidationSuccessful
--- PASS: TestValidationSuccessful (0.00s)
=== RUN   TestValidationFailsWhenVersionUnchangedFromBaseline
--- PASS: TestValidationFailsWhenVersionUnchangedFromBaseline (0.00s)
=== RUN   TestValidationFailsWhenServiceIsDegraded
--- PASS: TestValidationFailsWhenServiceIsDegraded (0.00s)
PASS
ok  github.com/shielddesk/ssh-patch-orchestrator/internal/orchestrator 0.592s
ok  github.com/shielddesk/ssh-patch-orchestrator/internal/rollback     2.553s
ok  github.com/shielddesk/ssh-patch-orchestrator/internal/validation   0.549s
ok  github.com/shielddesk/ssh-patch-orchestrator/internal/precheck     0.481s
ok  github.com/shielddesk/ssh-patch-orchestrator/internal/snapshot     0.395s
ok  github.com/shielddesk/ssh-patch-orchestrator/internal/patch        0.412s
ok  github.com/shielddesk/ssh-patch-orchestrator/internal/security     0.380s
ok  github.com/shielddesk/ssh-patch-orchestrator/internal/ssh          0.440s
```

### 5.2 TypeScript Failure-Injection Harness Execution (`tests/rollback-failure-injection.test.ts`)
The failure-injection harness executes 8 synthetic failure scenarios against the verification engine, verifying that rollback outcomes append to the SHA-256 Merkle hash chain:

```
TAP version 13
# Subtest: Rollback failure-injection harness records simulated rollback outcomes in the evidence chain
    # Subtest: patch failure
    ok 1 - patch failure
    # Subtest: service failure
    ok 2 - service failure
    # Subtest: network failure
    ok 3 - network failure
    # Subtest: snapshot corruption
    ok 4 - snapshot corruption
    # Subtest: disk full
    ok 5 - disk full
    # Subtest: agent disconnect mid-execution
    ok 6 - agent disconnect mid-execution
    # Subtest: reboot before verification
    ok 7 - reboot before verification
    # Subtest: partial execution
    ok 8 - partial execution
    1..8
ok 1 - Rollback failure-injection harness records simulated rollback outcomes in the evidence chain
# tests 9 | pass 9 | fail 0
```

### 5.3 Verification and Rollback Engine Suite (`tests/verification-and-rollback-engine.test.ts`)
Validates that Rule 3 invariants hold and command execution is never conflated with verified remediation:

```
# Subtest: Phase 12 & 13: Verification Engine & Rollback Engine Suite
    # Subtest: VerificationEngine (Prove Before You Act)
        ok 1 - Plan Creation: Deterministically synthesizes appropriate verification checks
        ok 2 - Rule 3 Invariant: Never treat command execution as success without state verification
        ok 3 - Verification Success: Confirms remediated host state and returns VERIFIED
    # Subtest: RollbackEngine (Governed Reversion)
        ok 1 - RollbackEngine: Reverts state using snapshot and records hash-chain ledger entry
        ok 2 - Network Rollback: Executes restore_host for failed or aborted isolation
# tests 5 | pass 5 | fail 0
```

---

## 6. Tamper-Evident Audit Ledger Records

Whenever an SSH patch or rollback occurs, the orchestrator generates cryptographically linked audit ledger events.

### Example: Patch Failure & Restored Vulnerability Ledger Entry
```json
{
  "event_id": "evt_job_patch_492_1760341852000000",
  "incident_id": "inc_cve_2024_6387",
  "job_id": "job_patch_492",
  "asset_id": "srv-prod-db-01",
  "timestamp": "2026-10-13T08:18:17Z",
  "actor": "system:orchestrator",
  "action": "STATE_ROLLED_BACK_HUMAN_REVIEW",
  "result": "SUCCESS",
  "state_from": "VERIFYING_RESTORE",
  "state_to": "ROLLED_BACK_HUMAN_REVIEW",
  "details": {
    "outcome": "RESTORED_VULNERABILITY_REMAINS",
    "vulnerability_status": "PRESENT",
    "snapshot_id": "snap_job_patch_492_root",
    "merge_deferred": true,
    "reboot_performed": true,
    "checks_passed": [
      "snapshot_merged:sd_job_patch_492_root",
      "package_restored:openssh-server",
      "service_restored:ssh"
    ]
  }
}
```

### Example: Restore Verification Failure Escalation Entry
```json
{
  "event_id": "evt_job_patch_493_1760341890000000",
  "incident_id": "inc_cve_2024_6387",
  "job_id": "job_patch_493",
  "asset_id": "srv-prod-app-02",
  "timestamp": "2026-10-13T08:18:20Z",
  "actor": "system:orchestrator",
  "action": "STATE_ESCALATED_URGENT",
  "result": "FAILURE",
  "state_from": "VERIFYING_RESTORE",
  "state_to": "ESCALATED_URGENT",
  "error": {
    "code": "ERR_RESTORE_VERIFY_FAILED",
    "message": "CRITICAL: rollback verification failed: service ssh state 'inactive' does not match pre-patch baseline 'active'"
  }
}
```

---

## 7. Conclusion & Governance Sign-Off

The **ShieldDesk SSH Patch Orchestrator** and **Governed Rollback Engine** fulfill all architectural constraints established under Rule 3 (**PROVE BEFORE YOU ACT**):
1. No un-snapshotted host can ever be patched.
2. Exit code 0 is never conflated with genuine remediation.
3. Rollbacks report factual reality (`RESTORED_VULNERABILITY_REMAINS`, `VulnStatusPresent`).
4. Reversion failures immediately escalate to high-priority incident status (`ESCALATED_URGENT`).

**Audited & Approved By:**  
DevSecOps Platform Engineering Team, Mints Global  
October 13, 2026
