package rollback

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/ssh"
)

// Manager coordinates snapshot merging, optional reboot, and restore verification.
// CRITICAL SAFETY RULE 4: NEVER hide rollback failures.
// CRITICAL LVM PRINCIPLE: Rollback returns system to pre-patch state; vulnerability remains present.
type Manager struct {
	runner ssh.Runner
}

// NewManager creates a new Rollback Manager.
func NewManager(runner ssh.Runner) *Manager {
	return &Manager{
		runner: runner,
	}
}

// Rollback executes snapshot merging back into origin volumes.
func (m *Manager) Rollback(ctx context.Context, jobID string, snapshots []*models.Snapshot, reason models.RollbackReason) (*models.RollbackExecution, error) {
	if len(snapshots) == 0 {
		return nil, fmt.Errorf("SAFETY VIOLATION: no snapshots found bound to job %s for rollback", jobID)
	}

	start := time.Now()
	rbExec := &models.RollbackExecution{
		RollbackID:      fmt.Sprintf("rb_%s_%d", jobID, start.Unix()),
		JobID:           jobID,
		Reason:          reason,
		StartedAt:       start,
		Verification:    make([]models.RollbackVerificationCheck, 0),
		Outcome:         models.OutcomeEscalatedUrgent, // default to urgent until proven restored
	}

	if len(snapshots) > 0 {
		rbExec.SnapshotID = snapshots[0].SnapshotID
	}

	// 1. Verify snapshot eligibility (must match jobID, not be invalid)
	for _, snap := range snapshots {
		if snap.JobID != jobID {
			return rbExec, fmt.Errorf("SAFETY VIOLATION: snapshot %s is bound to job %s, not %s", snap.SnapshotID, snap.JobID, jobID)
		}
		if snap.Status == models.SnapshotInvalid {
			return rbExec, fmt.Errorf("snapshot %s is marked INVALID (COW overflow), cannot merge", snap.SnapshotLV)
		}
	}

	// 2. Merge each snapshot into origin
	for _, snap := range snapshots {
		devPath := fmt.Sprintf("/dev/%s/%s", snap.VG, snap.SnapshotLV)

		res, err := m.runner.Run(ctx, models.Operation{
			Ref:     fmt.Sprintf("op:lvm.rollback.merge:%s", snap.SnapshotLV),
			ArgV:    []string{"sudo", "lvconvert", "--merge", devPath},
			Timeout: 5 * time.Minute,
		})

		if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
			return rbExec, fmt.Errorf("lvconvert --merge failed for %s: %v (stderr: %s)", devPath, err, res.Stderr)
		}

		output := res.Stdout + " " + res.Stderr
		// Detect deferred merge on in-use (root) origin
		if strings.Contains(strings.ToLower(output), "merging will occur on next activation") ||
			strings.Contains(strings.ToLower(output), "delayed until next activation") ||
			strings.Contains(strings.ToLower(output), "merge will take place on next activation") {
			rbExec.MergeDeferred = true
		}
	}

	// 3. If merge is deferred, initiate a controlled reboot
	if rbExec.MergeDeferred {
		rbExec.RebootPerformed = true
		_, _ = m.runner.Run(ctx, models.Operation{
			Ref:     "op:lvm.rollback.reboot",
			ArgV:    []string{"sudo", "systemctl", "reboot"},
			Timeout: 10 * time.Second,
		})

		// Wait for host to complete reboot and resume SSH connectivity
		if err := m.waitForHostReboot(ctx); err != nil {
			return rbExec, fmt.Errorf("host did not recover after rollback reboot: %w", err)
		}
	}

	return rbExec, nil
}

// VerifyRestore checks that the host matches the recorded pre-patch baseline.
func (m *Manager) VerifyRestore(ctx context.Context, rbExec *models.RollbackExecution, snapshots []*models.Snapshot, baseline *models.Baseline) error {
	addCheck := func(name string, pass bool) bool {
		status := "PASS"
		if !pass {
			status = "FAIL"
		}
		rbExec.Verification = append(rbExec.Verification, models.RollbackVerificationCheck{
			Name:   name,
			Result: status,
		})
		return pass
	}

	// 1. Confirm snapshot is no longer present (merge finished)
	for _, snap := range snapshots {
		devPath := fmt.Sprintf("/dev/%s/%s", snap.VG, snap.SnapshotLV)
		res, _ := m.runner.Run(ctx, models.Operation{
			Ref:  fmt.Sprintf("op:lvm.rollback.check_merged:%s", snap.SnapshotLV),
			ArgV: []string{"sudo", "lvs", devPath},
		})
		// If lvs returns non-zero, the snapshot was merged and deleted
		if res != nil && res.ExitCode != nil && *res.ExitCode != 0 {
			addCheck(fmt.Sprintf("snapshot_merged:%s", snap.SnapshotLV), true)
			snap.Status = models.SnapshotMerged
		} else {
			addCheck(fmt.Sprintf("snapshot_merged:%s", snap.SnapshotLV), false)
			rbExec.Outcome = models.OutcomeEscalatedUrgent
			return fmt.Errorf("snapshot %s still exists; merge did not complete", devPath)
		}
	}

	// 2. Verify package versions match baseline
	if baseline != nil {
		for pkg, expectedVer := range baseline.PackageVersions {
			currentVer, err := m.getInstalledVersion(ctx, pkg)
			if err != nil || currentVer != expectedVer {
				addCheck(fmt.Sprintf("package_restored:%s", pkg), false)
				rbExec.Outcome = models.OutcomeEscalatedUrgent
				return fmt.Errorf("package %s version %q does not match pre-patch baseline %q", pkg, currentVer, expectedVer)
			}
			addCheck(fmt.Sprintf("package_restored:%s", pkg), true)
		}

		// 3. Verify services match baseline
		for svc, expectedState := range baseline.ServiceStates {
			currentState, err := m.getServiceState(ctx, svc)
			if err != nil || currentState != expectedState {
				addCheck(fmt.Sprintf("service_restored:%s", svc), false)
				rbExec.Outcome = models.OutcomeEscalatedUrgent
				return fmt.Errorf("service %s state %q does not match pre-patch baseline %q", svc, currentState, expectedState)
			}
			addCheck(fmt.Sprintf("service_restored:%s", svc), true)
		}
	}

	rbExec.RestoreVerified = true
	// PRINCIPLE: Rollback returns system to pre-patch state; vulnerability remains!
	rbExec.Outcome = models.OutcomeRestoredVulnerabilityRemains
	return nil
}

func (m *Manager) waitForHostReboot(ctx context.Context) error {
	// Poll host until reachable or context expires
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeout := time.After(3 * time.Minute)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timed out waiting for host to reboot after rollback")
		case <-ticker.C:
			res, err := m.runner.Run(ctx, models.Operation{
				Ref:  "op:reboot.ping",
				ArgV: []string{"echo", "reboot_ok"},
			})
			if err == nil && res.ExitCode != nil && *res.ExitCode == 0 {
				return nil
			}
		}
	}
}

func (m *Manager) getInstalledVersion(ctx context.Context, pkg string) (string, error) {
	res, err := m.runner.Run(ctx, models.Operation{
		Ref:  "op:rollback.check_version:" + pkg,
		ArgV: []string{"dpkg-query", "-W", "-f=${Version}", pkg},
	})
	if err == nil && res.ExitCode != nil && *res.ExitCode == 0 {
		return strings.TrimSpace(res.Stdout), nil
	}

	resRPM, errRPM := m.runner.Run(ctx, models.Operation{
		Ref:  "op:rollback.check_version_rpm:" + pkg,
		ArgV: []string{"rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg},
	})
	if errRPM == nil && resRPM.ExitCode != nil && *resRPM.ExitCode == 0 {
		return strings.TrimSpace(resRPM.Stdout), nil
	}

	return "", fmt.Errorf("failed reading installed version for %s", pkg)
}

func (m *Manager) getServiceState(ctx context.Context, svc string) (string, error) {
	res, err := m.runner.Run(ctx, models.Operation{
		Ref:  "op:rollback.check_service:" + svc,
		ArgV: []string{"systemctl", "is-active", svc},
	})
	if err != nil || res.ExitCode == nil {
		return "", fmt.Errorf("failed reading service state for %s", svc)
	}
	return strings.TrimSpace(res.Stdout), nil
}
