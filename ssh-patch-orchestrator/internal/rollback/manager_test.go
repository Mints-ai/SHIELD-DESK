package rollback

import (
	"context"
	"testing"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/ssh"
)

func TestRollbackImmediateMergeAndRestoreSuccess(t *testing.T) {
	ctx := context.Background()
	mock := ssh.NewMockRunner()
	zero := 0
	exit1 := 1

	// Merge command succeeds immediately (not deferred)
	mock.RegisterHandler("op:lvm.rollback.merge:sd_job_1_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "Merging of volume sd_job_1_root started.\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	// Check merged (snapshot LV is gone, exit 1 from lvs)
	mock.RegisterHandler("op:lvm.rollback.check_merged:sd_job_1_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &exit1,
			Stderr:     "One or more specified logical volume(s) not found.",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	// Check restored package version matches baseline 1.1.1f-1ubuntu2.19
	mock.RegisterHandler("op:rollback.check_version:openssl", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "1.1.1f-1ubuntu2.19\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	// Check restored service state matches baseline "active"
	mock.RegisterHandler("op:rollback.check_service:nginx", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "active\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	mgr := NewManager(mock)
	snap := &models.Snapshot{
		SnapshotID: "snap-1",
		JobID:      "job-1",
		VG:         "vg0",
		SnapshotLV: "sd_job_1_root",
		Status:     models.SnapshotActive,
	}

	baseline := &models.Baseline{
		PackageVersions: map[string]string{"openssl": "1.1.1f-1ubuntu2.19"},
		ServiceStates:   map[string]string{"nginx": "active"},
	}

	exec, err := mgr.Rollback(ctx, "job-1", []*models.Snapshot{snap}, models.RollbackValidationFailed)
	if err != nil {
		t.Fatalf("rollback failed unexpectedly: %v", err)
	}

	if exec.MergeDeferred || exec.RebootPerformed {
		t.Fatalf("immediate merge should not trigger reboot")
	}

	// Now verify restore
	if err := mgr.VerifyRestore(ctx, exec, []*models.Snapshot{snap}, baseline); err != nil {
		t.Fatalf("verify restore failed: %v", err)
	}

	if !exec.RestoreVerified {
		t.Fatalf("expected RestoreVerified to be true")
	}

	// CRITICAL REPORTING RULE: Must report RESTORED_VULNERABILITY_REMAINS
	if exec.Outcome != models.OutcomeRestoredVulnerabilityRemains {
		t.Fatalf("expected outcome RESTORED_VULNERABILITY_REMAINS, got: %s", exec.Outcome)
	}
}

func TestRollbackDeferredMergeWithReboot(t *testing.T) {
	ctx := context.Background()
	mock := ssh.NewMockRunner()
	zero := 0
	exit1 := 1

	// Merge command reports deferred merge on next activation of root
	mock.RegisterHandler("op:lvm.rollback.merge:sd_job_2_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "Can't merge over open origin volume. Merging will occur on next activation of origin.\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	// Reboot command
	mock.RegisterHandler("op:lvm.rollback.reboot", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Outcome: models.OutcomeCompleted}, nil
	})

	// Ping after reboot succeeds
	mock.RegisterHandler("op:reboot.ping", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "reboot_ok\n", Outcome: models.OutcomeCompleted}, nil
	})

	// Snapshot merged
	mock.RegisterHandler("op:lvm.rollback.check_merged:sd_job_2_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &exit1, Outcome: models.OutcomeCompleted}, nil
	})

	// Baseline checks
	mock.RegisterHandler("op:rollback.check_version:openssl", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "1.1.1f-1ubuntu2.19\n"}, nil
	})

	mgr := NewManager(mock)
	snap := &models.Snapshot{
		SnapshotID: "snap-2",
		JobID:      "job-2",
		VG:         "vg0",
		SnapshotLV: "sd_job_2_root",
		Status:     models.SnapshotActive,
	}

	exec, err := mgr.Rollback(ctx, "job-2", []*models.Snapshot{snap}, models.RollbackPatchFailed)
	if err != nil {
		t.Fatalf("rollback failed unexpectedly: %v", err)
	}

	if !exec.MergeDeferred || !exec.RebootPerformed {
		t.Fatalf("expected deferred merge and reboot performed, got deferred=%v, reboot=%v", exec.MergeDeferred, exec.RebootPerformed)
	}
}

// Critical Safety Rule 4: Never hide rollback failure
func TestRestoreVerificationFailureEscalatesUrgently(t *testing.T) {
	ctx := context.Background()
	mock := ssh.NewMockRunner()
	zero := 0
	exit1 := 1

	mock.RegisterHandler("op:lvm.rollback.merge:sd_job_3_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Outcome: models.OutcomeCompleted}, nil
	})

	mock.RegisterHandler("op:lvm.rollback.check_merged:sd_job_3_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &exit1, Outcome: models.OutcomeCompleted}, nil
	})

	// Package version did NOT return to baseline!
	mock.RegisterHandler("op:rollback.check_version:openssl", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "corrupted-version-unknown\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	mgr := NewManager(mock)
	snap := &models.Snapshot{
		SnapshotID: "snap-3",
		JobID:      "job-3",
		VG:         "vg0",
		SnapshotLV: "sd_job_3_root",
		Status:     models.SnapshotActive,
	}

	baseline := &models.Baseline{
		PackageVersions: map[string]string{"openssl": "1.1.1f-1ubuntu2.19"},
	}

	exec, err := mgr.Rollback(ctx, "job-3", []*models.Snapshot{snap}, models.RollbackPatchFailed)
	if err != nil {
		t.Fatalf("rollback initiation error: %v", err)
	}

	verErr := mgr.VerifyRestore(ctx, exec, []*models.Snapshot{snap}, baseline)
	if verErr == nil {
		t.Fatalf("SAFETY RULE 4 VIOLATION: restore verification succeeded despite package corruption!")
	}

	// Must escalate urgently
	if exec.Outcome != models.OutcomeEscalatedUrgent {
		t.Fatalf("expected outcome ESCALATED_URGENT on verification failure, got: %s", exec.Outcome)
	}
}
