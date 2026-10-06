package snapshot

import (
	"context"
	"strings"
	"testing"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/ssh"
)

func TestCreateAndVerifySnapshotSuccess(t *testing.T) {
	ctx := context.Background()
	mock := ssh.NewMockRunner()
	zero := 0

	// lvcreate mock
	mock.RegisterHandler("op:lvm.snapshot.create:root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "  Logical volume \"sd_job_100_root\" created.\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	// lvs verify mock
	mock.RegisterHandler("op:lvm.snapshot.verify:sd_job_100_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		// Output fields: lv_name, vg_name, origin, lv_attr, data_percent, lv_uuid
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "  sd_job_100_root vg0 root swi-a-s--- 2.50 uuid-12345-67890\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	mgr := NewManager(mock)

	rollbackSet := []models.RollbackSetEntry{
		{VG: "vg0", LV: "root", Mount: "/"},
	}

	snaps, err := mgr.CreateSnapshots(ctx, "job-100", rollbackSet, 2048)
	if err != nil {
		t.Fatalf("failed to create snapshots: %v", err)
	}

	if len(snaps) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(snaps))
	}
	if snaps[0].SnapshotLV != "sd_job_100_root" {
		t.Fatalf("unexpected snapshot name: %s", snaps[0].SnapshotLV)
	}

	// Now run Verification Gate
	if err := mgr.VerifySnapshots(ctx, snaps); err != nil {
		t.Fatalf("snapshot verification failed unexpectedly: %v", err)
	}

	if !snaps[0].Verified {
		t.Fatalf("expected snapshot to be marked as verified")
	}
	if snaps[0].LVUUID != "uuid-12345-67890" {
		t.Fatalf("unexpected UUID: %s", snaps[0].LVUUID)
	}
	if snaps[0].COWUsagePercent != 2.50 {
		t.Fatalf("unexpected COW usage percent: %f", snaps[0].COWUsagePercent)
	}
}

func TestVerifySnapshotInvalidAttributeFails(t *testing.T) {
	ctx := context.Background()
	mock := ssh.NewMockRunner()
	zero := 0

	// Snapshot attribute has 'I' indicating invalid snapshot (COW overflow)
	mock.RegisterHandler("op:lvm.snapshot.verify:sd_job_bad_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "  sd_job_bad_root vg0 root swi-I-s--- 100.00 uuid-bad-uuid\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	mgr := NewManager(mock)
	snap := &models.Snapshot{
		SnapshotID: "snap-1",
		JobID:      "job-bad",
		VG:         "vg0",
		OriginLV:   "root",
		SnapshotLV: "sd_job_bad_root",
	}

	err := mgr.VerifySnapshots(ctx, []*models.Snapshot{snap})
	if err == nil {
		t.Fatalf("expected verification to fail for invalid snapshot attribute")
	}

	if !strings.Contains(err.Error(), "INVALID") {
		t.Fatalf("expected 'INVALID' in error message, got: %v", err)
	}
	if snap.Status != models.SnapshotInvalid {
		t.Fatalf("expected status to be updated to SnapshotInvalid, got: %s", snap.Status)
	}
}

func TestVerifySnapshotOriginMismatchFails(t *testing.T) {
	ctx := context.Background()
	mock := ssh.NewMockRunner()
	zero := 0

	// Origin returned is 'home' instead of expected 'root'
	mock.RegisterHandler("op:lvm.snapshot.verify:sd_job_mismatch_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "  sd_job_mismatch_root vg0 home swi-a-s--- 1.00 uuid-xyz\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	mgr := NewManager(mock)
	snap := &models.Snapshot{
		SnapshotID: "snap-mismatch",
		JobID:      "job-mismatch",
		VG:         "vg0",
		OriginLV:   "root",
		SnapshotLV: "sd_job_mismatch_root",
	}

	err := mgr.VerifySnapshots(ctx, []*models.Snapshot{snap})
	if err == nil {
		t.Fatalf("expected verification to fail on origin mismatch")
	}

	if !strings.Contains(err.Error(), "origin mismatch") {
		t.Fatalf("expected 'origin mismatch' in error message, got: %v", err)
	}
}

func TestCleanupSnapshots(t *testing.T) {
	ctx := context.Background()
	mock := ssh.NewMockRunner()
	zero := 0

	mock.RegisterHandler("op:lvm.snapshot.remove:sd_job_clean_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "  Logical volume \"sd_job_clean_root\" successfully removed\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	mgr := NewManager(mock)
	snap := &models.Snapshot{
		SnapshotID: "snap-clean",
		VG:         "vg0",
		SnapshotLV: "sd_job_clean_root",
		Status:     models.SnapshotActive,
	}

	if err := mgr.CleanupSnapshots(ctx, []*models.Snapshot{snap}); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	if snap.Status != models.SnapshotRemoved {
		t.Fatalf("expected status to be SnapshotRemoved, got %s", snap.Status)
	}
}
