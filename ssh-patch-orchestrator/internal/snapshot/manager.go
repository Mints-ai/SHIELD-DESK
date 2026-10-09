package snapshot

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/security"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/ssh"
)

// Manager manages the lifecycle of LVM snapshots for patch recovery points.
type Manager struct {
	runner ssh.Runner
}

// NewManager creates a new LVM Snapshot Manager.
func NewManager(runner ssh.Runner) *Manager {
	return &Manager{
		runner: runner,
	}
}

// FormatSnapshotName produces a deterministic, collision-safe snapshot LV name bound to the job.
func FormatSnapshotName(jobID, originLV string) string {
	cleanJob := strings.ReplaceAll(jobID, "-", "_")
	return fmt.Sprintf("sd_%s_%s", cleanJob, originLV)
}

// CreateSnapshots creates an LVM snapshot for each volume in the rollback set.
func (m *Manager) CreateSnapshots(ctx context.Context, jobID string, rollbackSet []models.RollbackSetEntry, cowSizeMB int) ([]*models.Snapshot, error) {
	if len(rollbackSet) == 0 {
		return nil, fmt.Errorf("cannot create snapshots: rollback set is empty")
	}
	if cowSizeMB <= 0 {
		cowSizeMB = 2048 // 2GB default COW size
	}

	created := make([]*models.Snapshot, 0, len(rollbackSet))

	for _, entry := range rollbackSet {
		if err := security.ValidateLVName(entry.VG); err != nil {
			return created, fmt.Errorf("invalid VG name %q: %w", entry.VG, err)
		}
		if err := security.ValidateLVName(entry.LV); err != nil {
			return created, fmt.Errorf("invalid LV name %q: %w", entry.LV, err)
		}

		snapName := FormatSnapshotName(jobID, entry.LV)
		if err := security.ValidateLVName(snapName); err != nil {
			return created, fmt.Errorf("generated snapshot name %q is invalid: %w", snapName, err)
		}

		originDev := fmt.Sprintf("/dev/%s/%s", entry.VG, entry.LV)
		sizeArg := fmt.Sprintf("%dM", cowSizeMB)

		res, err := m.runner.Run(ctx, models.Operation{
			Ref:     fmt.Sprintf("op:lvm.snapshot.create:%s", entry.LV),
			ArgV:    []string{"sudo", "lvcreate", "-s", "-n", snapName, "-L", sizeArg, originDev},
			Timeout: 2 * time.Minute,
		})

		if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
			// Clean up already created snapshots before failing
			_ = m.CleanupSnapshots(ctx, created)
			return nil, fmt.Errorf("failed creating snapshot %s for %s: %s (stderr: %s)", snapName, originDev, err, res.Stderr)
		}

		snap := &models.Snapshot{
			SnapshotID:      fmt.Sprintf("snap_%s_%s", jobID, entry.LV),
			JobID:           jobID,
			VG:              entry.VG,
			OriginLV:        entry.LV,
			SnapshotLV:      snapName,
			Size:            sizeArg,
			CreatedAt:       time.Now().UTC(),
			Verified:        false,
			COWUsagePercent: 0.0,
			Status:          models.SnapshotActive,
		}

		created = append(created, snap)
	}

	return created, nil
}

// VerifySnapshots implements Phase 4: Snapshot Verification Gate.
// Verifies snapshot exists, origin matches, is active and not invalid,
// and COW space is healthy.
func (m *Manager) VerifySnapshots(ctx context.Context, snapshots []*models.Snapshot) error {
	if len(snapshots) == 0 {
		return fmt.Errorf("no snapshots provided for verification")
	}

	for _, snap := range snapshots {
		devPath := fmt.Sprintf("/dev/%s/%s", snap.VG, snap.SnapshotLV)

		res, err := m.runner.Run(ctx, models.Operation{
			Ref:  fmt.Sprintf("op:lvm.snapshot.verify:%s", snap.SnapshotLV),
			ArgV: []string{"sudo", "lvs", "--noheadings", "--nosuffix", "--units", "m", "-o", "lv_name,vg_name,origin,lv_attr,data_percent,lv_uuid", devPath},
		})

		if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
			return fmt.Errorf("snapshot %s verification query failed: %v", devPath, err)
		}

		fields := strings.Fields(res.Stdout)
		if len(fields) < 6 {
			return fmt.Errorf("snapshot %s verification failed: unexpected lvs output fields (%v)", devPath, fields)
		}

		lvName := fields[0]
		vgName := fields[1]
		origin := fields[2]
		lvAttr := fields[3]
		dataPercentStr := fields[4]
		lvUUID := fields[5]

		// 1. Verify name and VG
		if lvName != snap.SnapshotLV || vgName != snap.VG {
			return fmt.Errorf("snapshot identity mismatch: expected %s/%s, got %s/%s", snap.VG, snap.SnapshotLV, vgName, lvName)
		}

		// 2. Verify origin
		if origin != snap.OriginLV {
			return fmt.Errorf("snapshot origin mismatch: expected origin %s, got %s", snap.OriginLV, origin)
		}

		// 3. Verify active and not invalid
		// First char in lv_attr: 's' or 'S' means snapshot volume
		// Fifth char in lv_attr: 'a' or 'A' means active
		if len(lvAttr) < 5 || (lvAttr[0] != 's' && lvAttr[0] != 'S') {
			return fmt.Errorf("snapshot %s is not a valid snapshot type in LVM attributes: %s", snap.SnapshotLV, lvAttr)
		}
		// Check for invalid snapshot flag (5th attribute character 'I' or 'i' or 'd' indicates invalid snapshot)
		if len(lvAttr) > 4 && (lvAttr[4] == 'I' || lvAttr[4] == 'i' || lvAttr[4] == 'd') {
			snap.Status = models.SnapshotInvalid
			return fmt.Errorf("snapshot %s has become INVALID (COW overflow or corruption, attr: %s)", snap.SnapshotLV, lvAttr)
		}
		if lvAttr[4] != 'a' && lvAttr[4] != 'A' {
			return fmt.Errorf("snapshot %s is not active: %s", snap.SnapshotLV, lvAttr)
		}

		// 4. Verify COW usage percentage
		percent, err := strconv.ParseFloat(dataPercentStr, 64)
		if err == nil {
			snap.COWUsagePercent = percent
			if percent > 85.0 {
				return fmt.Errorf("snapshot %s COW usage is dangerously high (%.1f%%) before patch began", snap.SnapshotLV, percent)
			}
		}

		snap.LVUUID = lvUUID
		snap.Verified = true
	}

	return nil
}

// MonitorCOWUsage checks the current data_percent consumption of an active snapshot.
func (m *Manager) MonitorCOWUsage(ctx context.Context, snap *models.Snapshot) (float64, error) {
	devPath := fmt.Sprintf("/dev/%s/%s", snap.VG, snap.SnapshotLV)
	res, err := m.runner.Run(ctx, models.Operation{
		Ref:  fmt.Sprintf("op:lvm.snapshot.cow_usage:%s", snap.SnapshotLV),
		ArgV: []string{"sudo", "lvs", "--noheadings", "--nosuffix", "-o", "data_percent,lv_attr", devPath},
	})
	if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
		return 0, fmt.Errorf("failed monitoring COW usage on %s: %v", devPath, err)
	}

	fields := strings.Fields(res.Stdout)
	if len(fields) >= 2 {
		lvAttr := fields[1]
		if len(lvAttr) > 4 && (lvAttr[4] == 'I' || lvAttr[4] == 'i' || lvAttr[4] == 'd') {
			snap.Status = models.SnapshotInvalid
			return 100.0, fmt.Errorf("snapshot %s overflowed and is now INVALID", snap.SnapshotLV)
		}
	}

	if len(fields) >= 1 {
		val, parseErr := strconv.ParseFloat(fields[0], 64)
		if parseErr == nil {
			snap.COWUsagePercent = val
			return val, nil
		}
	}

	return 0, nil
}

// CleanupSnapshots removes snapshots after successful remediation or upon abort before patch.
func (m *Manager) CleanupSnapshots(ctx context.Context, snapshots []*models.Snapshot) error {
	var errs []string
	for _, snap := range snapshots {
		devPath := fmt.Sprintf("/dev/%s/%s", snap.VG, snap.SnapshotLV)
		res, err := m.runner.Run(ctx, models.Operation{
			Ref:     fmt.Sprintf("op:lvm.snapshot.remove:%s", snap.SnapshotLV),
			ArgV:    []string{"sudo", "lvremove", "-y", devPath},
			Timeout: 1 * time.Minute,
		})
		if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
			errs = append(errs, fmt.Sprintf("failed removing snapshot %s: %v", devPath, err))
		} else {
			snap.Status = models.SnapshotRemoved
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("snapshot cleanup failed: %s", strings.Join(errs, "; "))
	}
	return nil
}
