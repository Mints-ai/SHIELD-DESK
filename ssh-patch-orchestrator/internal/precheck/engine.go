package precheck

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/security"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/ssh"
)

// PrecheckEngine evaluates a target Linux host to determine if patch execution
// and LVM rollback are possible, and captures pre-patch baselines.
type PrecheckEngine struct {
	runner ssh.Runner
}

// NewPrecheckEngine creates a new precheck engine using the provided Runner.
func NewPrecheckEngine(runner ssh.Runner) *PrecheckEngine {
	return &PrecheckEngine{
		runner: runner,
	}
}

// Run executes all required prechecks and returns a PrecheckResult.
func (e *PrecheckEngine) Run(ctx context.Context, jobID string, asset *models.TargetAsset, plan *models.RemediationPlan) (*models.PrecheckResult, error) {
	result := &models.PrecheckResult{
		JobID:    jobID,
		Passed:   true,
		Checks:   make([]models.PrecheckItem, 0),
		Baseline: &models.Baseline{
			PackageVersions: make(map[string]string),
			ServiceStates:   make(map[string]string),
		},
		RollbackSet: make([]models.RollbackSetEntry, 0),
	}

	addCheck := func(name string, pass bool, detail string) bool {
		status := models.PrecheckPass
		if !pass {
			status = models.PrecheckFail
			result.Passed = false
			if result.FailReason == "" {
				result.FailReason = fmt.Sprintf("%s: %s", name, detail)
			}
		}
		result.Checks = append(result.Checks, models.PrecheckItem{
			Name:   name,
			Result: status,
			Detail: detail,
		})
		return pass
	}

	// 1. Check OS
	osName, osVersion, err := e.detectOS(ctx)
	if err != nil {
		addCheck("os_supported", false, fmt.Sprintf("failed detecting OS: %v", err))
		return result, nil
	}
	if !isSupportedOS(osName) {
		addCheck("os_supported", false, fmt.Sprintf("unsupported OS %q (%s)", osName, osVersion))
		return result, nil
	}
	addCheck("os_supported", true, fmt.Sprintf("%s %s", osName, osVersion))

	// 2. Check Package Manager
	pkgMgr, err := e.detectPackageManager(ctx)
	if err != nil || pkgMgr == "" {
		addCheck("package_manager", false, "no supported package manager (apt/dnf/yum) found")
		return result, nil
	}
	addCheck("package_manager", true, pkgMgr)

	// 3. Check Privileges (must have passwordless sudo or root)
	hasPriv, privDetail := e.checkPrivileges(ctx)
	if !addCheck("required_privileges", hasPriv, privDetail) {
		return result, nil
	}

	// 4. Check Package Manager Locks
	isLocked, lockDetail := e.checkPackageLocks(ctx, pkgMgr)
	if !addCheck("package_manager_unlocked", !isLocked, lockDetail) {
		return result, nil
	}

	// 5. Check Disk Space (need at least 1GB on /)
	diskOK, diskDetail := e.checkDiskSpace(ctx, "/")
	if !addCheck("disk_space_root", diskOK, diskDetail) {
		return result, nil
	}

	// 6. Check Non-LVM State Policy
	if plan.TouchesNonLVMState {
		addCheck("non_lvm_state_check", false, "remediation touches non-LVM state (/boot/EFI) which cannot be rolled back")
		return result, nil
	}
	addCheck("non_lvm_state_check", true, "remediation restricted to LVM-covered volumes")

	// 7. Check LVM availability & Discover Rollback Set
	rollbackSet, lvmErr := e.discoverRollbackSet(ctx)
	if lvmErr != nil {
		addCheck("lvm_available", false, fmt.Sprintf("LVM discovery failed: %v", lvmErr))
		return result, nil
	}
	if len(rollbackSet) == 0 {
		addCheck("lvm_available", false, "no LVM logical volumes identified for root filesystem")
		return result, nil
	}
	result.RollbackSet = rollbackSet
	addCheck("lvm_available", true, fmt.Sprintf("found %d volume(s) in rollback set", len(rollbackSet)))

	// 8. Check VG Free Space for Snapshots
	for _, entry := range rollbackSet {
		freeExtents, spaceErr := e.getVGFreeSpaceMB(ctx, entry.VG)
		if spaceErr != nil || freeExtents < 1024 { // require at least 1GB COW space per snapshot
			addCheck("vg_free_space", false, fmt.Sprintf("insufficient COW space in VG %s: %d MB free (minimum 1024 MB required)", entry.VG, freeExtents))
			return result, nil
		}
		addCheck("vg_free_space", true, fmt.Sprintf("VG %s has %d MB free for COW snapshot", entry.VG, freeExtents))
	}

	// 9. Baseline Capture: Package Versions
	for _, op := range plan.Operations {
		if op.Package != "" {
			if err := security.ValidatePackageName(op.Package); err != nil {
				addCheck("package_name_valid", false, err.Error())
				return result, nil
			}
			ver, verErr := e.getInstalledVersion(ctx, pkgMgr, op.Package)
			if verErr != nil {
				addCheck("baseline_package_state", false, fmt.Sprintf("failed to read installed version of %s: %v", op.Package, verErr))
				return result, nil
			}
			result.Baseline.PackageVersions[op.Package] = ver
		}

		// Services affected
		for _, svc := range op.RestartServices {
			if err := security.ValidateServiceName(svc); err != nil {
				addCheck("service_name_valid", false, err.Error())
				return result, nil
			}
			state, svcErr := e.getServiceState(ctx, svc)
			if svcErr != nil {
				addCheck("baseline_service_state", false, fmt.Sprintf("failed to read service state for %s: %v", svc, svcErr))
				return result, nil
			}
			result.Baseline.ServiceStates[svc] = state
		}
	}
	addCheck("baseline_captured", true, fmt.Sprintf("%d package(s), %d service(s)", len(result.Baseline.PackageVersions), len(result.Baseline.ServiceStates)))

	return result, nil
}

func (e *PrecheckEngine) detectOS(ctx context.Context) (name string, version string, err error) {
	res, err := e.runner.Run(ctx, models.Operation{
		Ref:     "op:precheck.os",
		ArgV:    []string{"cat", "/etc/os-release"},
		Timeout: 0,
	})
	if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
		return "", "", fmt.Errorf("reading /etc/os-release failed: %v", err)
	}

	lines := strings.Split(res.Stdout, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			name = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}
	return name, version, nil
}

func isSupportedOS(osID string) bool {
	switch strings.ToLower(osID) {
	case "ubuntu", "debian", "rhel", "centos", "rocky", "almalinux":
		return true
	default:
		return false
	}
}

func (e *PrecheckEngine) detectPackageManager(ctx context.Context) (string, error) {
	managers := []struct {
		name string
		bin  string
	}{
		{"apt", "apt-get"},
		{"dnf", "dnf"},
		{"yum", "yum"},
	}

	for _, m := range managers {
		res, err := e.runner.Run(ctx, models.Operation{
			Ref:  "op:precheck.pkg_manager:" + m.name,
			ArgV: []string{"which", m.bin},
		})
		if err == nil && res.ExitCode != nil && *res.ExitCode == 0 {
			return m.name, nil
		}
	}
	return "", nil
}

func (e *PrecheckEngine) checkPrivileges(ctx context.Context) (bool, string) {
	res, err := e.runner.Run(ctx, models.Operation{
		Ref:  "op:precheck.privileges",
		ArgV: []string{"sudo", "-n", "true"},
	})
	if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
		return false, "account lacks non-interactive sudo privileges (sudo -n true failed)"
	}
	return true, "passwordless sudo verified"
}

func (e *PrecheckEngine) checkPackageLocks(ctx context.Context, pkgMgr string) (bool, string) {
	if pkgMgr == "apt" {
		res, err := e.runner.Run(ctx, models.Operation{
			Ref:  "op:precheck.apt_lock",
			ArgV: []string{"fuser", "/var/lib/dpkg/lock-frontend"},
		})
		// If fuser returns exit code 0, a process holds the lock
		if err == nil && res.ExitCode != nil && *res.ExitCode == 0 {
			return true, "apt is locked by another process (/var/lib/dpkg/lock-frontend in use)"
		}
	}
	return false, "package manager is not locked"
}

func (e *PrecheckEngine) checkDiskSpace(ctx context.Context, mountPoint string) (bool, string) {
	res, err := e.runner.Run(ctx, models.Operation{
		Ref:  "op:precheck.disk_space",
		ArgV: []string{"df", "-Pk", mountPoint},
	})
	if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
		return false, fmt.Sprintf("unable to check disk space on %s", mountPoint)
	}

	lines := strings.Split(strings.TrimSpace(res.Stdout), "\n")
	if len(lines) < 2 {
		return false, "unexpected df output format"
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		return false, "failed parsing df fields"
	}

	availableKB, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return false, fmt.Sprintf("parsing free space KB failed: %v", err)
	}

	freeMB := availableKB / 1024
	if freeMB < 1024 {
		return false, fmt.Sprintf("free disk space %d MB is below minimum required 1024 MB", freeMB)
	}
	return true, fmt.Sprintf("%d MB free on %s", freeMB, mountPoint)
}

func (e *PrecheckEngine) discoverRollbackSet(ctx context.Context) ([]models.RollbackSetEntry, error) {
	// Find device mounted on /
	res, err := e.runner.Run(ctx, models.Operation{
		Ref:  "op:precheck.findmnt_root",
		ArgV: []string{"findmnt", "-n", "-o", "SOURCE", "/"},
	})
	if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
		return nil, fmt.Errorf("failed executing findmnt for /: %v", err)
	}

	dev := strings.TrimSpace(res.Stdout)
	if dev == "" {
		return nil, fmt.Errorf("no source device found for /")
	}

	// Check if this device is an LVM logical volume via lvs
	lvsRes, err := e.runner.Run(ctx, models.Operation{
		Ref:  "op:precheck.lvs_root",
		ArgV: []string{"sudo", "lvs", "--noheadings", "-o", "vg_name,lv_name", dev},
	})
	if err != nil || lvsRes.ExitCode == nil || *lvsRes.ExitCode != 0 {
		return nil, fmt.Errorf("device %s is not a managed LVM logical volume (NO_LVM)", dev)
	}

	fields := strings.Fields(lvsRes.Stdout)
	if len(fields) < 2 {
		return nil, fmt.Errorf("could not parse VG/LV from lvs for %s", dev)
	}

	return []models.RollbackSetEntry{
		{
			VG:    fields[0],
			LV:    fields[1],
			Mount: "/",
		},
	}, nil
}

func (e *PrecheckEngine) getVGFreeSpaceMB(ctx context.Context, vgName string) (int64, error) {
	res, err := e.runner.Run(ctx, models.Operation{
		Ref:  "op:precheck.vg_free",
		ArgV: []string{"sudo", "vgs", "--noheadings", "--units", "m", "--nosuffix", "-o", "vg_free", vgName},
	})
	if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
		return 0, fmt.Errorf("failed running vgs for %s: %v", vgName, err)
	}

	str := strings.TrimSpace(res.Stdout)
	// Handle float or integer string
	val, err := strconv.ParseFloat(str, 64)
	if err != nil {
		return 0, fmt.Errorf("failed parsing vg_free %q: %v", str, err)
	}
	return int64(val), nil
}

func (e *PrecheckEngine) getInstalledVersion(ctx context.Context, pkgMgr, pkg string) (string, error) {
	if pkgMgr == "apt" {
		res, err := e.runner.Run(ctx, models.Operation{
			Ref:  "op:precheck.dpkg_version:" + pkg,
			ArgV: []string{"dpkg-query", "-W", "-f=${Version}", pkg},
		})
		if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
			return "", fmt.Errorf("dpkg-query failed: %v", err)
		}
		return strings.TrimSpace(res.Stdout), nil
	}

	// RPM (dnf/yum)
	res, err := e.runner.Run(ctx, models.Operation{
		Ref:  "op:precheck.rpm_version:" + pkg,
		ArgV: []string{"rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg},
	})
	if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
		return "", fmt.Errorf("rpm query failed: %v", err)
	}
	return strings.TrimSpace(res.Stdout), nil
}

func (e *PrecheckEngine) getServiceState(ctx context.Context, service string) (string, error) {
	res, err := e.runner.Run(ctx, models.Operation{
		Ref:  "op:precheck.service_state:" + service,
		ArgV: []string{"systemctl", "is-active", service},
	})
	if err != nil || res.ExitCode == nil {
		return "", fmt.Errorf("failed executing systemctl is-active: %v", err)
	}
	return strings.TrimSpace(res.Stdout), nil
}
