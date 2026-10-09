package precheck

import (
	"context"
	"strings"
	"testing"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/ssh"
)

func setupHealthyUbuntuMock() *ssh.MockRunner {
	r := ssh.NewMockRunner()
	zero := 0

	r.RegisterHandler("op:precheck.os", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "NAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nID=ubuntu\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	r.RegisterHandler("op:precheck.pkg_manager:apt", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "/usr/bin/apt-get\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	r.RegisterHandler("op:precheck.privileges", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	r.RegisterHandler("op:precheck.apt_lock", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		exit1 := 1 // fuser exit 1 means no lock
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &exit1,
			Stdout:     "",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	r.RegisterHandler("op:precheck.disk_space", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/mapper/vg0-root 41943040 10485760 31457280 25% /\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	r.RegisterHandler("op:precheck.findmnt_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "/dev/mapper/vg0-root\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	r.RegisterHandler("op:precheck.lvs_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "  vg0 root\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	r.RegisterHandler("op:precheck.vg_free", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "  10240.00\n", // 10 GB free
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	r.RegisterHandler("op:precheck.dpkg_version:openssl", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "1.1.1f-1ubuntu2.19\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	r.RegisterHandler("op:precheck.service_state:nginx", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "active\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	return r
}

func TestPrecheckHealthySuccess(t *testing.T) {
	ctx := context.Background()
	mock := setupHealthyUbuntuMock()
	engine := NewPrecheckEngine(mock)

	plan := &models.RemediationPlan{
		PlanID:          "plan-1",
		VulnerabilityID: "CVE-2023-0001",
		Operations: []models.RemediationOperation{
			{
				Type:            models.OpPkgUpgrade,
				Package:         "openssl",
				RestartServices: []string{"nginx"},
			},
		},
		TouchesNonLVMState: false,
	}

	asset := &models.TargetAsset{
		AssetID:  "ast-1",
		Hostname: "srv-01",
	}

	result, err := engine.Run(ctx, "job-1", asset, plan)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Passed {
		t.Fatalf("expected precheck to pass, failed with reason: %s", result.FailReason)
	}

	if len(result.RollbackSet) != 1 || result.RollbackSet[0].VG != "vg0" || result.RollbackSet[0].LV != "root" {
		t.Fatalf("unexpected rollback set: %+v", result.RollbackSet)
	}

	if result.Baseline.PackageVersions["openssl"] != "1.1.1f-1ubuntu2.19" {
		t.Fatalf("unexpected baseline package version: %s", result.Baseline.PackageVersions["openssl"])
	}

	if result.Baseline.ServiceStates["nginx"] != "active" {
		t.Fatalf("unexpected baseline service state: %s", result.Baseline.ServiceStates["nginx"])
	}
}

func TestPrecheckUnsupportedOSFails(t *testing.T) {
	ctx := context.Background()
	mock := setupHealthyUbuntuMock()
	zero := 0

	mock.RegisterHandler("op:precheck.os", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "ID=freebsd\nVERSION_ID=13.2\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	engine := NewPrecheckEngine(mock)
	plan := &models.RemediationPlan{PlanID: "plan-2"}
	asset := &models.TargetAsset{AssetID: "ast-2"}

	result, err := engine.Run(ctx, "job-2", asset, plan)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Passed {
		t.Fatalf("expected precheck to fail for unsupported OS FreeBSD")
	}

	if !strings.Contains(result.FailReason, "unsupported OS") {
		t.Fatalf("unexpected fail reason: %s", result.FailReason)
	}
}

func TestPrecheckNoLVMFails(t *testing.T) {
	ctx := context.Background()
	mock := setupHealthyUbuntuMock()
	exit1 := 1

	// lvs fails on non-LVM device
	mock.RegisterHandler("op:precheck.lvs_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &exit1,
			Stderr:     "Device /dev/sda1 not found",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	engine := NewPrecheckEngine(mock)
	plan := &models.RemediationPlan{PlanID: "plan-3"}
	asset := &models.TargetAsset{AssetID: "ast-3"}

	result, err := engine.Run(ctx, "job-3", asset, plan)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Passed {
		t.Fatalf("expected precheck to fail on non-LVM host")
	}

	if !strings.Contains(result.FailReason, "NO_LVM") {
		t.Fatalf("expected NO_LVM in fail reason, got: %s", result.FailReason)
	}
}

func TestPrecheckInsufficientCOWSpaceFails(t *testing.T) {
	ctx := context.Background()
	mock := setupHealthyUbuntuMock()
	zero := 0

	// Free space only 256 MB (less than 1024 MB required)
	mock.RegisterHandler("op:precheck.vg_free", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "  256.00\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	engine := NewPrecheckEngine(mock)
	plan := &models.RemediationPlan{PlanID: "plan-4"}
	asset := &models.TargetAsset{AssetID: "ast-4"}

	result, err := engine.Run(ctx, "job-4", asset, plan)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Passed {
		t.Fatalf("expected precheck to fail when COW space is insufficient")
	}

	if !strings.Contains(result.FailReason, "insufficient COW space") {
		t.Fatalf("unexpected fail reason: %s", result.FailReason)
	}
}

func TestPrecheckNonLVMStateCheckFails(t *testing.T) {
	ctx := context.Background()
	mock := setupHealthyUbuntuMock()
	engine := NewPrecheckEngine(mock)

	plan := &models.RemediationPlan{
		PlanID:             "plan-5",
		TouchesNonLVMState: true, // e.g. kernel update modifying non-LVM /boot
	}
	asset := &models.TargetAsset{AssetID: "ast-5"}

	result, err := engine.Run(ctx, "job-5", asset, plan)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Passed {
		t.Fatalf("expected precheck to fail when remediation touches non-LVM state")
	}
}
