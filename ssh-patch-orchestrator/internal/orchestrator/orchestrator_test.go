package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/approval"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/audit"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/patch"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/precheck"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/rollback"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/snapshot"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/ssh"
)

type mockValidationEngine struct {
	result *models.ValidationResult
	err    error
}

func (m *mockValidationEngine) Validate(ctx context.Context, jobID string, plan *models.RemediationPlan, baseline *models.Baseline) (*models.ValidationResult, error) {
	return m.result, m.err
}

func setupFullPipelineMock() *ssh.MockRunner {
	mock := ssh.NewMockRunner()
	zero := 0

	// 1. Prechecks
	mock.RegisterHandler("op:precheck.os", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "ID=ubuntu\nVERSION_ID=22.04\n"}, nil
	})
	mock.RegisterHandler("op:precheck.pkg_manager:apt", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "/usr/bin/apt-get\n"}, nil
	})
	mock.RegisterHandler("op:precheck.privileges", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero}, nil
	})
	mock.RegisterHandler("op:precheck.apt_lock", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		exit1 := 1
		return &models.CommandResult{ExitCode: &exit1}, nil
	})
	mock.RegisterHandler("op:precheck.disk_space", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/mapper/vg0-root 41943040 10485760 31457280 25% /\n"}, nil
	})
	mock.RegisterHandler("op:precheck.findmnt_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "/dev/mapper/vg0-root\n"}, nil
	})
	mock.RegisterHandler("op:precheck.lvs_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "  vg0 root\n"}, nil
	})
	mock.RegisterHandler("op:precheck.vg_free", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "  5120.00\n"}, nil
	})
	mock.RegisterHandler("op:precheck.dpkg_version:openssl", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "1.1.1f-1ubuntu2.19\n"}, nil
	})

	// 2. Snapshot Create & Verify
	mock.RegisterHandler("op:lvm.snapshot.create:root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "Logical volume created\n"}, nil
	})
	mock.RegisterHandler("op:lvm.snapshot.verify:sd_job_happy_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "sd_job_happy_root vg0 root swi-a-s--- 1.2 uuid-snap-1\n"}, nil
	})
	mock.RegisterHandler("op:lvm.snapshot.remove:sd_job_happy_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "removed\n"}, nil
	})

	// 3. Patch Execution
	mock.RegisterHandler("op:pkg.detect:apt", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero}, nil
	})
	mock.RegisterHandler("op:pkg.upgrade:apt:openssl", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "upgraded\n"}, nil
	})

	return mock
}

func TestEndToEndHappyPathRemediation(t *testing.T) {
	ctx := context.Background()
	mock := setupFullPipelineMock()
	auditStore := audit.NewMemoryWriter()

	job := &models.PatchJob{
		JobID:              "job_happy",
		IncidentID:         "inc_001",
		AssetID:            "ast_001",
		State:              models.StateDetected,
		VulnerabilityStatus: models.VulnStatusPresent,
		CreatedAt:          time.Now().UTC(),
	}

	asset := &models.TargetAsset{
		AssetID:     "ast_001",
		Criticality: models.CriticalityLow,
	}

	plan := &models.RemediationPlan{
		PlanID: "plan_001",
		Operations: []models.RemediationOperation{
			{
				Type:          models.OpPkgUpgrade,
				Package:       "openssl",
				TargetVersion: "1.1.1f-1ubuntu2.20",
			},
		},
	}

	pre := precheck.NewPrecheckEngine(mock)
	snap := snapshot.NewManager(mock)
	pat := patch.NewEngine(mock)
	val := &mockValidationEngine{
		result: &models.ValidationResult{
			Result:              models.ValidationPassed,
			VulnerabilityStatus: models.VulnStatusFixed,
		},
	}
	rb := rollback.NewManager(mock)
	apr := approval.NewDefaultEvaluator(false)

	orch := NewOrchestrator(job, asset, plan, auditStore, pre, snap, pat, val, rb, apr)

	err := orch.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected pipeline failure: %v", err)
	}

	if orch.State() != models.StateRemediated {
		t.Fatalf("expected final state REMEDIATED, got: %s", orch.State())
	}

	if job.Outcome == nil || *job.Outcome != models.OutcomeRemediated {
		t.Fatalf("expected outcome REMEDIATED, got: %v", job.Outcome)
	}

	if job.VulnerabilityStatus != models.VulnStatusFixed {
		t.Fatalf("expected vulnerability FIXED, got: %s", job.VulnerabilityStatus)
	}

	events, _ := auditStore.Query(ctx, job.JobID)
	if len(events) < 8 {
		t.Fatalf("expected at least 8 audit events, got %d", len(events))
	}
}

func TestEndToEndPatchFailureTriggersRollbackAndHumanReview(t *testing.T) {
	ctx := context.Background()
	mock := setupFullPipelineMock()
	exit1 := 1
	zero := 0

	// Snapshot name for this test
	mock.RegisterHandler("op:lvm.snapshot.verify:sd_job_rb_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "sd_job_rb_root vg0 root swi-a-s--- 1.2 uuid-snap-rb\n"}, nil
	})

	// Make patch execution FAIL with exit code 100
	exit100 := 100
	mock.RegisterHandler("op:pkg.upgrade:apt:openssl", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &exit100,
			Stderr:     "dpkg failed to configure package",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	// Rollback handlers
	mock.RegisterHandler("op:lvm.rollback.merge:sd_job_rb_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "Merging started\n"}, nil
	})
	mock.RegisterHandler("op:lvm.rollback.check_merged:sd_job_rb_root", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &exit1}, nil
	})
	mock.RegisterHandler("op:rollback.check_version:openssl", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "1.1.1f-1ubuntu2.19\n"}, nil
	})

	auditStore := audit.NewMemoryWriter()
	job := &models.PatchJob{
		JobID:              "job_rb",
		State:              models.StateDetected,
		VulnerabilityStatus: models.VulnStatusPresent,
	}
	asset := &models.TargetAsset{AssetID: "ast_rb"}
	plan := &models.RemediationPlan{
		PlanID: "plan_rb",
		Operations: []models.RemediationOperation{
			{Type: models.OpPkgUpgrade, Package: "openssl"},
		},
	}

	pre := precheck.NewPrecheckEngine(mock)
	snap := snapshot.NewManager(mock)
	pat := patch.NewEngine(mock)
	val := &mockValidationEngine{}
	rb := rollback.NewManager(mock)
	apr := approval.NewDefaultEvaluator(false)

	orch := NewOrchestrator(job, asset, plan, auditStore, pre, snap, pat, val, rb, apr)

	_ = orch.Run(ctx)

	// CRITICAL SAFETY REQUIREMENT: Must end in ROLLED_BACK_HUMAN_REVIEW
	if orch.State() != models.StateRolledBackHumanReview {
		t.Fatalf("expected state ROLLED_BACK_HUMAN_REVIEW, got: %s", orch.State())
	}

	// CRITICAL REPORTING RULE: Must report RESTORED_VULNERABILITY_REMAINS and vulnerability PRESENT!
	if job.Outcome == nil || *job.Outcome != models.OutcomeRestoredVulnerabilityRemains {
		t.Fatalf("expected outcome RESTORED_VULNERABILITY_REMAINS, got: %v", job.Outcome)
	}
	if job.VulnerabilityStatus != models.VulnStatusPresent {
		t.Fatalf("SAFETY RULE VIOLATION: rolled back job marked vulnerability as %s instead of PRESENT", job.VulnerabilityStatus)
	}
}

func TestPrecheckFailureStopsBeforeSnapshotOrPatch(t *testing.T) {
	ctx := context.Background()
	mock := setupFullPipelineMock()
	zero := 0

	// Force OS to be unsupported
	mock.RegisterHandler("op:precheck.os", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "ID=solaris\nVERSION_ID=11\n"}, nil
	})

	auditStore := audit.NewMemoryWriter()
	job := &models.PatchJob{
		JobID: "job_precheck_fail",
		State: models.StateDetected,
	}
	asset := &models.TargetAsset{AssetID: "ast_precheck_fail"}
	plan := &models.RemediationPlan{
		PlanID: "plan_fail",
		Operations: []models.RemediationOperation{
			{Type: models.OpPkgUpgrade, Package: "openssl"},
		},
	}

	pre := precheck.NewPrecheckEngine(mock)
	snap := snapshot.NewManager(mock)
	pat := patch.NewEngine(mock)
	val := &mockValidationEngine{}
	rb := rollback.NewManager(mock)
	apr := approval.NewDefaultEvaluator(false)

	orch := NewOrchestrator(job, asset, plan, auditStore, pre, snap, pat, val, rb, apr)

	_ = orch.Run(ctx)

	// State machine must lead to HUMAN_REVIEW
	if orch.State() != models.StateHumanReview {
		t.Fatalf("expected final state HUMAN_REVIEW after precheck failure, got: %s", orch.State())
	}

	if job.Outcome == nil || *job.Outcome != models.OutcomePrecheckFailedHumanReview {
		t.Fatalf("unexpected outcome: %v", job.Outcome)
	}
}
