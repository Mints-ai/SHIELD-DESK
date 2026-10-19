package orchestrator

import (
	"context"
	"fmt"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/approval"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/audit"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/patch"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/precheck"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/rollback"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/snapshot"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/ssh"
	"testing"
)

func manualRollbackFixture(t *testing.T) (*Orchestrator, *ssh.MockRunner) {
	t.Helper()
	runner := setupFullPipelineMock()
	job := &models.PatchJob{JobID: "job_happy", State: models.StateDetected, VulnerabilityStatus: models.VulnStatusPresent}
	asset := &models.TargetAsset{AssetID: "test", Criticality: models.CriticalityLow}
	plan := &models.RemediationPlan{PlanID: "test", Operations: []models.RemediationOperation{{Type: models.OpPkgUpgrade, Package: "openssl", TargetVersion: "1.1.1f-1ubuntu2.20"}}}
	o := NewOrchestrator(job, asset, plan, audit.NewMemoryWriter(), precheck.NewPrecheckEngine(runner), snapshot.NewManager(runner), patch.NewEngine(runner), &mockValidationEngine{result: &models.ValidationResult{Result: models.ValidationPassed}}, rollback.NewManager(runner), approval.NewDefaultEvaluator(false))
	o.RetainSnapshots()
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	zero, one := 0, 1
	runner.RegisterHandler("op:lvm.rollback.merge:sd_job_happy_root", func(context.Context, models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero}, nil
	})
	runner.RegisterHandler("op:lvm.rollback.check_merged:sd_job_happy_root", func(context.Context, models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &one}, nil
	})
	runner.RegisterHandler("op:rollback.check_version:openssl", func(context.Context, models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "1.1.1f-1ubuntu2.19\n"}, nil
	})
	return o, runner
}

func TestManualRollbackRetainsSnapshotAndVerifiesBaseline(t *testing.T) {
	o, runner := manualRollbackFixture(t)
	for _, op := range runner.ExecutedOps() {
		if op.Ref == "op:lvm.snapshot.remove:sd_job_happy_root" {
			t.Fatal("snapshot was removed before manual rollback")
		}
	}
	done, err := o.StartManualRollback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if o.State() != models.StateRolledBackHumanReview || o.Job().VulnerabilityStatus != models.VulnStatusPresent {
		t.Fatal("restore was not verified as vulnerable baseline")
	}
	if _, err := o.StartManualRollback(context.Background()); err == nil {
		t.Fatal("repeated rollback must be rejected")
	}
}

func TestManualRollbackReportsSSHFailureWithoutPanic(t *testing.T) {
	o, runner := manualRollbackFixture(t)
	runner.RegisterHandler("op:lvm.rollback.merge:sd_job_happy_root", func(context.Context, models.Operation) (*models.CommandResult, error) {
		return nil, fmt.Errorf("SSH disconnected")
	})
	done, err := o.StartManualRollback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("merge failure must be reported")
	}
	if o.State() != models.StateEscalatedUrgent {
		t.Fatal("failed recovery must escalate")
	}
}

func TestManualRollbackRejectsConcurrentRequests(t *testing.T) {
	o, runner := manualRollbackFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	zero := 0
	runner.RegisterHandler("op:lvm.rollback.merge:sd_job_happy_root", func(context.Context, models.Operation) (*models.CommandResult, error) {
		close(entered)
		<-release
		return &models.CommandResult{ExitCode: &zero}, nil
	})
	done, err := o.StartManualRollback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	_, duplicateErr := o.StartManualRollback(context.Background())
	close(release)
	if duplicateErr == nil {
		t.Fatal("concurrent rollback must be rejected")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
