package patch

import (
	"context"
	"strings"
	"testing"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/ssh"
)

func TestPatchExecutionAptSuccess(t *testing.T) {
	ctx := context.Background()
	mock := ssh.NewMockRunner()
	zero := 0

	// Detect apt
	mock.RegisterHandler("op:pkg.detect:apt", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "/usr/bin/apt-get\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	// Upgrade openssl
	mock.RegisterHandler("op:pkg.upgrade:apt:openssl", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "Setting up openssl (1.1.1f-1ubuntu2.20) ...\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	// Restart nginx
	mock.RegisterHandler("op:service.restart:nginx", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	engine := NewEngine(mock)
	plan := &models.RemediationPlan{
		PlanID: "plan-upgrade-openssl",
		Operations: []models.RemediationOperation{
			{
				Type:            models.OpPkgUpgrade,
				Package:         "openssl",
				RestartServices: []string{"nginx"},
			},
		},
	}

	exec, err := engine.Execute(ctx, "job-upgrade", plan)
	if err != nil {
		t.Fatalf("unexpected execution failure: %v", err)
	}

	if exec.Outcome != models.OutcomeCompleted || *exec.ExitCode != 0 {
		t.Fatalf("unexpected execution outcome: %+v", exec)
	}

	ops := mock.ExecutedOps()
	if len(ops) < 3 {
		t.Fatalf("expected at least 3 operations (detect, upgrade, restart), got %d", len(ops))
	}
}

func TestRejectNonAllowlistedOperation(t *testing.T) {
	ctx := context.Background()
	mock := ssh.NewMockRunner()
	zero := 0

	mock.RegisterHandler("op:pkg.detect:apt", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero}, nil
	})

	engine := NewEngine(mock)
	plan := &models.RemediationPlan{
		PlanID: "plan-arbitrary",
		Operations: []models.RemediationOperation{
			{
				Type:    models.OperationType("shell.exec_raw"), // Unallowlisted!
				Package: "evil",
			},
		},
	}

	_, err := engine.Execute(ctx, "job-malicious", plan)
	if err == nil {
		t.Fatalf("SAFETY RULE 3 VIOLATION: non-allowlisted operation was executed!")
	}

	if !strings.Contains(err.Error(), "rejected non-allowlisted operation type") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestRejectCommandInjectionInPackage(t *testing.T) {
	ctx := context.Background()
	mock := ssh.NewMockRunner()
	zero := 0

	mock.RegisterHandler("op:pkg.detect:apt", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero}, nil
	})

	engine := NewEngine(mock)
	plan := &models.RemediationPlan{
		PlanID: "plan-injection",
		Operations: []models.RemediationOperation{
			{
				Type:    models.OpPkgUpgrade,
				Package: "openssl; rm -rf /", // Injection attempt!
			},
		},
	}

	_, err := engine.Execute(ctx, "job-injection", plan)
	if err == nil {
		t.Fatalf("command injection in package name was not rejected!")
	}
}
