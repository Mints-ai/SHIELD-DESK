package patch

import (
	"context"
	"fmt"
	"time"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/security"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/ssh"
)

// Engine executes structured remediation operations using allowlisted templates.
// It explicitly denies unrestricted or arbitrary shell script execution.
type Engine struct {
	runner   ssh.Runner
	adapters map[string]PackageManager
}

// NewEngine creates a new patch execution engine.
func NewEngine(runner ssh.Runner) *Engine {
	e := &Engine{
		runner:   runner,
		adapters: make(map[string]PackageManager),
	}
	e.RegisterAdapter(NewAptAdapter())
	e.RegisterAdapter(NewDnfAdapter())
	return e
}

// RegisterAdapter adds a package manager adapter.
func (e *Engine) RegisterAdapter(adapter PackageManager) {
	e.adapters[adapter.Name()] = adapter
}

// DetectPackageManager queries the target to determine the applicable adapter.
func (e *Engine) DetectPackageManager(ctx context.Context) (PackageManager, error) {
	for _, adapter := range e.adapters {
		detected, err := adapter.Detect(ctx, e.runner)
		if err == nil && detected {
			return adapter, nil
		}
	}
	return nil, fmt.Errorf("no supported package manager adapter detected on host")
}

// Execute applies the operations in the remediation plan sequentially.
// If any command fails or times out, execution stops immediately and returns the execution report.
func (e *Engine) Execute(ctx context.Context, jobID string, plan *models.RemediationPlan) (*models.PatchExecution, error) {
	if len(plan.Operations) == 0 {
		return nil, fmt.Errorf("remediation plan contains no operations")
	}

	adapter, err := e.DetectPackageManager(ctx)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	execution := &models.PatchExecution{
		ExecutionID: fmt.Sprintf("exe_%s_%d", jobID, start.Unix()),
		JobID:       jobID,
		StartedAt:   start,
		Outcome:     models.OutcomeCompleted,
	}

	// 1. Process each allowlisted operation
	for _, op := range plan.Operations {
		execution.OperationRef = fmt.Sprintf("op:%s:%s", op.Type, op.Package)
		var res *models.CommandResult
		var opErr error

		switch op.Type {
		case models.OpPkgUpgrade:
			res, opErr = adapter.Upgrade(ctx, e.runner, op.Package, op.TargetVersion)

		case models.OpPkgInstall:
			res, opErr = adapter.Install(ctx, e.runner, op.Package, op.TargetVersion)

		case models.OpServiceRestart:
			res, opErr = e.restartService(ctx, op.ServiceName)

		case models.OpServiceReload:
			res, opErr = e.reloadService(ctx, op.ServiceName)

		default:
			// Fail-closed on any non-allowlisted operation type
			return nil, fmt.Errorf("SAFETY VIOLATION: rejected non-allowlisted operation type %q", op.Type)
		}

		if res != nil {
			execution.ExitCode = res.ExitCode
			execution.Outcome = res.Outcome
		}

		if opErr != nil || res == nil || res.ExitCode == nil || *res.ExitCode != 0 {
			execution.Duration = time.Since(start)
			return execution, fmt.Errorf("patch operation %s failed: %v", execution.OperationRef, opErr)
		}

		// If operation specified restart services, restart them now
		for _, svc := range op.RestartServices {
			svcRes, svcErr := e.restartService(ctx, svc)
			if svcErr != nil || svcRes == nil || svcRes.ExitCode == nil || *svcRes.ExitCode != 0 {
				execution.Duration = time.Since(start)
				execution.OperationRef = fmt.Sprintf("op:service.restart:%s", svc)
				if svcRes != nil {
					execution.ExitCode = svcRes.ExitCode
					execution.Outcome = svcRes.Outcome
				}
				return execution, fmt.Errorf("post-patch service restart failed for %s: %v", svc, svcErr)
			}
		}
	}

	execution.Duration = time.Since(start)
	return execution, nil
}

func (e *Engine) restartService(ctx context.Context, service string) (*models.CommandResult, error) {
	if err := security.ValidateServiceName(service); err != nil {
		return nil, err
	}
	return e.runner.Run(ctx, models.Operation{
		Ref:     fmt.Sprintf("op:service.restart:%s", service),
		ArgV:    []string{"sudo", "systemctl", "restart", service},
		Timeout: 2 * time.Minute,
	})
}

func (e *Engine) reloadService(ctx context.Context, service string) (*models.CommandResult, error) {
	if err := security.ValidateServiceName(service); err != nil {
		return nil, err
	}
	return e.runner.Run(ctx, models.Operation{
		Ref:     fmt.Sprintf("op:service.reload:%s", service),
		ArgV:    []string{"sudo", "systemctl", "reload", service},
		Timeout: 2 * time.Minute,
	})
}
