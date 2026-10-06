package validation

import (
	"context"
	"testing"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/ssh"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int // -1 (v1 < v2), 0 (v1 == v2), 1 (v1 > v2)
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.1.1f-1ubuntu2.20", "1.1.1f-1ubuntu2.19", 1},
		{"1.1.1f-1ubuntu2.19", "1.1.1f-1ubuntu2.20", -1},
		{"2:1.0", "1:2.0", 1},   // Epoch check
		{"1.0~beta1", "1.0", -1}, // Tilde check (Debian sorts ~ before anything)
		{"1.0", "1.0~beta1", 1},
		{"1.2.3.4", "1.2.3.5", -1},
	}

	for _, tt := range tests {
		got := CompareVersions(tt.v1, tt.v2)
		if got != tt.expected {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.expected)
		}
	}
}

func TestValidationSuccessful(t *testing.T) {
	ctx := context.Background()
	mock := ssh.NewMockRunner()
	zero := 0

	// Version read-back returns updated version 1.1.1f-1ubuntu2.20
	mock.RegisterHandler("op:validation.version.dpkg:openssl", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "1.1.1f-1ubuntu2.20\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	// Service state is active
	mock.RegisterHandler("op:validation.service_state:nginx", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "active\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	// No failed systemd units
	mock.RegisterHandler("op:validation.failed_units", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	engine := NewEngine(mock)
	plan := &models.RemediationPlan{
		PlanID: "plan-val-ok",
		Operations: []models.RemediationOperation{
			{
				Type:            models.OpPkgUpgrade,
				Package:         "openssl",
				TargetVersion:   "1.1.1f-1ubuntu2.20",
				RestartServices: []string{"nginx"},
			},
		},
		SuccessCriteria: models.SuccessCriteria{
			MinPackageVersion: "1.1.1f-1ubuntu2.20",
		},
	}

	baseline := &models.Baseline{
		PackageVersions: map[string]string{"openssl": "1.1.1f-1ubuntu2.19"},
		ServiceStates:   map[string]string{"nginx": "active"},
	}

	result, err := engine.Validate(ctx, "job-val-ok", plan, baseline)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if result.Result != models.ValidationPassed {
		t.Fatalf("expected validation to pass, got: %s", result.Result)
	}

	if result.VulnerabilityStatus != models.VulnStatusFixed {
		t.Fatalf("expected vulnerability status to be FIXED, got: %s", result.VulnerabilityStatus)
	}
}

// Critical Safety Rule 2 & 5: Version unchanged from baseline must FAIL validation
func TestValidationFailsWhenVersionUnchangedFromBaseline(t *testing.T) {
	ctx := context.Background()
	mock := ssh.NewMockRunner()
	zero := 0

	// Host still returns vulnerable baseline version
	mock.RegisterHandler("op:validation.version.dpkg:openssl", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "1.1.1f-1ubuntu2.19\n", // Unchanged!
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	mock.RegisterHandler("op:validation.service_state:nginx", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "active\n"}, nil
	})

	mock.RegisterHandler("op:validation.failed_units", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "\n"}, nil
	})

	engine := NewEngine(mock)
	plan := &models.RemediationPlan{
		PlanID: "plan-val-fail",
		Operations: []models.RemediationOperation{
			{
				Type:          models.OpPkgUpgrade,
				Package:       "openssl",
				TargetVersion: "1.1.1f-1ubuntu2.20",
			},
		},
	}

	baseline := &models.Baseline{
		PackageVersions: map[string]string{"openssl": "1.1.1f-1ubuntu2.19"},
	}

	result, err := engine.Validate(ctx, "job-val-fail", plan, baseline)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Result == models.ValidationPassed {
		t.Fatalf("SAFETY RULE 2 VIOLATION: validation passed despite version being unchanged from vulnerable baseline!")
	}

	if result.VulnerabilityStatus == models.VulnStatusFixed {
		t.Fatalf("SAFETY RULE 5 VIOLATION: vulnerability marked FIXED despite failed validation!")
	}
}

func TestValidationFailsWhenServiceIsDegraded(t *testing.T) {
	ctx := context.Background()
	mock := ssh.NewMockRunner()
	zero := 0

	mock.RegisterHandler("op:validation.version.dpkg:openssl", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "1.1.1f-1ubuntu2.20\n"}, nil
	})

	// Service crashed/failed
	mock.RegisterHandler("op:validation.service_state:nginx", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "failed\n", // Broken service!
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	mock.RegisterHandler("op:validation.failed_units", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{ExitCode: &zero, Stdout: "\n"}, nil
	})

	engine := NewEngine(mock)
	plan := &models.RemediationPlan{
		PlanID: "plan-svc-fail",
		Operations: []models.RemediationOperation{
			{
				Type:            models.OpPkgUpgrade,
				Package:         "openssl",
				RestartServices: []string{"nginx"},
			},
		},
	}

	baseline := &models.Baseline{
		PackageVersions: map[string]string{"openssl": "1.1.1f-1ubuntu2.19"},
		ServiceStates:   map[string]string{"nginx": "active"},
	}

	result, err := engine.Validate(ctx, "job-svc-fail", plan, baseline)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Result == models.ValidationPassed {
		t.Fatalf("expected validation to fail when service state degraded to 'failed'")
	}
}
