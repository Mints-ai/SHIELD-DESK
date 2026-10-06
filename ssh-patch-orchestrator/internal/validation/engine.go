package validation

import (
	"context"
	"fmt"
	"strings"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/security"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/ssh"
)

// Engine performs post-patch validation.
// CRITICAL SAFETY RULE 2: NEVER treat patch command success as proof of remediation.
// CRITICAL SAFETY RULE 5: NEVER report a vulnerability as fixed unless validation confirms it.
type Engine struct {
	runner ssh.Runner
}

// NewEngine creates a new validation engine.
func NewEngine(runner ssh.Runner) *Engine {
	return &Engine{
		runner: runner,
	}
}

// Validate executes all validation checks against the target host.
func (e *Engine) Validate(ctx context.Context, jobID string, plan *models.RemediationPlan, baseline *models.Baseline) (*models.ValidationResult, error) {
	result := &models.ValidationResult{
		JobID:               jobID,
		Result:              models.ValidationPassed,
		Checks:              make([]models.ValidationCheck, 0),
		VulnerabilityStatus: models.VulnStatusPresent, // Default to present until confirmed fixed
	}

	failValidation := func(name, expected, actual, detail string) {
		result.Result = models.ValidationFailed
		result.Checks = append(result.Checks, models.ValidationCheck{
			Name:     name,
			Result:   "FAIL",
			Expected: expected,
			Actual:   actual,
			Detail:   detail,
		})
	}

	passCheck := func(name, expected, actual, detail string) {
		result.Checks = append(result.Checks, models.ValidationCheck{
			Name:     name,
			Result:   "PASS",
			Expected: expected,
			Actual:   actual,
			Detail:   detail,
		})
	}

	// 1. Verify Package Versions
	for _, op := range plan.Operations {
		if op.Package == "" {
			continue
		}

		if err := security.ValidatePackageName(op.Package); err != nil {
			failValidation("package_name_safe", "valid name", op.Package, err.Error())
			return result, nil
		}

		currentVer, err := e.getInstalledVersion(ctx, op.Package)
		if err != nil {
			failValidation("package_version_readable", "installed version", "error", err.Error())
			return result, nil
		}

		// Check against baseline: Must not be equal to vulnerable baseline (unless baseline was empty)
		if baseline != nil {
			baseVer, exists := baseline.PackageVersions[op.Package]
			if exists && baseVer != "" && currentVer == baseVer {
				failValidation(
					fmt.Sprintf("package_version_changed:%s", op.Package),
					fmt.Sprintf("> %s", baseVer),
					currentVer,
					"package version did not change from vulnerable pre-patch baseline",
				)
				return result, nil
			}
		}

		// Check against target version or success criteria
		minVersion := op.TargetVersion
		if plan.SuccessCriteria.MinPackageVersion != "" {
			minVersion = plan.SuccessCriteria.MinPackageVersion
		}

		if minVersion != "" {
			cmp := CompareVersions(currentVer, minVersion)
			if cmp < 0 {
				failValidation(
					fmt.Sprintf("package_version_target:%s", op.Package),
					fmt.Sprintf(">= %s", minVersion),
					currentVer,
					fmt.Sprintf("installed version %s is lower than required target version %s", currentVer, minVersion),
				)
				return result, nil
			}
			passCheck(
				fmt.Sprintf("package_version:%s", op.Package),
				fmt.Sprintf(">= %s", minVersion),
				currentVer,
				"package version meets or exceeds remediation target",
			)
		} else {
			passCheck(
				fmt.Sprintf("package_version:%s", op.Package),
				"changed from baseline",
				currentVer,
				"package successfully updated",
			)
		}

		// 2. Verify Service Health
		for _, svc := range op.RestartServices {
			if err := security.ValidateServiceName(svc); err != nil {
				failValidation("service_name_safe", "valid name", svc, err.Error())
				return result, nil
			}

			currentState, err := e.getServiceState(ctx, svc)
			if err != nil {
				failValidation(fmt.Sprintf("service_health:%s", svc), "active", "error", err.Error())
				return result, nil
			}

			expectedState := "active"
			if baseline != nil {
				if baseState, exists := baseline.ServiceStates[svc]; exists && baseState != "" {
					expectedState = baseState
				}
			}

			if currentState != expectedState {
				failValidation(
					fmt.Sprintf("service_health:%s", svc),
					expectedState,
					currentState,
					fmt.Sprintf("service %s state is %q, expected %q", svc, currentState, expectedState),
				)
				return result, nil
			}

			passCheck(
				fmt.Sprintf("service_health:%s", svc),
				expectedState,
				currentState,
				"service is running and healthy",
			)
		}
	}

	// 3. System Sanity Check: No failed systemd units
	failedUnits, err := e.getFailedSystemdUnits(ctx)
	if err == nil && len(failedUnits) > 0 {
		failValidation(
			"system_health",
			"0 failed units",
			fmt.Sprintf("%d failed unit(s)", len(failedUnits)),
			fmt.Sprintf("failed system units: %s", strings.Join(failedUnits, ", ")),
		)
		return result, nil
	}
	passCheck("system_health", "0 failed units", "0 failed units", "host system units healthy")

	// If all passed, confirm remediation
	if result.Result == models.ValidationPassed {
		result.VulnerabilityStatus = models.VulnStatusFixed
	}

	return result, nil
}

func (e *Engine) getInstalledVersion(ctx context.Context, pkg string) (string, error) {
	// Try dpkg-query first
	res, err := e.runner.Run(ctx, models.Operation{
		Ref:  "op:validation.version.dpkg:" + pkg,
		ArgV: []string{"dpkg-query", "-W", "-f=${Version}", pkg},
	})
	if err == nil && res.ExitCode != nil && *res.ExitCode == 0 {
		return strings.TrimSpace(res.Stdout), nil
	}

	// Try rpm
	resRPM, errRPM := e.runner.Run(ctx, models.Operation{
		Ref:  "op:validation.version.rpm:" + pkg,
		ArgV: []string{"rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg},
	})
	if errRPM == nil && resRPM.ExitCode != nil && *resRPM.ExitCode == 0 {
		return strings.TrimSpace(resRPM.Stdout), nil
	}

	return "", fmt.Errorf("failed querying package version for %s", pkg)
}

func (e *Engine) getServiceState(ctx context.Context, service string) (string, error) {
	res, err := e.runner.Run(ctx, models.Operation{
		Ref:  "op:validation.service_state:" + service,
		ArgV: []string{"systemctl", "is-active", service},
	})
	if err != nil || res.ExitCode == nil {
		return "", fmt.Errorf("failed querying service status: %v", err)
	}
	return strings.TrimSpace(res.Stdout), nil
}

func (e *Engine) getFailedSystemdUnits(ctx context.Context) ([]string, error) {
	res, err := e.runner.Run(ctx, models.Operation{
		Ref:  "op:validation.failed_units",
		ArgV: []string{"systemctl", "--failed", "--no-legend", "--plain"},
	})
	if err != nil || res.ExitCode == nil || *res.ExitCode != 0 {
		return nil, fmt.Errorf("failed querying systemctl --failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(res.Stdout), "\n")
	var failed []string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] != "" {
			failed = append(failed, fields[0])
		}
	}
	return failed, nil
}
