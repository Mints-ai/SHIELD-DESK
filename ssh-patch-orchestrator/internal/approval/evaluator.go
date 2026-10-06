package approval

import (
	"context"
	"fmt"
	"strings"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
)

// Evaluator checks whether a patch job is permitted to auto-execute or requires approval.
type Evaluator interface {
	Evaluate(ctx context.Context, job *models.PatchJob, asset *models.TargetAsset) (*models.PolicyDecision, error)
	VerifyApproval(ctx context.Context, approvalRef string, jobID string) error
}

// DefaultEvaluator is the MVP policy evaluator stub.
// Auto-executes Low and Medium criticality assets, requires human approval for High/Critical.
type DefaultEvaluator struct {
	ForceApproval bool
}

func NewDefaultEvaluator(forceApproval bool) *DefaultEvaluator {
	return &DefaultEvaluator{
		ForceApproval: forceApproval,
	}
}

func (e *DefaultEvaluator) Evaluate(ctx context.Context, job *models.PatchJob, asset *models.TargetAsset) (*models.PolicyDecision, error) {
	if e.ForceApproval {
		return &models.PolicyDecision{
			Outcome: models.PolicyHumanApproval,
			Ref:     "pol:forced_approval",
		}, nil
	}

	if asset != nil && (asset.Criticality == models.CriticalityHigh || asset.Criticality == models.CriticalityCritical) {
		return &models.PolicyDecision{
			Outcome: models.PolicyHumanApproval,
			Ref:     fmt.Sprintf("pol:high_criticality_%s", asset.Criticality),
		}, nil
	}

	return &models.PolicyDecision{
		Outcome: models.PolicyAutoExecute,
		Ref:     "pol:auto_approved_low_risk",
	}, nil
}

func (e *DefaultEvaluator) VerifyApproval(ctx context.Context, approvalRef string, jobID string) error {
	if strings.TrimSpace(approvalRef) == "" {
		return fmt.Errorf("approval reference is required but was empty")
	}
	// Verify token format (e.g. "appr_<jobID>_...")
	if !strings.Contains(approvalRef, jobID) && !strings.HasPrefix(approvalRef, "appr_") {
		return fmt.Errorf("approval token %q is not bound to job %s", approvalRef, jobID)
	}
	return nil
}
