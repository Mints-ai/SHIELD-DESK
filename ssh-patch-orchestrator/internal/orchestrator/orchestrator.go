package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/approval"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/audit"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/patch"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/precheck"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/rollback"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/snapshot"
)

// Orchestrator executes the complete patch lifecycle for a single job
// according to the state machine, safety rules, and audit requirements.
type Orchestrator struct {
	mu           sync.Mutex
	job          *models.PatchJob
	asset        *models.TargetAsset
	plan         *models.RemediationPlan
	stateMachine *StateMachine
	auditWriter  audit.Writer

	precheck   *precheck.PrecheckEngine
	snapshot   *snapshot.Manager
	patch      *patch.Engine
	validation ValidationEngine
	rollback   *rollback.Manager
	approval   approval.Evaluator

	createdSnapshots []*models.Snapshot
	precheckResult   *models.PrecheckResult
}

// ValidationEngine interface used by orchestrator
type ValidationEngine interface {
	Validate(ctx context.Context, jobID string, plan *models.RemediationPlan, baseline *models.Baseline) (*models.ValidationResult, error)
}

// NewOrchestrator creates a new Orchestrator instance.
func NewOrchestrator(
	job *models.PatchJob,
	asset *models.TargetAsset,
	plan *models.RemediationPlan,
	auditWriter audit.Writer,
	pre *precheck.PrecheckEngine,
	snap *snapshot.Manager,
	pat *patch.Engine,
	val ValidationEngine,
	rb *rollback.Manager,
	apr approval.Evaluator,
) *Orchestrator {
	sm := NewStateMachine(job.JobID, job.State)

	orch := &Orchestrator{
		job:              job,
		asset:            asset,
		plan:             plan,
		stateMachine:     sm,
		auditWriter:      auditWriter,
		precheck:         pre,
		snapshot:         snap,
		patch:            pat,
		validation:       val,
		rollback:         rb,
		approval:         apr,
		createdSnapshots: make([]*models.Snapshot, 0),
	}

	sm.SetTransitionCallback(func(from, to models.JobState) {
		orch.mu.Lock()
		orch.job.State = to
		orch.job.UpdatedAt = time.Now().UTC()
		orch.mu.Unlock()

		_ = orch.emitAudit(context.Background(), models.AuditEventType(fmt.Sprintf("STATE_%s", to)), models.AuditResultSuccess, "", from, to)
	})

	return orch
}

// State returns the current state of the orchestrator.
func (o *Orchestrator) State() models.JobState {
	return o.stateMachine.State()
}

// Job returns the current job state snapshot.
func (o *Orchestrator) Job() *models.PatchJob {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.job
}

// Run executes the complete remediation lifecycle.
func (o *Orchestrator) Run(ctx context.Context) error {
	// 1. Initial State Handling
	if o.stateMachine.State() == models.StateDetected {
		if o.plan == nil || len(o.plan.Operations) == 0 {
			_ = o.transition(models.StateHumanReview)
			return fmt.Errorf("no known remediation fix available; routed to human review")
		}
		if err := o.transition(models.StateFIXAvailable); err != nil {
			return err
		}
	}

	// 2. Policy & Approval Evaluation
	decision, err := o.approval.Evaluate(ctx, o.job, o.asset)
	if err != nil {
		return fmt.Errorf("policy evaluation failed: %w", err)
	}
	o.job.PolicyDecision = decision
	_ = o.emitAudit(ctx, models.AuditPolicyEvaluated, models.AuditResultSuccess, decision.Ref, "", "")

	if decision.Outcome == models.PolicyHumanApproval {
		// If approval ref is not provided or invalid, wait in AWAITING_APPROVAL
		if o.job.ApprovalRef == nil || *o.job.ApprovalRef == "" {
			_ = o.transition(models.StateAwaitingApproval)
			return nil // Pauses here until approval endpoint is called
		}
		if err := o.approval.VerifyApproval(ctx, *o.job.ApprovalRef, o.job.JobID); err != nil {
			_ = o.transition(models.StateAwaitingApproval)
			return fmt.Errorf("invalid approval reference: %w", err)
		}
	}

	// 3. Precheck Stage
	if err := o.transition(models.StatePrechecking); err != nil {
		return err
	}
	_ = o.emitAudit(ctx, models.AuditPrecheckStarted, models.AuditResultPending, "", "", "")

	preResult, err := o.precheck.Run(ctx, o.job.JobID, o.asset, o.plan)
	if err != nil || preResult == nil || !preResult.Passed {
		failDetail := "unknown precheck error"
		if preResult != nil && preResult.FailReason != "" {
			failDetail = preResult.FailReason
		}
		_ = o.emitAudit(ctx, models.AuditPrecheckCompleted, models.AuditResultFailure, failDetail, "", "")
		_ = o.transition(models.StatePrecheckFailed)
		_ = o.transition(models.StateHumanReview)
		outcome := models.OutcomePrecheckFailedHumanReview
		o.job.Outcome = &outcome
		return fmt.Errorf("prechecks failed: %s", failDetail)
	}

	o.precheckResult = preResult
	_ = o.emitAudit(ctx, models.AuditPrecheckCompleted, models.AuditResultSuccess, "all prechecks passed", "", "")

	if err := o.transition(models.StateReadyForSnapshot); err != nil {
		return err
	}

	// 4. Snapshot Creation & Verification Stage
	if err := o.transition(models.StateSnapshotCreating); err != nil {
		return err
	}
	_ = o.emitAudit(ctx, models.AuditSnapshotCreateStarted, models.AuditResultPending, "", "", "")

	snapshots, snapErr := o.snapshot.CreateSnapshots(ctx, o.job.JobID, preResult.RollbackSet, 2048)
	if snapErr != nil {
		_ = o.emitAudit(ctx, models.AuditSnapshotCreateFailed, models.AuditResultFailure, snapErr.Error(), "", "")
		_ = o.transition(models.StateSnapshotFailed)
		_ = o.transition(models.StateHumanReview)
		outcome := models.OutcomeSnapshotFailedHumanReview
		o.job.Outcome = &outcome
		return fmt.Errorf("snapshot creation failed: %w", snapErr)
	}
	o.createdSnapshots = snapshots
	_ = o.emitAudit(ctx, models.AuditSnapshotCreated, models.AuditResultSuccess, fmt.Sprintf("%d snapshot(s)", len(snapshots)), "", "")

	// Phase 4: Snapshot Verification Gate
	if verifyErr := o.snapshot.VerifySnapshots(ctx, snapshots); verifyErr != nil {
		_ = o.emitAudit(ctx, models.AuditSnapshotCreateFailed, models.AuditResultFailure, verifyErr.Error(), "", "")
		_ = o.snapshot.CleanupSnapshots(ctx, snapshots)
		_ = o.transition(models.StateSnapshotFailed)
		_ = o.transition(models.StateHumanReview)
		outcome := models.OutcomeSnapshotFailedHumanReview
		o.job.Outcome = &outcome
		return fmt.Errorf("snapshot verification gate failed: %w", verifyErr)
	}

	_ = o.emitAudit(ctx, models.AuditSnapshotVerified, models.AuditResultSuccess, "recovery point verified active and healthy", "", "")
	if err := o.transition(models.StateSnapshotVerified); err != nil {
		return err
	}

	// 5. Controlled Patch Execution Stage
	// CRITICAL SAFETY RULE 1: Only reachable from SNAPSHOT_VERIFIED
	if err := o.transition(models.StatePatching); err != nil {
		return err
	}
	_ = o.emitAudit(ctx, models.AuditPatchStarted, models.AuditResultPending, "", "", "")

	execResult, patchErr := o.patch.Execute(ctx, o.job.JobID, o.plan)
	if patchErr != nil || execResult == nil || execResult.ExitCode == nil || *execResult.ExitCode != 0 {
		_ = o.emitAudit(ctx, models.AuditPatchFailed, models.AuditResultFailure, fmt.Sprintf("%v", patchErr), "", "")
		return o.executeRollback(ctx, models.RollbackPatchFailed)
	}
	_ = o.emitAudit(ctx, models.AuditPatchCompleted, models.AuditResultSuccess, "patch commands executed successfully", "", "")

	// 6. Post-Patch Validation Stage
	// CRITICAL SAFETY RULE 2: Command exit code 0 is NOT proof of remediation
	if err := o.transition(models.StateValidating); err != nil {
		return err
	}
	_ = o.emitAudit(ctx, models.AuditValidationStarted, models.AuditResultPending, "", "", "")

	valResult, valErr := o.validation.Validate(ctx, o.job.JobID, o.plan, preResult.Baseline)
	if valErr != nil || valResult == nil || valResult.Result != models.ValidationPassed {
		failMsg := "validation checks failed"
		if valErr != nil {
			failMsg = valErr.Error()
		}
		_ = o.emitAudit(ctx, models.AuditValidationFailed, models.AuditResultFailure, failMsg, "", "")
		return o.executeRollback(ctx, models.RollbackValidationFailed)
	}

	// Remediation fully verified!
	_ = o.emitAudit(ctx, models.AuditValidationPassed, models.AuditResultSuccess, "fix confirmed by post-patch validation", "", "")
	if err := o.transition(models.StateRemediated); err != nil {
		return err
	}

	outcome := models.OutcomeRemediated
	o.job.Outcome = &outcome
	o.job.VulnerabilityStatus = models.VulnStatusFixed

	// Clean up snapshots after successful verified remediation
	_ = o.snapshot.CleanupSnapshots(ctx, o.createdSnapshots)
	return nil
}

// executeRollback executes recovery when patch or validation fails.
func (o *Orchestrator) executeRollback(ctx context.Context, reason models.RollbackReason) error {
	if err := o.transition(models.StateRollbackRequired); err != nil {
		return err
	}
	_ = o.emitAudit(ctx, models.AuditRollbackStarted, models.AuditResultPending, string(reason), "", "")

	if err := o.transition(models.StateRollingBack); err != nil {
		return err
	}

	rbExec, rbErr := o.rollback.Rollback(ctx, o.job.JobID, o.createdSnapshots, reason)
	if rbErr != nil {
		_ = o.emitAudit(ctx, models.AuditRollbackFailed, models.AuditResultFailure, rbErr.Error(), "", "")
		_ = o.transition(models.StateEscalatedUrgent)
		outcome := models.OutcomeEscalatedUrgent
		o.job.Outcome = &outcome
		return fmt.Errorf("CRITICAL: rollback failed: %w", rbErr)
	}

	if err := o.transition(models.StateVerifyingRestore); err != nil {
		return err
	}

	var baseline *models.Baseline
	if o.precheckResult != nil {
		baseline = o.precheckResult.Baseline
	}

	verifyErr := o.rollback.VerifyRestore(ctx, rbExec, o.createdSnapshots, baseline)
	if verifyErr != nil {
		_ = o.emitAudit(ctx, models.AuditRollbackVerificationFailed, models.AuditResultFailure, verifyErr.Error(), "", "")
		_ = o.transition(models.StateEscalatedUrgent)
		outcome := models.OutcomeEscalatedUrgent
		o.job.Outcome = &outcome
		return fmt.Errorf("CRITICAL: rollback verification failed: %w", verifyErr)
	}

	// Restore successfully verified!
	_ = o.emitAudit(ctx, models.AuditRollbackCompleted, models.AuditResultSuccess, "system restored to pre-patch state", "", "")
	if err := o.transition(models.StateRolledBackHumanReview); err != nil {
		return err
	}

	outcome := models.OutcomeRestoredVulnerabilityRemains
	o.job.Outcome = &outcome
	// LVM PRINCIPLE: Vulnerability remains present!
	o.job.VulnerabilityStatus = models.VulnStatusPresent
	return nil
}

func (o *Orchestrator) transition(to models.JobState) error {
	return o.stateMachine.Transition(to)
}

func (o *Orchestrator) emitAudit(ctx context.Context, action models.AuditEventType, result models.AuditResult, detail string, from, to models.JobState) error {
	if o.auditWriter == nil {
		return nil
	}

	var errInfo *models.AuditError
	if result == models.AuditResultFailure {
		errInfo = &models.AuditError{
			Code:    string(action),
			Message: detail,
		}
	}

	evt := &models.AuditEvent{
		EventID:    fmt.Sprintf("evt_%s_%d", o.job.JobID, time.Now().UnixNano()),
		IncidentID: o.job.IncidentID,
		JobID:      o.job.JobID,
		AssetID:    o.job.AssetID,
		Timestamp:  time.Now().UTC(),
		Actor:      "system:orchestrator",
		Action:     action,
		Result:     result,
		Error:      errInfo,
		StateFrom:  from,
		StateTo:    to,
	}

	return o.auditWriter.Write(ctx, evt)
}
