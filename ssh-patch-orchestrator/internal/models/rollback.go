package models

import "time"

// RollbackReason classifies why a rollback was triggered.
type RollbackReason string

const (
	RollbackPatchFailed           RollbackReason = "PATCH_FAILED"
	RollbackValidationFailed      RollbackReason = "VALIDATION_FAILED"
	RollbackServiceRegression     RollbackReason = "SERVICE_REGRESSION"
	RollbackManualRequest         RollbackReason = "MANUAL_REQUEST"
	RollbackUncertainStateRecovery RollbackReason = "UNCERTAIN_STATE_RECOVERY"
)

// RollbackVerificationCheck records one restore verification check.
type RollbackVerificationCheck struct {
	Name   string `json:"name"`
	Result string `json:"result"` // PASS, FAIL
}

// RollbackExecution records the full lifecycle of a rollback attempt.
type RollbackExecution struct {
	RollbackID      string                      `json:"rollback_id"`
	JobID           string                      `json:"job_id"`
	Reason          RollbackReason              `json:"reason"`
	SnapshotID      string                      `json:"snapshot_id"`
	StartedAt       time.Time                   `json:"started_at"`
	MergeDeferred   bool                        `json:"merge_deferred"`
	RebootPerformed bool                        `json:"reboot_performed"`
	RestoreVerified bool                        `json:"restore_verified"`
	Verification    []RollbackVerificationCheck `json:"verification"`
	Outcome         JobOutcome                  `json:"outcome"`
}
