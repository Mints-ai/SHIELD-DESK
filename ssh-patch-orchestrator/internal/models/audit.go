package models

import "time"

// AuditEventType classifies the kind of audit event.
type AuditEventType string

const (
	AuditPatchRequested           AuditEventType = "PATCH_REQUESTED"
	AuditPolicyEvaluated          AuditEventType = "POLICY_EVALUATED"
	AuditPrecheckStarted          AuditEventType = "PRECHECK_STARTED"
	AuditPrecheckCompleted        AuditEventType = "PRECHECK_COMPLETED"
	AuditSnapshotCreateStarted    AuditEventType = "SNAPSHOT_CREATE_STARTED"
	AuditSnapshotCreated          AuditEventType = "SNAPSHOT_CREATED"
	AuditSnapshotCreateFailed     AuditEventType = "SNAPSHOT_CREATE_FAILED"
	AuditSnapshotVerified         AuditEventType = "SNAPSHOT_VERIFIED"
	AuditPatchStarted             AuditEventType = "PATCH_STARTED"
	AuditPatchCompleted           AuditEventType = "PATCH_COMPLETED"
	AuditPatchFailed              AuditEventType = "PATCH_FAILED"
	AuditValidationStarted        AuditEventType = "VALIDATION_STARTED"
	AuditValidationPassed         AuditEventType = "VALIDATION_PASSED"
	AuditValidationFailed         AuditEventType = "VALIDATION_FAILED"
	AuditRollbackStarted          AuditEventType = "ROLLBACK_STARTED"
	AuditRollbackCompleted        AuditEventType = "ROLLBACK_COMPLETED"
	AuditRollbackFailed           AuditEventType = "ROLLBACK_FAILED"
	AuditRollbackVerificationFailed AuditEventType = "ROLLBACK_VERIFICATION_FAILED"
	AuditHumanReviewRequired      AuditEventType = "HUMAN_REVIEW_REQUIRED"
	AuditEscalationRequired       AuditEventType = "ESCALATION_REQUIRED"
	AuditStateUncertainDetected   AuditEventType = "STATE_UNCERTAIN_DETECTED"
)

// AuditResult represents the result of an audited action.
type AuditResult string

const (
	AuditResultSuccess   AuditResult = "SUCCESS"
	AuditResultFailure   AuditResult = "FAILURE"
	AuditResultPending   AuditResult = "PENDING"
	AuditResultUncertain AuditResult = "UNCERTAIN"
)

// AuditEvent is an immutable record of an action taken during a patch job.
// Every state transition and every remote operation produces an audit event.
type AuditEvent struct {
	EventID          string          `json:"event_id"`
	IncidentID       string          `json:"incident_id"`
	JobID            string          `json:"job_id"`
	AssetID          string          `json:"asset_id"`
	Timestamp        time.Time       `json:"timestamp"`
	Actor            string          `json:"actor"`
	Action           AuditEventType  `json:"action"`
	Result           AuditResult     `json:"result"`
	ExitCode         *int            `json:"exit_code,omitempty"`
	SnapshotID       string          `json:"snapshot_id,omitempty"`
	CommandRef       string          `json:"command_ref,omitempty"`
	ApprovalRef      string          `json:"approval_ref,omitempty"`
	Error            *AuditError     `json:"error,omitempty"`
	ValidationResult *string         `json:"validation_result,omitempty"`
	StateFrom        JobState        `json:"state_from,omitempty"`
	StateTo          JobState        `json:"state_to,omitempty"`
}

// AuditError holds structured error information for an audit event.
type AuditError struct {
	Code    string `json:"code"`
	Message string `json:"message"` // redacted, no secrets
}
