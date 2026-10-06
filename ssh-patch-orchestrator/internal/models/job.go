// Package models defines the core data types for the SSH Patch Orchestrator.
// These types represent the domain model: jobs, assets, remediations, snapshots,
// audit events, and all associated enumerations.
package models

import "time"

// --- Job States ---

// JobState represents the current state of a patch job in the state machine.
type JobState string

const (
	StateDetected              JobState = "DETECTED"
	StateFIXAvailable          JobState = "FIX_AVAILABLE"
	StateAwaitingApproval      JobState = "AWAITING_APPROVAL"
	StatePrechecking           JobState = "PRECHECKING"
	StateReadyForSnapshot      JobState = "READY_FOR_SNAPSHOT"
	StateSnapshotCreating      JobState = "SNAPSHOT_CREATING"
	StateSnapshotVerified      JobState = "SNAPSHOT_VERIFIED"
	StatePatching              JobState = "PATCHING"
	StateValidating            JobState = "VALIDATING"
	StateRemediated            JobState = "REMEDIATED"
	StateRollbackRequired      JobState = "ROLLBACK_REQUIRED"
	StateRollingBack           JobState = "ROLLING_BACK"
	StateVerifyingRestore      JobState = "VERIFYING_RESTORE"
	StateRolledBackHumanReview JobState = "ROLLED_BACK_HUMAN_REVIEW"
	StateStateUncertain        JobState = "STATE_UNCERTAIN"
	StatePrecheckFailed        JobState = "PRECHECK_FAILED"
	StateSnapshotFailed        JobState = "SNAPSHOT_FAILED"
	StateHumanReview           JobState = "HUMAN_REVIEW"
	StateEscalatedUrgent       JobState = "ESCALATED_URGENT"
	StateCancelled             JobState = "CANCELLED"
)

// terminalStates lists all states from which no further transition is possible.
var terminalStates = map[JobState]bool{
	StateRemediated:            true,
	StateRolledBackHumanReview: true,
	StateHumanReview:           true,
	StateEscalatedUrgent:       true,
	StateCancelled:             true,
}

// IsTerminal returns true if this state is a terminal (final) state.
func (s JobState) IsTerminal() bool {
	return terminalStates[s]
}

// String returns the string representation of the state.
func (s JobState) String() string { return string(s) }

// --- Job Outcomes ---

// JobOutcome represents the final reported outcome of a patch job.
type JobOutcome string

const (
	OutcomeRemediated                    JobOutcome = "REMEDIATED"
	OutcomeRestoredVulnerabilityRemains  JobOutcome = "RESTORED_VULNERABILITY_REMAINS"
	OutcomeEscalatedUrgent               JobOutcome = "ESCALATED_URGENT"
	OutcomeSnapshotFailedHumanReview     JobOutcome = "SNAPSHOT_FAILED_HUMAN_REVIEW"
	OutcomePrecheckFailedHumanReview     JobOutcome = "PRECHECK_FAILED_HUMAN_REVIEW"
	OutcomeCancelled                     JobOutcome = "CANCELLED"
)

// --- Vulnerability Status ---

// VulnerabilityStatus represents the known status of the vulnerability.
type VulnerabilityStatus string

const (
	VulnStatusPresent VulnerabilityStatus = "PRESENT"
	VulnStatusFixed   VulnerabilityStatus = "FIXED"
	VulnStatusUnknown VulnerabilityStatus = "UNKNOWN"
)

// --- Policy ---

// PolicyOutcome represents the autonomy decision from the policy engine.
type PolicyOutcome string

const (
	PolicyAutoExecute     PolicyOutcome = "AUTO_EXECUTE"
	PolicyStageAndConfirm PolicyOutcome = "STAGE_AND_CONFIRM"
	PolicyHumanApproval   PolicyOutcome = "HUMAN_APPROVAL"
)

// PolicyDecision holds the policy engine's decision for a patch job.
type PolicyDecision struct {
	Outcome PolicyOutcome `json:"outcome"`
	Ref     string        `json:"ref"`
}

// --- Patch Job ---

// PatchJob is the central entity representing a single patch remediation lifecycle.
type PatchJob struct {
	JobID              string              `json:"job_id"`
	IncidentID         string              `json:"incident_id"`
	AssetID            string              `json:"asset_id"`
	RemediationPlanID  string              `json:"remediation_plan_id"`
	State              JobState            `json:"state"`
	Outcome            *JobOutcome         `json:"outcome"`
	VulnerabilityStatus VulnerabilityStatus `json:"vulnerability_status"`
	PolicyDecision     *PolicyDecision     `json:"policy_decision"`
	ApprovalRef        *string             `json:"approval_ref"`
	IdempotencyKey     string              `json:"idempotency_key"`
	CreatedAt          time.Time           `json:"created_at"`
	UpdatedAt          time.Time           `json:"updated_at"`
}
