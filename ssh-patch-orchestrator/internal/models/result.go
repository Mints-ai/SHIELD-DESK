package models

import "time"

// Operation represents a structured, allowlisted command to execute on a remote host.
// Operations are NEVER free-form shell commands — they are argument vectors
// from the allowlisted operation registry.
type Operation struct {
	Ref        string        `json:"ref"`        // Reference ID, e.g. "op:pkg.upgrade:openssl"
	ArgV       []string      `json:"-"`          // Argument vector (never logged/serialized)
	Timeout    time.Duration `json:"timeout"`    // Per-command timeout
	Idempotent bool          `json:"idempotent"` // Whether safe to retry on uncertain outcome
}

// CommandOutcome classifies how a remote command execution ended.
type CommandOutcome string

const (
	OutcomeCompleted       CommandOutcome = "COMPLETED"
	OutcomeTimeout         CommandOutcome = "TIMEOUT"
	OutcomeDisconnected    CommandOutcome = "DISCONNECTED"
	OutcomeAuthFailed      CommandOutcome = "AUTH_FAILED"
	OutcomeHostKeyMismatch CommandOutcome = "HOST_KEY_MISMATCH"
	OutcomeConnectFailed   CommandOutcome = "CONNECT_FAILED"
)

// CommandResult captures the full result of a remote command execution.
type CommandResult struct {
	CommandRef string         `json:"command_ref"`
	ExitCode   *int           `json:"exit_code"`   // nil means unknown (disconnect/timeout)
	Stdout     string         `json:"stdout"`
	Stderr     string         `json:"stderr"`
	Duration   time.Duration  `json:"duration_ms"`
	Outcome    CommandOutcome `json:"outcome"`
	Truncated  bool           `json:"truncated"`
}

// PatchExecution records details of a single patch execution attempt.
type PatchExecution struct {
	ExecutionID  string         `json:"execution_id"`
	JobID        string         `json:"job_id"`
	OperationRef string         `json:"operation_ref"`
	StartedAt    time.Time      `json:"started_at"`
	Duration     time.Duration  `json:"duration_ms"`
	ExitCode     *int           `json:"exit_code"`
	Outcome      CommandOutcome `json:"outcome"`
	StdoutRef    *string        `json:"stdout_ref"` // reference to redacted blob
	StderrRef    *string        `json:"stderr_ref"`
}
