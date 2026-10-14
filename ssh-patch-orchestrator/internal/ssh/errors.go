package ssh

import "fmt"

// ErrorClass categorizes SSH failures for the orchestrator's decision logic.
type ErrorClass string

const (
	ErrClassDNS                    ErrorClass = "DNS"
	ErrClassRefused                ErrorClass = "REFUSED"
	ErrClassTimeout                ErrorClass = "TIMEOUT"
	ErrClassAuthFailed             ErrorClass = "AUTH_FAILED"
	ErrClassHostKeyMismatch        ErrorClass = "HOST_KEY_MISMATCH"
	ErrClassDisconnected           ErrorClass = "DISCONNECTED_MID_COMMAND"
	ErrClassPassphraseRequired     ErrorClass = "PASSPHRASE_REQUIRED"
	ErrClassInvalidKeyFormat       ErrorClass = "INVALID_KEY_FORMAT"
	ErrClassPermissionsStrictModes ErrorClass = "PERMISSIONS_STRICTMODES"
	ErrClassUnknown                ErrorClass = "UNKNOWN"
)

// SSHError provides a classified, structured SSH failure with wrapped root cause and remediation hints.
type SSHError struct {
	Class            ErrorClass `json:"class"`
	Message          string     `json:"message"`
	DiagnosticHint   string     `json:"diagnostic_hint,omitempty"`
	RemediationSteps []string   `json:"remediation_steps,omitempty"`
	Cause            error      `json:"cause,omitempty"`
}

func (e *SSHError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("SSH error [%s]: %s: %v", e.Class, e.Message, e.Cause)
	}
	return fmt.Sprintf("SSH error [%s]: %s", e.Class, e.Message)
}

func (e *SSHError) Unwrap() error {
	return e.Cause
}

// WithRemediation decorates an SSHError with actionable Linux operational guidance.
func (e *SSHError) WithRemediation(hint string, steps ...string) *SSHError {
	e.DiagnosticHint = hint
	e.RemediationSteps = steps
	return e
}

// NewSSHError constructs a classified SSHError.
func NewSSHError(class ErrorClass, message string, cause error) *SSHError {
	return &SSHError{
		Class:   class,
		Message: message,
		Cause:   cause,
	}
}
