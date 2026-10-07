package ssh

import "fmt"

// ErrorClass categorizes SSH failures for the orchestrator's decision logic.
type ErrorClass string

const (
	ErrClassDNS             ErrorClass = "DNS"
	ErrClassRefused         ErrorClass = "REFUSED"
	ErrClassTimeout         ErrorClass = "TIMEOUT"
	ErrClassAuthFailed      ErrorClass = "AUTH_FAILED"
	ErrClassHostKeyMismatch ErrorClass = "HOST_KEY_MISMATCH"
	ErrClassDisconnected    ErrorClass = "DISCONNECTED_MID_COMMAND"
	ErrClassUnknown         ErrorClass = "UNKNOWN"
)

// SSHError provides a classified, structured SSH failure with wrapped root cause.
type SSHError struct {
	Class   ErrorClass
	Message string
	Cause   error
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

// NewSSHError constructs a classified SSHError.
func NewSSHError(class ErrorClass, message string, cause error) *SSHError {
	return &SSHError{
		Class:   class,
		Message: message,
		Cause:   cause,
	}
}
