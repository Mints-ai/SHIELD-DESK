package models

// ValidationOverallResult represents the overall validation outcome.
type ValidationOverallResult string

const (
	ValidationPassed       ValidationOverallResult = "PASSED"
	ValidationFailed       ValidationOverallResult = "FAILED"
	ValidationInconclusive ValidationOverallResult = "INCONCLUSIVE"
)

// ValidationCheck records a single validation check result.
type ValidationCheck struct {
	Name     string `json:"name"`
	Result   string `json:"result"` // PASS, FAIL, SKIP
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// ValidationResult contains the overall validation verdict and per-check details.
// INCONCLUSIVE is NEVER treated as PASSED.
type ValidationResult struct {
	JobID               string                  `json:"job_id"`
	Result              ValidationOverallResult `json:"result"`
	Checks              []ValidationCheck       `json:"checks"`
	VulnerabilityStatus VulnerabilityStatus     `json:"vulnerability_status"`
}
