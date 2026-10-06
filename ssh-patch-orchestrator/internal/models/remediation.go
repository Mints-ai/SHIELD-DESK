package models

// RemediationPlan describes the approved, validated remediation for a vulnerability.
// It contains ONLY allowlisted structured operations — never free-form commands.
type RemediationPlan struct {
	PlanID             string                 `json:"plan_id"`
	VulnerabilityID    string                 `json:"vulnerability_id"`
	Confidence         RemediationConfidence  `json:"confidence"`
	Operations         []RemediationOperation `json:"operations"`
	TouchesNonLVMState bool                   `json:"touches_non_lvm_state"`
	SuccessCriteria    SuccessCriteria        `json:"success_criteria"`
}

// RemediationConfidence indicates how confident we are in the remediation.
type RemediationConfidence string

const (
	ConfidenceHigh   RemediationConfidence = "HIGH"
	ConfidenceMedium RemediationConfidence = "MEDIUM"
	ConfidenceLow    RemediationConfidence = "LOW"
)

// OperationType defines the type of an allowlisted remediation operation.
type OperationType string

const (
	OpPkgUpgrade      OperationType = "pkg.upgrade"
	OpPkgInstall      OperationType = "pkg.install"
	OpServiceRestart  OperationType = "service.restart"
	OpServiceReload   OperationType = "service.reload"
	OpConfigUpdate    OperationType = "config.update"
)

// RemediationOperation is a single structured, allowlisted operation.
// Operations are NEVER raw shell commands — they are typed with validated parameters.
type RemediationOperation struct {
	Type            OperationType `json:"type"`
	Package         string        `json:"package,omitempty"`
	TargetVersion   string        `json:"target_version,omitempty"`
	RestartServices []string      `json:"restart_services,omitempty"`
	ServiceName     string        `json:"service_name,omitempty"`
}

// SuccessCriteria defines what constitutes a successful remediation.
type SuccessCriteria struct {
	MinPackageVersion string `json:"min_package_version,omitempty"`
}
