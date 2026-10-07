package models

// PrecheckResultStatus represents a single precheck item outcome.
type PrecheckResultStatus string

const (
	PrecheckPass PrecheckResultStatus = "PASS"
	PrecheckFail PrecheckResultStatus = "FAIL"
	PrecheckSkip PrecheckResultStatus = "SKIP"
)

// PrecheckItem records the result of a single precheck.
type PrecheckItem struct {
	Name   string               `json:"name"`
	Result PrecheckResultStatus `json:"result"`
	Detail string               `json:"detail,omitempty"`
}

// Baseline records the pre-patch state for later comparison during validation
// and rollback verification.
type Baseline struct {
	PackageVersions map[string]string `json:"package_versions"`
	ServiceStates   map[string]string `json:"services"`
}

// RollbackSetEntry identifies a single LVM logical volume to snapshot.
type RollbackSetEntry struct {
	VG    string `json:"vg"`
	LV    string `json:"lv"`
	Mount string `json:"mount"`
}

// PrecheckResult contains the overall precheck outcome, individual checks,
// the baseline snapshot, and the identified rollback set.
type PrecheckResult struct {
	JobID       string             `json:"job_id"`
	Passed      bool               `json:"passed"`
	Checks      []PrecheckItem     `json:"checks"`
	Baseline    *Baseline          `json:"baseline"`
	RollbackSet []RollbackSetEntry `json:"rollback_set"`
	FailReason  string             `json:"fail_reason,omitempty"`
}
