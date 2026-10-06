package models

// TargetAsset represents a Linux server that is the target of a patch job.
type TargetAsset struct {
	AssetID     string      `json:"asset_id"`
	TenantID    string      `json:"tenant_id"`
	Hostname    string      `json:"hostname"`
	Address     string      `json:"address"`
	SSHConfig   SSHTarget   `json:"ssh"`
	Criticality Criticality `json:"criticality"`
}

// SSHTarget holds SSH connection parameters for the target asset.
type SSHTarget struct {
	Port               int    `json:"port"`
	User               string `json:"user"`
	CredentialRef      string `json:"credential_ref"`
	HostKeyFingerprint string `json:"host_key_fingerprint"`
}

// Criticality represents the asset's criticality classification.
type Criticality string

const (
	CriticalityLow      Criticality = "LOW"
	CriticalityMedium   Criticality = "MEDIUM"
	CriticalityHigh     Criticality = "HIGH"
	CriticalityCritical Criticality = "CRITICAL"
)
