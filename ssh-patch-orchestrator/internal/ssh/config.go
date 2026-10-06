package ssh

import "time"

// Config holds SSH connection and execution parameters.
type Config struct {
	Host               string
	Port               int
	User               string
	PrivateKeyPEM      []byte        // Private key content in PEM format
	PrivateKeyPath     string        // Path to private key file (alternative to PEM)
	HostKeyFingerprint string        // Required SHA256 fingerprint (e.g. "SHA256:...")
	ConnectTimeout     time.Duration // Timeout for establishing TCP & SSH handshake
	CommandTimeout     time.Duration // Default per-command timeout
	JobTimeout         time.Duration // Total job-level timeout
	MaxOutputBytes     int           // Maximum captured bytes per stdout/stderr stream
}

// DefaultConfig provides sensible security and operational defaults.
func DefaultConfig() Config {
	return Config{
		Port:           22,
		ConnectTimeout: 15 * time.Second,
		CommandTimeout: 5 * time.Minute,
		JobTimeout:     30 * time.Minute,
		MaxOutputBytes: 1024 * 1024, // 1MB output limit per stream
	}
}
