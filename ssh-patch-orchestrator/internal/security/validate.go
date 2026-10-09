package security

import (
	"fmt"
	"regexp"
)

var (
	// Safe package name: alphanumeric, dash, dot, underscore, plus, colon
	safePackageName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+:-]*$`)
	// Safe service name: alphanumeric, dash, dot, underscore, @
	safeServiceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]*$`)
	// Safe LV/VG name: alphanumeric, dash, dot, underscore
	safeLVName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
	// Safe version string
	safeVersion = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.+~:-]*$`)
)

// ValidatePackageName validates a package name against safe patterns.
// Rejects shell metacharacters and invalid naming.
func ValidatePackageName(name string) error {
	if name == "" {
		return fmt.Errorf("package name cannot be empty")
	}
	if ContainsShellMetacharacters(name) {
		return fmt.Errorf("package name contains prohibited shell metacharacters: %q", name)
	}
	if !safePackageName.MatchString(name) {
		return fmt.Errorf("package name contains invalid characters: %q", name)
	}
	return nil
}

// ValidateServiceName validates a systemd service name.
func ValidateServiceName(name string) error {
	if name == "" {
		return fmt.Errorf("service name cannot be empty")
	}
	if ContainsShellMetacharacters(name) {
		return fmt.Errorf("service name contains prohibited shell metacharacters: %q", name)
	}
	if !safeServiceName.MatchString(name) {
		return fmt.Errorf("service name contains invalid characters: %q", name)
	}
	return nil
}

// ValidateLVName validates an LVM logical volume or volume group name.
func ValidateLVName(name string) error {
	if name == "" {
		return fmt.Errorf("volume name cannot be empty")
	}
	if ContainsShellMetacharacters(name) {
		return fmt.Errorf("volume name contains prohibited shell metacharacters: %q", name)
	}
	if !safeLVName.MatchString(name) {
		return fmt.Errorf("volume name contains invalid characters: %q", name)
	}
	return nil
}

// ValidateVersion validates a package version string.
func ValidateVersion(version string) error {
	if version == "" {
		return fmt.Errorf("version cannot be empty")
	}
	if ContainsShellMetacharacters(version) {
		return fmt.Errorf("version contains prohibited shell metacharacters: %q", version)
	}
	if !safeVersion.MatchString(version) {
		return fmt.Errorf("version contains invalid characters: %q", version)
	}
	return nil
}
