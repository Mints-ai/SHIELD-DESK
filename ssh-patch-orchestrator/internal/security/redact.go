// Package security provides cross-cutting security helpers:
// input validation, output redaction, and shell metacharacter detection.
package security

import (
	"regexp"
	"strings"
)

// Patterns that look like secrets and must be redacted from stored output.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+`),
	regexp.MustCompile(`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(bearer|basic)\s+[A-Za-z0-9+/=_-]{8,}`),
	regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`), // AWS access key
	regexp.MustCompile(`(?i)ghp_[A-Za-z0-9_]{36,}`), // GitHub PAT
}

const redactedPlaceholder = "[REDACTED]"

// Redact replaces secret-like patterns in output before storage.
// This is a best-effort defense-in-depth measure; it does not
// guarantee all secrets are caught.
func Redact(input string) string {
	result := input
	for _, pattern := range secretPatterns {
		result = pattern.ReplaceAllString(result, redactedPlaceholder)
	}
	return result
}

// RedactBytes operates on byte slices.
func RedactBytes(input []byte) []byte {
	return []byte(Redact(string(input)))
}

// BoundOutput truncates output to maxBytes, marking it as truncated.
// Returns the bounded string and whether truncation occurred.
func BoundOutput(output string, maxBytes int) (string, bool) {
	if len(output) <= maxBytes {
		return output, false
	}
	// Truncate at a safe boundary (don't split UTF-8)
	truncated := output[:maxBytes]
	// Find the last valid rune boundary
	for i := len(truncated) - 1; i >= len(truncated)-4 && i >= 0; i-- {
		if truncated[i] < 0x80 || truncated[i] >= 0xC0 {
			truncated = truncated[:i+1]
			break
		}
	}
	return truncated + "\n... [OUTPUT TRUNCATED]", true
}

// shellMetacharacters are characters that have special meaning in shell contexts.
var shellMetacharacters = []string{
	";", "&", "|", "$", "`", "(", ")", "{", "}", "<", ">",
	"!", "\\", "'", "\"", "\n", "\r", "\x00",
}

// ContainsShellMetacharacters returns true if the string contains any
// shell metacharacters that could enable command injection.
func ContainsShellMetacharacters(s string) bool {
	for _, mc := range shellMetacharacters {
		if strings.Contains(s, mc) {
			return true
		}
	}
	return false
}
