package main

import (
	"regexp"
	"strings"
)

var (
	emailRegex      = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
	creditCardRegex = regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)
	jwtRegex        = regexp.MustCompile(`\beyJ[a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9_\-]+\b`)
	bearerRegex     = regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}`)
)

var sensitiveKeyNames = map[string]bool{
	"password":       true,
	"passwd":         true,
	"secret":         true,
	"private_key":    true,
	"credit_card":    true,
	"ssn":            true,
	"token":          true,
	"api_key":        true,
	"authorization":  true,
	"cookie":         true,
}

// StripPII cleans a telemetry payload map, redacting sensitive keys and regex-matching values.
func StripPII(payload map[string]string) map[string]string {
	if payload == nil {
		return nil
	}

	cleaned := make(map[string]string, len(payload))
	for k, v := range payload {
		lowerKey := strings.ToLower(k)
		if sensitiveKeyNames[lowerKey] {
			cleaned[k] = "[REDACTED_SENSITIVE_KEY]"
			continue
		}

		// Regex redactions on values
		val := emailRegex.ReplaceAllString(v, "[REDACTED_EMAIL]")
		val = creditCardRegex.ReplaceAllString(val, "[REDACTED_CREDIT_CARD]")
		val = jwtRegex.ReplaceAllString(val, "[REDACTED_JWT]")
		val = bearerRegex.ReplaceAllString(val, "[REDACTED_BEARER]")

		cleaned[k] = val
	}

	return cleaned
}
