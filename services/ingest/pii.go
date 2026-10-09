package main

import (
	"regexp"
	"strings"
	"sync"
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

// PIICategoryStats tracks redacted tokens by compliance classification
type PIICategoryStats struct {
	JWTTokens           int64 `json:"jwt_tokens"`
	PasswordsAndSecrets int64 `json:"passwords_and_secrets"`
	CreditCards         int64 `json:"credit_cards"`
	SSNAndNationalIDs   int64 `json:"ssn_and_national_ids"`
	Emails              int64 `json:"emails"`
}

// PIIMetricsTracker maintains thread-safe live counts of in-flight redacted tokens
type PIIMetricsTracker struct {
	mu            sync.RWMutex
	TotalRedacted int64            `json:"total_redacted"`
	Categories    PIICategoryStats `json:"categories"`
}

var globalPIITracker = &PIIMetricsTracker{
	TotalRedacted: 0,
	Categories:    PIICategoryStats{},
}

// GetPIIStats returns a snapshot copy of current PII redaction statistics
func GetPIIStats() (int64, PIICategoryStats) {
	globalPIITracker.mu.RLock()
	defer globalPIITracker.mu.RUnlock()
	return globalPIITracker.TotalRedacted, globalPIITracker.Categories
}

// ResetPIIStats resets PII redaction metrics
func ResetPIIStats() {
	globalPIITracker.mu.Lock()
	defer globalPIITracker.mu.Unlock()
	globalPIITracker.TotalRedacted = 0
	globalPIITracker.Categories = PIICategoryStats{}
}

// StripPII cleans a telemetry payload map, redacting sensitive keys and regex-matching values,
// and increments the in-memory compliance scrubbing counters.
func StripPII(payload map[string]string) map[string]string {
	if payload == nil {
		return nil
	}

	cleaned := make(map[string]string, len(payload))
	var passwordsCount, emailsCount, ccCount, jwtCount int64

	for k, v := range payload {
		lowerKey := strings.ToLower(k)
		if sensitiveKeyNames[lowerKey] {
			cleaned[k] = "[REDACTED_SENSITIVE_KEY]"
			passwordsCount++
			continue
		}

		// Regex redactions on values
		val := v
		if emailRegex.MatchString(val) {
			val = emailRegex.ReplaceAllString(val, "[REDACTED_EMAIL]")
			emailsCount++
		}
		if creditCardRegex.MatchString(val) {
			val = creditCardRegex.ReplaceAllString(val, "[REDACTED_CREDIT_CARD]")
			ccCount++
		}
		if jwtRegex.MatchString(val) {
			val = jwtRegex.ReplaceAllString(val, "[REDACTED_JWT]")
			jwtCount++
		}
		if bearerRegex.MatchString(val) {
			val = bearerRegex.ReplaceAllString(val, "[REDACTED_BEARER]")
			passwordsCount++
		}

		cleaned[k] = val
	}

	totalRedacted := passwordsCount + emailsCount + ccCount + jwtCount
	if totalRedacted > 0 {
		globalPIITracker.mu.Lock()
		globalPIITracker.TotalRedacted += totalRedacted
		globalPIITracker.Categories.PasswordsAndSecrets += passwordsCount
		globalPIITracker.Categories.Emails += emailsCount
		globalPIITracker.Categories.CreditCards += ccCount
		globalPIITracker.Categories.JWTTokens += jwtCount
		globalPIITracker.mu.Unlock()
	}

	return cleaned
}

