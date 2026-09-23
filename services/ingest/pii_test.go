package main

import (
	"testing"
)

func TestStripPII(t *testing.T) {
	rawPayload := map[string]string{
		"command":     "curl -H 'Authorization: Bearer sk-123456789012345678901234' https://api.internal.corp",
		"user_email":  "john.doe@company.com",
		"password":    "MySecretPassword!",
		"cc_number":   "4111 2222 3333 4444",
		"process_name": "svchost.exe",
	}

	cleaned := StripPII(rawPayload)

	if cleaned["password"] != "[REDACTED_SENSITIVE_KEY]" {
		t.Errorf("Expected password to be redacted, got %s", cleaned["password"])
	}

	if cleaned["user_email"] != "[REDACTED_EMAIL]" {
		t.Errorf("Expected email to be redacted, got %s", cleaned["user_email"])
	}

	if cleaned["cc_number"] != "[REDACTED_CREDIT_CARD]" {
		t.Errorf("Expected credit card to be redacted, got %s", cleaned["cc_number"])
	}

	if cleaned["process_name"] != "svchost.exe" {
		t.Errorf("Harmless fields should remain unchanged, got %s", cleaned["process_name"])
	}
}

func TestTenantRateLimiter(t *testing.T) {
	rl := NewTenantRateLimiter()
	tenant := "ten_test_throttle"

	// First event should be allowed without backpressure
	allowed, backpressure := rl.AllowEvent(tenant)
	if !allowed {
		t.Errorf("First event should be allowed")
	}
	if backpressure {
		t.Errorf("First event should not trigger backpressure")
	}

	// Push over 8000 events to verify proactive backpressure signal
	for i := 0; i < 8050; i++ {
		rl.AllowEvent(tenant)
	}

	allowed, backpressure = rl.AllowEvent(tenant)
	if !allowed {
		t.Errorf("At 8050 events, should still be allowed")
	}
	if !backpressure {
		t.Errorf("At >80%% limit, proactive backpressure must be signaled")
	}
}
