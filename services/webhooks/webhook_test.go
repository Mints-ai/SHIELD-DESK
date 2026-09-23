package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHmacSha256Signing(t *testing.T) {
	payload := []byte(`{"event":"alert.created","tenant_id":"ten_acme123"}`)
	secret := "whsec_test_secret_key_123456"

	signature := SignPayload(payload, secret)
	if len(signature) < 10 || signature[:7] != "sha256=" {
		t.Errorf("Invalid signature format: %s", signature)
	}

	valid := VerifySignature(payload, signature, secret)
	if !valid {
		t.Errorf("Signature verification failed for valid secret")
	}

	invalid := VerifySignature(payload, signature, "wrong_secret")
	if invalid {
		t.Errorf("Signature verification must fail for invalid secret")
	}
}

func TestDispatcherRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := NewWebhookDispatcher()
	payload := &WebhookPayload{
		Event:    "alert.created",
		TenantID: "ten_test",
		Data:     map[string]interface{}{"severity": "critical"},
	}

	err := dispatcher.DispatchWithRetry(context.Background(), server.URL, "test_secret", payload)
	if err != nil {
		t.Errorf("Expected successful retry, got error: %v", err)
	}

	if attempts != 2 {
		t.Errorf("Expected 2 attempts before success, got %d", attempts)
	}
}
