package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestTimestampedHmacSigningAndVerification(t *testing.T) {
	payload := []byte(`{"event":"alert.created","tenant_id":"ten_acme123","data":{"threat":"ransomware"}}`)
	secret := "whsec_super_secret_999"
	timestamp := time.Now().UTC().Unix()

	sigHeader := SignTimestampedPayload(timestamp, payload, secret)
	if !strings.HasPrefix(sigHeader, "t=") || !strings.Contains(sigHeader, ",v1=") {
		t.Fatalf("Signature header does not match expected format t={ts},v1={hex}: %s", sigHeader)
	}

	// 1. Valid verification
	if !VerifyTimestampedSignature(payload, sigHeader, secret, 300) {
		t.Errorf("VerifyTimestampedSignature failed for fresh valid signature")
	}

	// 2. Tampered payload
	tamperedPayload := []byte(`{"event":"alert.created","tenant_id":"ten_acme123","data":{"threat":"benign"}}`)
	if VerifyTimestampedSignature(tamperedPayload, sigHeader, secret, 300) {
		t.Errorf("VerifyTimestampedSignature must reject tampered payload")
	}

	// 3. Wrong secret
	if VerifyTimestampedSignature(payload, sigHeader, "wrong_secret_key", 300) {
		t.Errorf("VerifyTimestampedSignature must reject signature verified with wrong secret")
	}
}

func TestTimestampedReplayDefenseTolerance(t *testing.T) {
	payload := []byte(`{"event":"policy.violated","tenant_id":"ten_acme123"}`)
	secret := "whsec_replay_defense_key"

	// Timestamp 10 minutes (600s) in the past
	oldTimestamp := time.Now().UTC().Unix() - 600
	oldSigHeader := SignTimestampedPayload(oldTimestamp, payload, secret)

	// Tolerance is 300 seconds (5 minutes)
	if VerifyTimestampedSignature(payload, oldSigHeader, secret, 300) {
		t.Errorf("VerifyTimestampedSignature must reject replay attack older than tolerance window")
	}

	// Fresh timestamp (30s ago) must pass
	freshTimestamp := time.Now().UTC().Unix() - 30
	freshSigHeader := SignTimestampedPayload(freshTimestamp, payload, secret)
	if !VerifyTimestampedSignature(payload, freshSigHeader, secret, 300) {
		t.Errorf("VerifyTimestampedSignature must accept timestamp within 300s tolerance")
	}
}

func TestSSRFProtection(t *testing.T) {
	dispatcher := NewWebhookDispatcher()
	// Disable local allowance to simulate production environment
	dispatcher.AllowLocal = false

	// 1. Cloud metadata IP must be blocked
	err := dispatcher.ValidateDestinationURL("http://169.254.169.254/latest/meta-data")
	if err == nil || !strings.Contains(err.Error(), "SSRF blocked") {
		t.Errorf("Expected SSRF block for AWS metadata IP, got: %v", err)
	}

	// 2. Loopback IP must be blocked
	err = dispatcher.ValidateDestinationURL("http://127.0.0.1:8080/callback")
	if err == nil || !strings.Contains(err.Error(), "SSRF blocked") {
		t.Errorf("Expected SSRF block for loopback 127.0.0.1, got: %v", err)
	}

	// 3. Plaintext HTTP must be blocked in production mode
	err = dispatcher.ValidateDestinationURL("http://google.com/webhook")
	if err == nil || !strings.Contains(err.Error(), "insecure plaintext HTTP is forbidden") {
		t.Errorf("Expected plaintext HTTP block in production, got: %v", err)
	}

	// 4. Local dev dispatcher allows local test server
	devDispatcher := NewWebhookDispatcher()
	devDispatcher.AllowLocal = true
	if err := devDispatcher.ValidateDestinationURL("http://127.0.0.1:9090/test"); err != nil {
		t.Errorf("Expected devDispatcher to allow local test URL, got: %v", err)
	}
}

func TestDispatcherRetry(t *testing.T) {
	attempts := 0
	var receivedSig, receivedTimestamp, receivedDeliveryID, receivedEvent string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		receivedSig = r.Header.Get("X-ShieldDesk-Signature")
		receivedTimestamp = r.Header.Get("X-ShieldDesk-Timestamp")
		receivedDeliveryID = r.Header.Get("X-ShieldDesk-Delivery-Id")
		receivedEvent = r.Header.Get("X-ShieldDesk-Event")

		if attempts < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := NewWebhookDispatcher()
	dispatcher.AllowLocal = true
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

	if !strings.HasPrefix(receivedSig, "t=") || !strings.Contains(receivedSig, ",v1=") {
		t.Errorf("Expected header X-ShieldDesk-Signature to match t=...,v1=..., got: %s", receivedSig)
	}
	if receivedTimestamp == "" {
		t.Errorf("Expected X-ShieldDesk-Timestamp header to be present")
	}
	if !strings.HasPrefix(receivedDeliveryID, "del_") {
		t.Errorf("Expected X-ShieldDesk-Delivery-Id starting with del_, got: %s", receivedDeliveryID)
	}
	if receivedEvent != "alert.created" {
		t.Errorf("Expected X-ShieldDesk-Event = alert.created, got: %s", receivedEvent)
	}
}

func TestNonRetryableFailureFailsFast(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		// 401 Unauthorized is a permanent client/config error
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	dispatcher := NewWebhookDispatcher()
	dispatcher.AllowLocal = true
	payload := &WebhookPayload{
		Event:    "alert.created",
		TenantID: "ten_test",
		Data:     map[string]interface{}{"severity": "high"},
	}

	err := dispatcher.DispatchWithRetry(context.Background(), server.URL, "test_secret", payload)
	if err == nil {
		t.Fatalf("Expected dispatch to fail on 401 Unauthorized")
	}

	// Must fail fast on 401 without retrying 3 times
	if attempts != 1 {
		t.Errorf("Expected exactly 1 attempt for non-retryable 401 error, got %d attempts", attempts)
	}
}

func TestDiscordPayloadFormatting(t *testing.T) {
	payload := &WebhookPayload{
		ID:        "del_test_12345",
		Event:     "alert.created",
		Timestamp: "2026-10-16T12:00:00Z",
		TenantID:  "ten_enterprise_soc",
		Data: map[string]interface{}{
			"title":       "Ransomware Detected",
			"description": "Suspicious mass file encryption on endpoint.",
			"severity":    "critical",
			"host":        "srv-prod-db-01",
			"threat":      "LockBit 3.0",
			"action_url":  "https://shielddesk.io/incidents/inc_999",
		},
	}

	formattedBytes := formatDiscordPayload(payload)
	var discordMsg map[string]interface{}
	if err := json.Unmarshal(formattedBytes, &discordMsg); err != nil {
		t.Fatalf("Failed to parse Discord payload as valid JSON: %v", err)
	}

	if discordMsg["content"] != "🛡️ **[ShieldDesk SOC Alert]**" {
		t.Errorf("Unexpected Discord content prefix: %v", discordMsg["content"])
	}

	embeds, ok := discordMsg["embeds"].([]interface{})
	if !ok || len(embeds) == 0 {
		t.Fatalf("Discord payload missing embeds list")
	}

	embed := embeds[0].(map[string]interface{})
	if !strings.Contains(embed["title"].(string), "Ransomware Detected") {
		t.Errorf("Expected embed title to contain rule/alert name, got: %v", embed["title"])
	}

	// Critical severity color is 0xDC2626 (14427686 in decimal)
	if color, ok := embed["color"].(float64); !ok || int(color) != 0xDC2626 {
		t.Errorf("Expected critical color 0xDC2626 (14427686), got: %v", embed["color"])
	}

	fields, ok := embed["fields"].([]interface{})
	if !ok || len(fields) < 4 {
		t.Errorf("Expected at least 4 fields (Tenant, Severity, Host, Threat), got %d", len(fields))
	}
}

func TestSlackPayloadFormatting(t *testing.T) {
	payload := &WebhookPayload{
		Event:     "alert.created",
		Timestamp: "2026-10-16T12:00:00Z",
		TenantID:  "ten_enterprise_soc",
		Data: map[string]interface{}{
			"title":       "Privilege Escalation",
			"description": "User escalated to root via sudo vulnerability.",
			"severity":    "high",
			"host":        "workstation-user-05",
		},
	}

	formattedBytes := formatSlackPayload(payload)
	var slackMsg map[string]interface{}
	if err := json.Unmarshal(formattedBytes, &slackMsg); err != nil {
		t.Fatalf("Failed to parse Slack payload as valid JSON: %v", err)
	}

	attachments, ok := slackMsg["attachments"].([]interface{})
	if !ok || len(attachments) == 0 {
		t.Fatalf("Slack payload missing attachments list")
	}

	attachment := attachments[0].(map[string]interface{})
	if color, ok := attachment["color"].(string); !ok || color != "#ea580c" {
		t.Errorf("Expected high severity color #ea580c, got: %v", attachment["color"])
	}
}

func TestPlatformSpecificWebhookDispatch(t *testing.T) {
	var receivedBody []byte
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		receivedBody = buf[:n]
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := NewWebhookDispatcher()
	dispatcher.AllowLocal = true

	// Simulate target URL that routes to discord
	targetURL := server.URL + "/discord.com/api/webhooks/mock"
	payload := &WebhookPayload{
		Event:    "alert.created",
		TenantID: "ten_test",
		Data: map[string]interface{}{
			"severity": "critical",
			"title":    "Database Breach Attempt",
		},
	}

	err := dispatcher.DispatchWithRetry(context.Background(), targetURL, "whsec_test", payload)
	if err != nil {
		t.Fatalf("Discord adapter dispatch failed: %v", err)
	}

	if receivedContentType != "application/json" {
		t.Errorf("Expected application/json content-type, got: %s", receivedContentType)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(receivedBody, &parsed); err != nil {
		t.Fatalf("Received body is not valid JSON: %v", err)
	}

	if _, hasEmbeds := parsed["embeds"]; !hasEmbeds {
		t.Errorf("Expected Discord payload to contain embeds array, got: %s", string(receivedBody))
	}
}

