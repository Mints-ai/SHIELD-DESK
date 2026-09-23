package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

type WebhookPayload struct {
	Event     string                 `json:"event"`
	Timestamp string                 `json:"timestamp"`
	TenantID  string                 `json:"tenant_id"`
	Data      map[string]interface{} `json:"data"`
	Signature string                 `json:"signature"`
}

type WebhookDispatcher struct {
	client *http.Client
}

func NewWebhookDispatcher() *WebhookDispatcher {
	return &WebhookDispatcher{
		client: &http.Client{
			Timeout: 8 * time.Second,
		},
	}
}

// DispatchWithRetry sends signed payload to destination URL with 3 attempts and exponential backoff
func (d *WebhookDispatcher) DispatchWithRetry(ctx context.Context, targetURL, secretKey string, payload *WebhookPayload) error {
	rawBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Sign payload
	payload.Signature = SignPayload(rawBytes, secretKey)
	signedBytes, _ := json.Marshal(payload)

	maxAttempts := 3
	backoff := 500 * time.Millisecond

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewBuffer(signedBytes))
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ShieldDesk-Signature", payload.Signature)
		req.Header.Set("User-Agent", "ShieldDesk-Webhooks/1.0")

		resp, err := d.client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				log.Info().
					Str("event", payload.Event).
					Str("tenant_id", payload.TenantID).
					Str("url", targetURL).
					Int("attempt", attempt).
					Msg("[WEBHOOK-DELIVERED] Customer webhook delivered successfully")
				return nil
			}
		}

		log.Warn().
			Err(err).
			Int("attempt", attempt).
			Str("target", targetURL).
			Msg("[WEBHOOK-RETRY] Webhook delivery failed, backing off...")

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff *= 2 // Exponential backoff: 500ms -> 1s -> 2s
		}
	}

	return fmt.Errorf("webhook delivery failed after %d attempts to %s", maxAttempts, targetURL)
}
