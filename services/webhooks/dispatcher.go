package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type WebhookPayload struct {
	ID        string                 `json:"id,omitempty"`
	Event     string                 `json:"event"`
	Timestamp string                 `json:"timestamp"`
	TenantID  string                 `json:"tenant_id"`
	Data      map[string]interface{} `json:"data"`
	Signature string                 `json:"signature,omitempty"`
}

type WebhookDispatcher struct {
	client     *http.Client
	AllowLocal bool
}

func NewWebhookDispatcher() *WebhookDispatcher {
	isDev := os.Getenv("APP_ENV") != "production" && os.Getenv("NODE_ENV") != "production"
	allowLocal := isDev || os.Getenv("ALLOW_LOCAL_WEBHOOKS") == "true"
	return &WebhookDispatcher{
		client: &http.Client{
			Timeout: 8 * time.Second,
		},
		AllowLocal: allowLocal,
	}
}

// GenerateDeliveryID generates a cryptographically random delivery tracking ID (e.g. del_01a2b3c4...)
func GenerateDeliveryID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return fmt.Sprintf("del_%s", hex.EncodeToString(b))
}

// ValidateDestinationURL verifies that the webhook destination does not violate SSRF boundaries.
func (d *WebhookDispatcher) ValidateDestinationURL(targetURL string) error {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid webhook url: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported URL scheme '%s', must be http or https", parsed.Scheme)
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return fmt.Errorf("webhook URL missing hostname")
	}

	// Resolve hostname IPs to enforce RFC 1918 / Loopback / Cloud Metadata defense
	if !d.AllowLocal {
		ips, err := net.LookupIP(hostname)
		if err != nil {
			// If it's already an IP address
			parsedIP := net.ParseIP(hostname)
			if parsedIP != nil {
				ips = []net.IP{parsedIP}
			} else {
				return fmt.Errorf("failed to resolve webhook hostname '%s': %w", hostname, err)
			}
		}

		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
				return fmt.Errorf("SSRF blocked: destination '%s' resolves to loopback/unspecified IP (%s)", hostname, ip)
			}

			// Block Link-Local Unicast (169.254.0.0/16 - AWS/GCP/Azure Metadata Services)
			if ip.IsLinkLocalUnicast() || strings.HasPrefix(ip.String(), "169.254.") {
				return fmt.Errorf("SSRF blocked: destination '%s' resolves to cloud metadata IP (%s)", hostname, ip)
			}

			// Block RFC 1918 Private Ranges in production
			if ip.IsPrivate() {
				return fmt.Errorf("SSRF blocked: destination '%s' resolves to internal private IP (%s)", hostname, ip)
			}
		}

		// In strict production mode, disallow plain HTTP
		if scheme != "https" {
			return fmt.Errorf("insecure plaintext HTTP is forbidden for external webhooks in production")
		}
	}

	return nil
}

// isNonRetryableStatusCode returns true for HTTP statuses indicating bad configuration or authentication,
// which will never succeed on retry.
func isNonRetryableStatusCode(statusCode int) bool {
	return statusCode == http.StatusBadRequest ||
		statusCode == http.StatusUnauthorized ||
		statusCode == http.StatusForbidden ||
		statusCode == http.StatusNotFound ||
		statusCode == http.StatusMethodNotAllowed ||
		statusCode == http.StatusGone ||
		statusCode == http.StatusUnprocessableEntity
}

// DispatchWithRetry sends signed payload to destination URL with up to 3 attempts and exponential backoff
func (d *WebhookDispatcher) DispatchWithRetry(ctx context.Context, targetURL, secretKey string, payload *WebhookPayload) error {
	// 1. SSRF Guard
	if err := d.ValidateDestinationURL(targetURL); err != nil {
		log.Error().Err(err).Str("target", targetURL).Msg("[WEBHOOK-SSRF-BLOCKED] Destination rejected")
		return err
	}

	// 2. Prepare payload & identifiers
	if payload.ID == "" {
		payload.ID = GenerateDeliveryID()
	}
	if payload.Timestamp == "" {
		payload.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	nowEpoch := time.Now().UTC().Unix()

	// Strip existing signature from payload body to avoid circular hashing
	payload.Signature = ""
	rawBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// 3. Compute HMAC-SHA256 timestamped signature
	signatureHeader := SignTimestampedPayload(nowEpoch, rawBytes, secretKey)
	legacySig := SignPayload(rawBytes, secretKey)

	maxAttempts := 3
	backoff := 500 * time.Millisecond

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewBuffer(rawBytes))
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-ShieldDesk-Signature", signatureHeader)
		req.Header.Set("X-ShieldDesk-Signature-Legacy", legacySig)
		req.Header.Set("X-ShieldDesk-Timestamp", fmt.Sprintf("%d", nowEpoch))
		req.Header.Set("X-ShieldDesk-Delivery-Id", payload.ID)
		req.Header.Set("X-ShieldDesk-Event", payload.Event)
		req.Header.Set("User-Agent", "ShieldDesk-Webhooks/1.0")

		resp, err := d.client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				log.Info().
					Str("event", payload.Event).
					Str("tenant_id", payload.TenantID).
					Str("url", targetURL).
					Str("delivery_id", payload.ID).
					Int("attempt", attempt).
					Msg("[WEBHOOK-DELIVERED] Customer webhook delivered successfully")
				return nil
			}

			// Fast-fail on permanent non-retryable errors
			if isNonRetryableStatusCode(resp.StatusCode) {
				log.Error().
					Int("status_code", resp.StatusCode).
					Str("target", targetURL).
					Str("delivery_id", payload.ID).
					Msg("[WEBHOOK-PERMANENT-FAILURE] Destination rejected webhook with non-retryable status code")
				return fmt.Errorf("webhook rejected with permanent non-retryable HTTP %d", resp.StatusCode)
			}
		}

		log.Warn().
			Err(err).
			Int("attempt", attempt).
			Str("target", targetURL).
			Str("delivery_id", payload.ID).
			Msg("[WEBHOOK-RETRY] Webhook delivery failed, backing off...")

		// Stop retrying if context cancelled or final attempt reached
		if attempt == maxAttempts {
			break
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff *= 2 // Exponential backoff: 500ms -> 1s -> 2s
		}
	}

	return fmt.Errorf("webhook delivery failed after %d attempts to %s", maxAttempts, targetURL)
}
