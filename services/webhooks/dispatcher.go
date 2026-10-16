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

func isDiscordWebhook(targetURL string) bool {
	u := strings.ToLower(targetURL)
	return strings.Contains(u, "discord.com/api/webhooks") || strings.Contains(u, "discordapp.com/api/webhooks")
}

func isSlackWebhook(targetURL string) bool {
	u := strings.ToLower(targetURL)
	return strings.Contains(u, "hooks.slack.com")
}

func formatDiscordPayload(payload *WebhookPayload) []byte {
	title := payload.Event
	description := "Autonomous security event dispatched from ShieldDesk."
	severity := "standard"
	host := ""
	threat := ""
	actionURL := "https://shielddesk.io"

	if payload.Data != nil {
		if t, ok := payload.Data["title"].(string); ok && t != "" {
			title = t
		} else if r, ok := payload.Data["rule_name"].(string); ok && r != "" {
			title = r
		} else if th, ok := payload.Data["threat"].(string); ok && th != "" {
			title = th
		}

		if d, ok := payload.Data["description"].(string); ok && d != "" {
			description = d
		} else if m, ok := payload.Data["message"].(string); ok && m != "" {
			description = m
		}

		if s, ok := payload.Data["severity"].(string); ok && s != "" {
			severity = s
		}

		if h, ok := payload.Data["host"].(string); ok && h != "" {
			host = h
		} else if hn, ok := payload.Data["hostname"].(string); ok && hn != "" {
			host = hn
		}

		if th, ok := payload.Data["threat"].(string); ok && th != "" {
			threat = th
		}

		if u, ok := payload.Data["action_url"].(string); ok && u != "" {
			actionURL = u
		}
	}

	color := 0x10B981 // Emerald green
	switch strings.ToLower(severity) {
	case "critical":
		color = 0xDC2626 // Red
	case "high":
		color = 0xEA580C // Orange
	case "medium":
		color = 0xD97706 // Amber
	}

	fields := []map[string]interface{}{
		{"name": "Tenant", "value": payload.TenantID, "inline": true},
		{"name": "Severity", "value": strings.ToUpper(severity), "inline": true},
	}
	if host != "" {
		fields = append(fields, map[string]interface{}{"name": "Host", "value": host, "inline": true})
	}
	if threat != "" {
		fields = append(fields, map[string]interface{}{"name": "Threat", "value": threat, "inline": true})
	}
	if payload.ID != "" {
		fields = append(fields, map[string]interface{}{"name": "Delivery ID", "value": payload.ID, "inline": false})
	}

	discordMsg := map[string]interface{}{
		"content": "🛡️ **[ShieldDesk SOC Alert]**",
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("ShieldDesk SOC: %s", title),
				"url":         actionURL,
				"description": description,
				"color":       color,
				"fields":      fields,
				"footer": map[string]string{
					"text": "ShieldDesk Autonomous SOC Platform",
				},
				"timestamp": payload.Timestamp,
			},
		},
	}

	b, _ := json.Marshal(discordMsg)
	return b
}

func formatSlackPayload(payload *WebhookPayload) []byte {
	title := payload.Event
	description := "Autonomous security event dispatched from ShieldDesk."
	severity := "standard"
	host := ""

	if payload.Data != nil {
		if t, ok := payload.Data["title"].(string); ok && t != "" {
			title = t
		}
		if d, ok := payload.Data["description"].(string); ok && d != "" {
			description = d
		}
		if s, ok := payload.Data["severity"].(string); ok && s != "" {
			severity = s
		}
		if h, ok := payload.Data["host"].(string); ok && h != "" {
			host = h
		} else if hn, ok := payload.Data["hostname"].(string); ok && hn != "" {
			host = hn
		}
	}

	color := "#10b981"
	switch strings.ToLower(severity) {
	case "critical":
		color = "#dc2626"
	case "high":
		color = "#ea580c"
	case "medium":
		color = "#d97706"
	}

	fields := []map[string]interface{}{
		{"title": "Tenant", "value": payload.TenantID, "short": true},
		{"title": "Severity", "value": strings.ToUpper(severity), "short": true},
	}
	if host != "" {
		fields = append(fields, map[string]interface{}{"title": "Host", "value": host, "short": true})
	}

	slackMsg := map[string]interface{}{
		"text": fmt.Sprintf("🛡️ *[ShieldDesk SOC Alert]* %s", title),
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"title":  title,
				"text":   description,
				"fields": fields,
				"footer": "ShieldDesk Autonomous SOC Platform",
			},
		},
	}

	b, _ := json.Marshal(slackMsg)
	return b
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

	var rawBytes []byte
	var err error

	// Select appropriate payload serializer based on target platform
	if isDiscordWebhook(targetURL) {
		rawBytes = formatDiscordPayload(payload)
	} else if isSlackWebhook(targetURL) {
		rawBytes = formatSlackPayload(payload)
	} else {
		rawBytes, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal payload: %w", err)
		}
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
