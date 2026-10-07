package security

import (
	"strings"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
		redacted bool
	}{
		{
			name:     "password in config line",
			input:    "DB_PASSWORD=SuperSecretPass123",
			redacted: true,
		},
		{
			name:     "token in output",
			input:    "Authorization token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			redacted: true,
		},
		{
			name:     "bearer auth header",
			input:    "Bearer secret_token_value_abc123",
			redacted: true,
		},
		{
			name:     "private key block",
			input:    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
			redacted: true,
		},
		{
			name:     "normal log output without secrets",
			input:    "Reading package lists... Done\nBuilding dependency tree... Done",
			redacted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := Redact(tt.input)
			if tt.redacted {
				if !strings.Contains(output, redactedPlaceholder) {
					t.Errorf("expected output to contain placeholder %s, got: %s", redactedPlaceholder, output)
				}
			} else {
				if strings.Contains(output, redactedPlaceholder) {
					t.Errorf("expected clean output without redaction, got: %s", output)
				}
			}
		})
	}
}

func TestBoundOutput(t *testing.T) {
	input := "1234567890abcdefghij"
	bounded, truncated := BoundOutput(input, 10)
	if !truncated {
		t.Errorf("expected truncated to be true")
	}
	if !strings.Contains(bounded, "... [OUTPUT TRUNCATED]") {
		t.Errorf("expected truncated notice in output")
	}

	notBounded, truncated2 := BoundOutput(input, 50)
	if truncated2 {
		t.Errorf("expected truncated to be false for large limit")
	}
	if notBounded != input {
		t.Errorf("expected output to match input exactly")
	}
}
