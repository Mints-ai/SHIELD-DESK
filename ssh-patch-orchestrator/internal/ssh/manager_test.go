package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"golang.org/x/crypto/ssh"
)

func TestEscapeArgV(t *testing.T) {
	tests := []struct {
		name     string
		argv     []string
		expected string
	}{
		{
			name:     "simple command",
			argv:     []string{"apt-get", "upgrade", "-y", "openssl"},
			expected: "'apt-get' 'upgrade' '-y' 'openssl'",
		},
		{
			name:     "argument with spaces",
			argv:     []string{"echo", "hello world"},
			expected: "'echo' 'hello world'",
		},
		{
			name:     "argument with quotes",
			argv:     []string{"grep", "it's fine"},
			expected: `'grep' 'it'\''s fine'`,
		},
		{
			name:     "injection attempt in argument is quoted",
			argv:     []string{"dpkg", "-i", "pkg; rm -rf /"},
			expected: `'dpkg' '-i' 'pkg; rm -rf /'`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := escapeArgV(tt.argv)
			if got != tt.expected {
				t.Errorf("escapeArgV() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	// Missing host
	cfg := DefaultConfig()
	cfg.User = "ubuntu"
	cfg.HostKeyFingerprint = "SHA256:dummy"
	cfg.PrivateKeyPEM = []byte("dummy")
	if _, err := NewManager(cfg); err == nil {
		t.Errorf("expected error for empty Host")
	}

	// Missing user
	cfg = DefaultConfig()
	cfg.Host = "10.0.0.1"
	cfg.HostKeyFingerprint = "SHA256:dummy"
	cfg.PrivateKeyPEM = []byte("dummy")
	if _, err := NewManager(cfg); err == nil {
		t.Errorf("expected error for empty User")
	}

	// Missing fingerprint (Strict verification requirement)
	cfg = DefaultConfig()
	cfg.Host = "10.0.0.1"
	cfg.User = "ubuntu"
	cfg.PrivateKeyPEM = []byte("dummy")
	if _, err := NewManager(cfg); err == nil {
		t.Errorf("expected error for missing HostKeyFingerprint")
	}

	// Missing key
	cfg = DefaultConfig()
	cfg.Host = "10.0.0.1"
	cfg.User = "ubuntu"
	cfg.HostKeyFingerprint = "SHA256:dummy"
	if _, err := NewManager(cfg); err == nil {
		t.Errorf("expected error for missing PrivateKey")
	}
}

func TestHostKeyVerification(t *testing.T) {
	// Generate an ed25519 key pair for test
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to create ssh public key: %v", err)
	}

	realFingerprint := ssh.FingerprintSHA256(sshPub)

	// Test matching fingerprint
	mgr, _ := NewManager(Config{
		Host:               "10.0.0.1",
		User:               "root",
		HostKeyFingerprint: realFingerprint,
		PrivateKeyPEM:      []byte("dummy"),
	})

	cb := mgr.strictHostKeyCallback()
	if err := cb("10.0.0.1", &net.IPAddr{IP: net.ParseIP("10.0.0.1")}, sshPub); err != nil {
		t.Errorf("expected matching fingerprint to succeed, got %v", err)
	}

	// Test mismatched fingerprint (MITM / changed key)
	badMgr, _ := NewManager(Config{
		Host:               "10.0.0.1",
		User:               "root",
		HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		PrivateKeyPEM:      []byte("dummy"),
	})

	badCB := badMgr.strictHostKeyCallback()
	err = badCB("10.0.0.1", &net.IPAddr{IP: net.ParseIP("10.0.0.1")}, sshPub)
	if err == nil {
		t.Errorf("expected mismatched fingerprint to fail, but got nil")
	}

	var sshErr *SSHError
	if !errors.As(err, &sshErr) || sshErr.Class != ErrClassHostKeyMismatch {
		t.Errorf("expected ErrClassHostKeyMismatch, got %v", err)
	}
}

func TestMockRunner(t *testing.T) {
	ctx := context.Background()
	runner := NewMockRunner()

	zero := 0
	runner.RegisterHandler("op:pkg.version:openssl", func(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
		return &models.CommandResult{
			CommandRef: op.Ref,
			ExitCode:   &zero,
			Stdout:     "1.1.1f-1ubuntu2.20\n",
			Outcome:    models.OutcomeCompleted,
		}, nil
	})

	res, err := runner.Run(ctx, models.Operation{
		Ref:  "op:pkg.version:openssl",
		ArgV: []string{"dpkg-query", "-W", "openssl"},
	})
	if err != nil {
		t.Fatalf("mock run failed: %v", err)
	}

	if *res.ExitCode != 0 || !strings.Contains(res.Stdout, "1.1.1f-1ubuntu2.20") {
		t.Fatalf("unexpected mock result: %+v", res)
	}

	ops := runner.ExecutedOps()
	if len(ops) != 1 || ops[0].Ref != "op:pkg.version:openssl" {
		t.Fatalf("expected 1 recorded operation, got %d", len(ops))
	}
}
