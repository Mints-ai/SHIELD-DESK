package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"golang.org/x/crypto/ssh"
)

// A dropped transport models the cached connection left behind by a host reboot.
type droppedTransport struct{ ssh.Conn }

func (*droppedTransport) OpenChannel(string, []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, io.EOF
}
func (*droppedTransport) Close() error { return nil }
func (*droppedTransport) Wait() error  { return io.EOF }

func TestDroppedTransportIsDiscardedBeforeNextProbe(t *testing.T) {
	channels := make(chan ssh.NewChannel)
	requests := make(chan *ssh.Request)
	close(channels)
	close(requests)
	manager := &Manager{
		client: ssh.NewClient(&droppedTransport{}, channels, requests),
		config: Config{PrivateKeyPEM: []byte("invalid-test-key")},
	}
	op := models.Operation{Ref: "op:reboot.ping", ArgV: []string{"echo", "reboot_ok"}}
	_, err := manager.Run(context.Background(), op)
	var sshErr *SSHError
	if !errors.As(err, &sshErr) || sshErr.Class != ErrClassDisconnected {
		t.Fatalf("expected dropped transport, got %v", err)
	}
	if manager.client != nil {
		t.Fatal("dead transport remained cached")
	}
	// Key validation precedes dialing, so this proves the next probe enters a
	// fresh, pinned Connect attempt without opening any network connection.
	_, err = manager.Run(context.Background(), op)
	if !errors.As(err, &sshErr) || sshErr.Class != ErrClassInvalidKeyFormat {
		t.Fatalf("next probe did not reconnect: %v", err)
	}
}

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

func TestPassphraseProtectedKeyDetection(t *testing.T) {
	ctx := context.Background()
	// Simulated encrypted private key with Proc-Type: 4,ENCRYPTED header
	encryptedKey := []byte("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\nDummyEncryptedBytes\n-----END RSA PRIVATE KEY-----\n")
	mgr, err := NewManager(Config{
		Host:               "10.0.0.1",
		User:               "root",
		HostKeyFingerprint: "SHA256:d8a2b3c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		PrivateKeyPEM:      encryptedKey,
	})
	if err != nil {
		t.Fatalf("failed creating manager: %v", err)
	}

	err = mgr.Connect(ctx)
	if err == nil {
		t.Fatalf("expected error for encrypted key, got nil")
	}

	var sshErr *SSHError
	if !errors.As(err, &sshErr) || sshErr.Class != ErrClassPassphraseRequired {
		t.Fatalf("expected ErrClassPassphraseRequired, got %v", err)
	}
	if sshErr.DiagnosticHint == "" || len(sshErr.RemediationSteps) == 0 {
		t.Fatalf("expected remediation steps for passphrase-protected key, got %+v", sshErr)
	}
}

func TestPuTTYKeyFormatDetection(t *testing.T) {
	ctx := context.Background()
	puttyKey := []byte("PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: rsa-key-20261013\nPublic-Lines: 6\nAAAAB3NzaC1yc2EAAAADAQABAAABAQC...\n")
	mgr, err := NewManager(Config{
		Host:               "10.0.0.1",
		User:               "root",
		HostKeyFingerprint: "SHA256:d8a2b3c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
		PrivateKeyPEM:      puttyKey,
	})
	if err != nil {
		t.Fatalf("failed creating manager: %v", err)
	}

	err = mgr.Connect(ctx)
	if err == nil {
		t.Fatalf("expected error for PuTTY key, got nil")
	}

	var sshErr *SSHError
	if !errors.As(err, &sshErr) || sshErr.Class != ErrClassInvalidKeyFormat {
		t.Fatalf("expected ErrClassInvalidKeyFormat, got %v", err)
	}
	if !strings.Contains(sshErr.DiagnosticHint, "puttygen") {
		t.Fatalf("expected puttygen hint in diagnostic, got %q", sshErr.DiagnosticHint)
	}
}

func TestPublicKeyRejectionDiagnosticAdvice(t *testing.T) {
	rawErr := errors.New("ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain")
	classified := classifyConnError(rawErr)

	var sshErr *SSHError
	if !errors.As(classified, &sshErr) || sshErr.Class != ErrClassAuthFailed {
		t.Fatalf("expected ErrClassAuthFailed, got %v", classified)
	}

	if !strings.Contains(sshErr.DiagnosticHint, "authorized_keys") {
		t.Fatalf("expected authorized_keys in diagnostic hint, got %q", sshErr.DiagnosticHint)
	}

	foundStrictModes := false
	for _, step := range sshErr.RemediationSteps {
		if strings.Contains(step, "chmod 700 ~/.ssh") {
			foundStrictModes = true
			break
		}
	}
	if !foundStrictModes {
		t.Fatalf("expected chmod 700 in remediation steps, got %v", sshErr.RemediationSteps)
	}
}

func TestConnectionRefusedAndTimeoutClassification(t *testing.T) {
	// 1. Refused
	opErr := &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: errors.New("connectex: No connection could be made because the target machine actively refused it"),
	}
	errRefused := classifyDialError(opErr)
	var sshErrRefused *SSHError
	if !errors.As(errRefused, &sshErrRefused) || sshErrRefused.Class != ErrClassRefused {
		t.Fatalf("expected ErrClassRefused, got %v", errRefused)
	}
	if !strings.Contains(sshErrRefused.DiagnosticHint, "sshd") && !strings.Contains(sshErrRefused.DiagnosticHint, "port 22") {
		t.Fatalf("expected sshd/port 22 hint, got %q", sshErrRefused.DiagnosticHint)
	}

	// 2. DNS
	dnsErr := &net.DNSError{
		Err:  "no such host",
		Name: "invalid.hostname.internal",
	}
	errDNS := classifyDialError(dnsErr)
	var sshErrDNS *SSHError
	if !errors.As(errDNS, &sshErrDNS) || sshErrDNS.Class != ErrClassDNS {
		t.Fatalf("expected ErrClassDNS, got %v", errDNS)
	}
}
