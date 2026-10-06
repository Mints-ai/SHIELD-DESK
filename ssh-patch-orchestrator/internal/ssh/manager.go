package ssh

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
	"github.com/shielddesk/ssh-patch-orchestrator/internal/security"
	"golang.org/x/crypto/ssh"
)

// Manager manages a single target server's SSH connection and command execution.
// It is the sole choke point for network access to the target Linux host.
type Manager struct {
	config Config
	client *ssh.Client
	mu     sync.Mutex
	closed bool
}

// NewManager creates and validates a new SSH Manager.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("SSH target host cannot be empty")
	}
	if cfg.Port <= 0 {
		cfg.Port = 22
	}
	if cfg.User == "" {
		return nil, fmt.Errorf("SSH user cannot be empty")
	}
	if cfg.HostKeyFingerprint == "" {
		return nil, fmt.Errorf("strict host key verification requires HostKeyFingerprint")
	}
	if len(cfg.PrivateKeyPEM) == 0 && cfg.PrivateKeyPath == "" {
		return nil, fmt.Errorf("private key must be provided via PrivateKeyPEM or PrivateKeyPath")
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 15 * time.Second
	}
	if cfg.CommandTimeout <= 0 {
		cfg.CommandTimeout = 5 * time.Minute
	}
	if cfg.MaxOutputBytes <= 0 {
		cfg.MaxOutputBytes = 1024 * 1024
	}

	return &Manager{
		config: cfg,
	}, nil
}

// Connect establishes the SSH connection with strict host key verification.
func (m *Manager) Connect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client != nil {
		return nil
	}

	keyBytes := m.config.PrivateKeyPEM
	if len(keyBytes) == 0 && m.config.PrivateKeyPath != "" {
		var err error
		keyBytes, err = os.ReadFile(m.config.PrivateKeyPath)
		if err != nil {
			return NewSSHError(ErrClassAuthFailed, "failed to read private key file", err)
		}
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return NewSSHError(ErrClassAuthFailed, "failed to parse private key", err)
	}

	clientConfig := &ssh.ClientConfig{
		User: m.config.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: m.strictHostKeyCallback(),
		Timeout:         m.config.ConnectTimeout,
	}

	addr := fmt.Sprintf("%s:%d", m.config.Host, m.config.Port)
	dialer := &net.Dialer{
		Timeout: m.config.ConnectTimeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return classifyDialError(err)
	}

	ncc, chans, reqs, err := ssh.NewClientConn(conn, addr, clientConfig)
	if err != nil {
		conn.Close()
		return classifyConnError(err)
	}

	m.client = ssh.NewClient(ncc, chans, reqs)
	m.closed = false
	return nil
}

// strictHostKeyCallback compares the presented public key fingerprint against the pinned one.
func (m *Manager) strictHostKeyCallback() ssh.HostKeyCallback {
	expected := m.config.HostKeyFingerprint
	// Clean expected format to match ssh.FingerprintSHA256
	if !strings.HasPrefix(expected, "SHA256:") {
		expected = "SHA256:" + expected
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		if subtle.ConstantTimeCompare([]byte(fp), []byte(expected)) != 1 {
			return NewSSHError(
				ErrClassHostKeyMismatch,
				fmt.Sprintf("host key fingerprint mismatch (expected: %s, received: %s)", expected, fp),
				nil,
			)
		}
		return nil
	}
}

// Run executes a structured, allowlisted operation over SSH.
func (m *Manager) Run(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
	if len(op.ArgV) == 0 {
		return nil, fmt.Errorf("operation ArgV cannot be empty")
	}

	m.mu.Lock()
	if m.client == nil || m.closed {
		m.mu.Unlock()
		// Try to connect if not connected
		if err := m.Connect(ctx); err != nil {
			return nil, err
		}
		m.mu.Lock()
	}
	client := m.client
	m.mu.Unlock()

	session, err := client.NewSession()
	if err != nil {
		return nil, NewSSHError(ErrClassDisconnected, "failed to create SSH session", err)
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &limitedWriter{w: &stdoutBuf, maxBytes: m.config.MaxOutputBytes}
	session.Stderr = &limitedWriter{w: &stderrBuf, maxBytes: m.config.MaxOutputBytes}

	// Escape argv into a POSIX single-quoted command string
	cmdStr := escapeArgV(op.ArgV)

	timeout := op.Timeout
	if timeout <= 0 {
		timeout = m.config.CommandTimeout
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	done := make(chan error, 1)

	go func() {
		done <- session.Run(cmdStr)
	}()

	var runErr error
	outcome := models.OutcomeCompleted

	select {
	case <-cmdCtx.Done():
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
		runErr = cmdCtx.Err()
		outcome = models.OutcomeTimeout
	case runErr = <-done:
	}

	duration := time.Since(start)

	var exitCode *int
	var stdoutTruncated, stderrTruncated bool

	rawStdout := stdoutBuf.String()
	rawStderr := stderrBuf.String()

	cleanStdout, stdoutTruncated := security.BoundOutput(security.Redact(rawStdout), m.config.MaxOutputBytes)
	cleanStderr, stderrTruncated := security.BoundOutput(security.Redact(rawStderr), m.config.MaxOutputBytes)

	if runErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			code := exitErr.ExitStatus()
			exitCode = &code
			outcome = models.OutcomeCompleted
		} else if errors.Is(runErr, context.DeadlineExceeded) {
			outcome = models.OutcomeTimeout
		} else {
			outcome = models.OutcomeDisconnected
		}
	} else {
		code := 0
		exitCode = &code
	}

	return &models.CommandResult{
		CommandRef: op.Ref,
		ExitCode:   exitCode,
		Stdout:     cleanStdout,
		Stderr:     cleanStderr,
		Duration:   duration,
		Outcome:    outcome,
		Truncated:  stdoutTruncated || stderrTruncated,
	}, nil
}

// Close closes the active SSH client.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.client != nil {
		err := m.client.Close()
		m.client = nil
		return err
	}
	return nil
}

// escapeArgV safely formats an argument vector into a single-quoted POSIX string.
func escapeArgV(argv []string) string {
	escaped := make([]string, len(argv))
	for i, arg := range argv {
		// Single quote each argument, escaping any embedded single quotes: ' -> '\''
		escaped[i] = "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
	}
	return strings.Join(escaped, " ")
}

// limitedWriter restricts the total bytes written to prevent out-of-memory issues.
type limitedWriter struct {
	w        io.Writer
	maxBytes int
	written  int
}

func (l *limitedWriter) Write(p []byte) (n int, err error) {
	if l.written >= l.maxBytes {
		return len(p), nil // drop remaining output silently
	}
	toWrite := len(p)
	if l.written+toWrite > l.maxBytes {
		toWrite = l.maxBytes - l.written
	}
	n, err = l.w.Write(p[:toWrite])
	l.written += n
	return len(p), err
}

func classifyDialError(err error) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return NewSSHError(ErrClassTimeout, "connection timed out during dial", err)
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return NewSSHError(ErrClassDNS, "DNS resolution failed", err)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return NewSSHError(ErrClassRefused, "connection refused or unreachable", err)
	}
	return NewSSHError(ErrClassUnknown, "dial failed", err)
}

func classifyConnError(err error) error {
	var sshErr *SSHError
	if errors.As(err, &sshErr) {
		return sshErr
	}
	msg := err.Error()
	if strings.Contains(msg, "unable to authenticate") {
		return NewSSHError(ErrClassAuthFailed, "SSH authentication rejected", err)
	}
	if strings.Contains(msg, "host key") {
		return NewSSHError(ErrClassHostKeyMismatch, "host key verification failed", err)
	}
	return NewSSHError(ErrClassUnknown, "SSH connection setup failed", err)
}
