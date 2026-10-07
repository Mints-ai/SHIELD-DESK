package ssh

import (
	"context"
	"fmt"
	"sync"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
)

// Runner executes controlled, allowlisted operations on a remote Linux host.
// All submodules (precheck, snapshot, patch, validation, rollback) interact
// with the target server exclusively through this interface.
type Runner interface {
	// Run executes an allowlisted operation with structured arguments.
	// It NEVER executes arbitrary unvalidated shell strings.
	Run(ctx context.Context, op models.Operation) (*models.CommandResult, error)

	// Close terminates the remote connection and cleans up sessions.
	Close() error
}

// CommandHandler is a function type for mocking command responses in MockRunner.
type CommandHandler func(ctx context.Context, op models.Operation) (*models.CommandResult, error)

// MockRunner is an in-memory Runner implementation for unit and integration testing.
type MockRunner struct {
	mu           sync.Mutex
	handlers     map[string]CommandHandler
	defaultHand  CommandHandler
	executedOps  []models.Operation
	closed       bool
}

// NewMockRunner initializes an empty MockRunner.
func NewMockRunner() *MockRunner {
	return &MockRunner{
		handlers:    make(map[string]CommandHandler),
		executedOps: make([]models.Operation, 0),
	}
}

// RegisterHandler registers a custom response for a specific Operation Ref.
func (m *MockRunner) RegisterHandler(ref string, handler CommandHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[ref] = handler
}

// SetDefaultHandler sets a fallback handler when an operation ref is not registered.
func (m *MockRunner) SetDefaultHandler(handler CommandHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultHand = handler
}

// Run simulates executing an operation.
func (m *MockRunner) Run(ctx context.Context, op models.Operation) (*models.CommandResult, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, fmt.Errorf("mock runner is closed")
	}
	m.executedOps = append(m.executedOps, op)
	handler, exists := m.handlers[op.Ref]
	defaultH := m.defaultHand
	m.mu.Unlock()

	if exists {
		return handler(ctx, op)
	}
	if defaultH != nil {
		return defaultH(ctx, op)
	}

	zero := 0
	return &models.CommandResult{
		CommandRef: op.Ref,
		ExitCode:   &zero,
		Stdout:     "",
		Stderr:     "",
		Outcome:    models.OutcomeCompleted,
	}, nil
}

// ExecutedOps returns a snapshot copy of all executed operations.
func (m *MockRunner) ExecutedOps() []models.Operation {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]models.Operation, len(m.executedOps))
	copy(out, m.executedOps)
	return out
}

// Close marks the mock runner as closed.
func (m *MockRunner) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}
