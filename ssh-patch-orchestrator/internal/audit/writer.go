package audit

import (
	"context"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
)

// Writer is the interface for writing and retrieving immutable audit events.
// CRITICAL SAFETY RULE: If an audit write fails, the corresponding state transition
// or privileged operation MUST fail closed.
type Writer interface {
	// Write persists an audit event. Returns an error if the write fails.
	Write(ctx context.Context, event *models.AuditEvent) error

	// Query retrieves audit events for a job, ordered by timestamp ascending.
	Query(ctx context.Context, jobID string) ([]*models.AuditEvent, error)

	// Close releases any resources held by the writer.
	Close() error
}
