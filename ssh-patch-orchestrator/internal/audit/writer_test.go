package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
)

func TestMemoryWriter(t *testing.T) {
	ctx := context.Background()
	mw := NewMemoryWriter()

	t1 := time.Now().Add(-2 * time.Minute)
	t2 := time.Now().Add(-1 * time.Minute)

	e1 := &models.AuditEvent{
		EventID:   "evt-1",
		JobID:     "job-100",
		Action:    models.AuditPatchRequested,
		Result:    models.AuditResultSuccess,
		Timestamp: t1,
	}
	e2 := &models.AuditEvent{
		EventID:   "evt-2",
		JobID:     "job-100",
		Action:    models.AuditPrecheckStarted,
		Result:    models.AuditResultSuccess,
		Timestamp: t2,
	}
	e3 := &models.AuditEvent{
		EventID:   "evt-3",
		JobID:     "job-200",
		Action:    models.AuditPatchRequested,
		Result:    models.AuditResultSuccess,
		Timestamp: time.Now(),
	}

	if err := mw.Write(ctx, e2); err != nil { // write out of order to verify sorting
		t.Fatalf("failed to write e2: %v", err)
	}
	if err := mw.Write(ctx, e1); err != nil {
		t.Fatalf("failed to write e1: %v", err)
	}
	if err := mw.Write(ctx, e3); err != nil {
		t.Fatalf("failed to write e3: %v", err)
	}

	events, err := mw.Query(ctx, "job-100")
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events for job-100, got %d", len(events))
	}

	if events[0].EventID != "evt-1" || events[1].EventID != "evt-2" {
		t.Fatalf("events not properly sorted by timestamp")
	}
}

func TestJSONFileWriter(t *testing.T) {
	ctx := context.Background()
	tempDir, err := os.MkdirTemp("", "audit-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "audit.jsonl")
	writer, err := NewJSONFileWriter(filePath)
	if err != nil {
		t.Fatalf("failed to create JSONFileWriter: %v", err)
	}
	defer writer.Close()

	evt := &models.AuditEvent{
		EventID:   "evt-file-1",
		JobID:     "job-300",
		Action:    models.AuditSnapshotVerified,
		Result:    models.AuditResultSuccess,
		Timestamp: time.Now(),
	}

	if err := writer.Write(ctx, evt); err != nil {
		t.Fatalf("failed to write audit event: %v", err)
	}

	results, err := writer.Query(ctx, "job-300")
	if err != nil {
		t.Fatalf("failed to query audit events: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].EventID != "evt-file-1" || results[0].Action != models.AuditSnapshotVerified {
		t.Fatalf("event data mismatch: %+v", results[0])
	}
}
