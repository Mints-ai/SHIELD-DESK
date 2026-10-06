package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
)

// JSONFileWriter is the MVP interim audit writer that appends events as JSON lines.
// It enforces thread-safe append-only guarantees.
type JSONFileWriter struct {
	mu       sync.Mutex
	filePath string
	file     *os.File
}

// NewJSONFileWriter creates or opens an audit file in append mode.
func NewJSONFileWriter(filePath string) (*JSONFileWriter, error) {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create audit directory %s: %w", dir, err)
	}

	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit file %s: %w", filePath, err)
	}

	return &JSONFileWriter{
		filePath: filePath,
		file:     file,
	}, nil
}

// Write writes an audit event as a single JSON line.
func (w *JSONFileWriter) Write(ctx context.Context, event *models.AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if event == nil {
		return fmt.Errorf("audit event cannot be nil")
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	data = append(data, '\n')
	if _, err := w.file.Write(data); err != nil {
		return fmt.Errorf("failed to write audit event to file: %w", err)
	}

	// Flush to disk to guarantee persistence
	return w.file.Sync()
}

// Query retrieves all audit events for a specific job from the log file.
func (w *JSONFileWriter) Query(ctx context.Context, jobID string) ([]*models.AuditEvent, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	readFile, err := os.Open(w.filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit file for reading: %w", err)
	}
	defer readFile.Close()

	var events []*models.AuditEvent
	scanner := bufio.NewScanner(readFile)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var evt models.AuditEvent
		if err := json.Unmarshal(line, &evt); err != nil {
			return nil, fmt.Errorf("corrupt audit record encountered: %w", err)
		}
		if evt.JobID == jobID {
			events = append(events, &evt)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed scanning audit file: %w", err)
	}

	// Sort by timestamp ascending
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	return events, nil
}

// Close closes the underlying audit file.
func (w *JSONFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// MemoryWriter is an in-memory implementation of Writer suitable for testing.
type MemoryWriter struct {
	mu     sync.RWMutex
	events []*models.AuditEvent
}

// NewMemoryWriter creates a new thread-safe in-memory audit writer.
func NewMemoryWriter() *MemoryWriter {
	return &MemoryWriter{
		events: make([]*models.AuditEvent, 0),
	}
}

// Write appends an event to the in-memory log.
func (m *MemoryWriter) Write(ctx context.Context, event *models.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}
	m.events = append(m.events, event)
	return nil
}

// Query retrieves events filtered by jobID in ascending timestamp order.
func (m *MemoryWriter) Query(ctx context.Context, jobID string) ([]*models.AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []*models.AuditEvent
	for _, e := range m.events {
		if e.JobID == jobID {
			out = append(out, e)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Timestamp.Before(out[j].Timestamp)
	})

	return out, nil
}

// All returns all recorded events.
func (m *MemoryWriter) All() []*models.AuditEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*models.AuditEvent, len(m.events))
	copy(out, m.events)
	return out
}

// Close is a no-op for MemoryWriter.
func (m *MemoryWriter) Close() error {
	return nil
}
