package handlers

import (
	"os"
	"strings"
	"testing"
)

func TestActionHandler_TakeSafetySnapshot(t *testing.T) {
	handler := NewActionHandler()
	snapID, err := handler.TakeSafetySnapshot("TEST-HOST-01")
	if err != nil {
		t.Fatalf("Failed to take safety snapshot: %v", err)
	}

	if !strings.HasPrefix(snapID, "snap-test-host-01-") {
		t.Errorf("Unexpected snapshot ID format: %s", snapID)
	}

	// Verify snapshot exists in handler state
	snap, ok := handler.snapshots[snapID]
	if !ok {
		t.Fatalf("Snapshot %s not saved in handler map", snapID)
	}

	if snap.ID != snapID {
		t.Errorf("Snapshot ID mismatch: expected %s, got %s", snapID, snap.ID)
	}
}

func TestActionHandler_BlockIP_Validation(t *testing.T) {
	handler := NewActionHandler()

	// 1. Empty IP
	_, err := handler.BlockIP("TEST-HOST-01", "")
	if err == nil {
		t.Error("Expected error when blocking empty IP, got nil")
	}

	// 2. Invalid IP
	_, err = handler.BlockIP("TEST-HOST-01", "not-an-ip")
	if err == nil {
		t.Error("Expected error when blocking malformed IP, got nil")
	}

	// 3. Loopback protection
	_, err = handler.BlockIP("TEST-HOST-01", "127.0.0.1")
	if err == nil {
		t.Error("Expected loopback protection error, got nil")
	}

	// 4. Management gateway protection
	_, err = handler.BlockIP("TEST-HOST-01", "10.0.0.1", "10.0.0.1")
	if err == nil {
		t.Error("Expected management gateway protection error, got nil")
	}
}

func TestActionHandler_KillProcess_SafetyGuardrails(t *testing.T) {
	handler := NewActionHandler()

	// 1. Refuse PID 0 or PID 1
	_, err := handler.KillProcess("TEST-HOST-01", 1)
	if err == nil {
		t.Error("Expected refusal to terminate PID 1 (init), got nil")
	}

	// 2. Refuse agent self PID
	selfPID := os.Getpid()
	_, err = handler.KillProcess("TEST-HOST-01", selfPID)
	if err == nil {
		t.Errorf("Expected refusal to terminate agent self PID %d, got nil", selfPID)
	}
}

func TestActionHandler_Rollback_NotFound(t *testing.T) {
	handler := NewActionHandler()

	_, err := handler.Rollback("TEST-HOST-01", "non-existent-snapshot-id")
	if err == nil {
		t.Error("Expected error when rolling back to non-existent snapshot, got nil")
	}
}
