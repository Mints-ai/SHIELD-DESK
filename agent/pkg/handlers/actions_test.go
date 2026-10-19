package handlers

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

func TestActionHandler_TakeSafetySnapshot(t *testing.T) {
	handler := newTestActionHandler()
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

func TestActionHandler_SetControlPlane(t *testing.T) {
	handler := newTestActionHandler()
	targetURL := "https://control.shielddesk.internal:8443"
	handler.SetControlPlane(targetURL)

	if handler.controlPlaneURL != targetURL {
		t.Errorf("Expected control plane URL %s, got %s", targetURL, handler.controlPlaneURL)
	}
}

func TestActionHandler_BlockIP_Validation(t *testing.T) {
	handler := newTestActionHandler()

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

func TestActionHandler_UnblockIP_Validation(t *testing.T) {
	handler := newTestActionHandler()

	// 1. Empty IP
	_, err := handler.UnblockIP("TEST-HOST-01", "")
	if err == nil {
		t.Error("Expected error when unblocking empty IP, got nil")
	}

	// 2. Invalid IP
	_, err = handler.UnblockIP("TEST-HOST-01", "not-an-ip")
	if err == nil {
		t.Error("Expected error when unblocking malformed IP, got nil")
	}

	// 3. Valid IP (should not return error even if rules don't exist yet)
	msg, err := handler.UnblockIP("TEST-HOST-01", "203.0.113.15")
	if err != nil {
		t.Errorf("Expected success when unblocking valid IP, got err: %v", err)
	}
	if !strings.Contains(msg, "Traffic restored") {
		t.Errorf("Expected confirmation message with 'Traffic restored', got: %s", msg)
	}
}

func TestActionHandler_KillProcess_SafetyGuardrails(t *testing.T) {
	handler := newTestActionHandler()

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
	handler := newTestActionHandler()

	_, err := handler.Rollback("TEST-HOST-01", "non-existent-snapshot-id")
	if err == nil {
		t.Error("Expected error when rolling back to non-existent snapshot, got nil")
	}
}

func TestActionHandler_ConcurrentSnapshots(t *testing.T) {
	handler := newTestActionHandler()
	var wg sync.WaitGroup
	errCh := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := handler.TakeSafetySnapshot("CONCURRENT-HOST")
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent snapshot error: %v", err)
	}
}

// Every command issued by these tests runs this inert helper, never host tools.
func newTestActionHandler() *ActionHandler {
	handler := NewActionHandler()
	handler.command = func(name string, args ...string) *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestActionCommandHelper$", "--", name)
		cmd.Args = append(cmd.Args, args...)
		cmd.Env = append(os.Environ(), "SHIELDDESK_TEST_COMMAND_HELPER=1")
		return cmd
	}
	return handler
}

func TestActionCommandHelper(t *testing.T) {
	if os.Getenv("SHIELDDESK_TEST_COMMAND_HELPER") == "1" {
		os.Exit(0)
	}
}

func TestBlockIPRejectsProtectedAddressesBeforeAnyCommand(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1"} {
		handler := NewActionHandler()
		handler.command = func(string, ...string) *exec.Cmd { t.Fatal("protected address invoked a host command"); return nil }
		if _, err := handler.BlockIP("TEST", ip); err == nil {
			t.Fatalf("accepted loopback %s", ip)
		}
		if len(handler.snapshots) != 0 {
			t.Fatal("invalid request created a snapshot")
		}
	}
	handler := NewActionHandler()
	handler.command = func(string, ...string) *exec.Cmd { t.Fatal("gateway validation invoked a host command"); return nil }
	if _, err := handler.BlockIP("TEST", "::ffff:10.0.0.1", "10.0.0.1"); err == nil {
		t.Fatal("accepted equivalent management address")
	}
}
