package orchestrator

import (
	"sync"
	"testing"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
)

func TestLegalTransitions(t *testing.T) {
	tests := []struct {
		name string
		from models.JobState
		to   models.JobState
	}{
		{"DETECTED -> FIX_AVAILABLE", models.StateDetected, models.StateFIXAvailable},
		{"DETECTED -> HUMAN_REVIEW", models.StateDetected, models.StateHumanReview},
		{"FIX_AVAILABLE -> PRECHECKING", models.StateFIXAvailable, models.StatePrechecking},
		{"FIX_AVAILABLE -> AWAITING_APPROVAL", models.StateFIXAvailable, models.StateAwaitingApproval},
		{"AWAITING_APPROVAL -> PRECHECKING", models.StateAwaitingApproval, models.StatePrechecking},
		{"AWAITING_APPROVAL -> CANCELLED", models.StateAwaitingApproval, models.StateCancelled},
		{"PRECHECKING -> READY_FOR_SNAPSHOT", models.StatePrechecking, models.StateReadyForSnapshot},
		{"PRECHECKING -> PRECHECK_FAILED", models.StatePrechecking, models.StatePrecheckFailed},
		{"PRECHECK_FAILED -> HUMAN_REVIEW", models.StatePrecheckFailed, models.StateHumanReview},
		{"READY_FOR_SNAPSHOT -> SNAPSHOT_CREATING", models.StateReadyForSnapshot, models.StateSnapshotCreating},
		{"SNAPSHOT_CREATING -> SNAPSHOT_VERIFIED", models.StateSnapshotCreating, models.StateSnapshotVerified},
		{"SNAPSHOT_CREATING -> SNAPSHOT_FAILED", models.StateSnapshotCreating, models.StateSnapshotFailed},
		{"SNAPSHOT_FAILED -> HUMAN_REVIEW", models.StateSnapshotFailed, models.StateHumanReview},
		{"SNAPSHOT_VERIFIED -> PATCHING", models.StateSnapshotVerified, models.StatePatching},
		{"PATCHING -> VALIDATING", models.StatePatching, models.StateValidating},
		{"PATCHING -> ROLLBACK_REQUIRED", models.StatePatching, models.StateRollbackRequired},
		{"PATCHING -> STATE_UNCERTAIN", models.StatePatching, models.StateStateUncertain},
		{"VALIDATING -> REMEDIATED", models.StateValidating, models.StateRemediated},
		{"VALIDATING -> ROLLBACK_REQUIRED", models.StateValidating, models.StateRollbackRequired},
		{"ROLLBACK_REQUIRED -> ROLLING_BACK", models.StateRollbackRequired, models.StateRollingBack},
		{"ROLLING_BACK -> VERIFYING_RESTORE", models.StateRollingBack, models.StateVerifyingRestore},
		{"ROLLING_BACK -> ESCALATED_URGENT", models.StateRollingBack, models.StateEscalatedUrgent},
		{"VERIFYING_RESTORE -> ROLLED_BACK_HUMAN_REVIEW", models.StateVerifyingRestore, models.StateRolledBackHumanReview},
		{"VERIFYING_RESTORE -> ESCALATED_URGENT", models.StateVerifyingRestore, models.StateEscalatedUrgent},
		{"STATE_UNCERTAIN -> VALIDATING", models.StateStateUncertain, models.StateValidating},
		{"STATE_UNCERTAIN -> ROLLBACK_REQUIRED", models.StateStateUncertain, models.StateRollbackRequired},
		{"STATE_UNCERTAIN -> ESCALATED_URGENT", models.StateStateUncertain, models.StateEscalatedUrgent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewStateMachine("job-test", tt.from)
			if !sm.CanTransition(tt.to) {
				t.Fatalf("expected CanTransition(%s, %s) to be true", tt.from, tt.to)
			}
			if err := sm.Transition(tt.to); err != nil {
				t.Fatalf("expected transition from %s to %s to succeed, got %v", tt.from, tt.to, err)
			}
			if sm.State() != tt.to {
				t.Fatalf("expected current state to be %s, got %s", tt.to, sm.State())
			}
		})
	}
}

// Critical Safety Rules: PATCHING can only ever be reached from SNAPSHOT_VERIFIED.
func TestPatchingOnlyFromSnapshotVerified(t *testing.T) {
	allStates := []models.JobState{
		models.StateDetected,
		models.StateFIXAvailable,
		models.StateAwaitingApproval,
		models.StatePrechecking,
		models.StateReadyForSnapshot,
		models.StateSnapshotCreating,
		models.StateSnapshotFailed,
		models.StatePatching,
		models.StateValidating,
		models.StateRemediated,
		models.StateRollbackRequired,
		models.StateRollingBack,
		models.StateVerifyingRestore,
		models.StateRolledBackHumanReview,
		models.StatePrecheckFailed,
		models.StateHumanReview,
		models.StateEscalatedUrgent,
		models.StateCancelled,
	}

	for _, state := range allStates {
		sm := NewStateMachine("safety-test", state)
		if sm.CanTransition(models.StatePatching) {
			t.Errorf("VIOLATION OF SAFETY RULE 1: state %s allowed transitioning directly to PATCHING", state)
		}
		if err := sm.Transition(models.StatePatching); err == nil {
			t.Errorf("VIOLATION OF SAFETY RULE 1: Transition(%s -> PATCHING) succeeded without error", state)
		}
	}

	// Verify SNAPSHOT_VERIFIED can transition to PATCHING
	validSM := NewStateMachine("safety-test", models.StateSnapshotVerified)
	if !validSM.CanTransition(models.StatePatching) {
		t.Errorf("expected SNAPSHOT_VERIFIED to be allowed to transition to PATCHING")
	}
	if err := validSM.Transition(models.StatePatching); err != nil {
		t.Errorf("failed legal transition from SNAPSHOT_VERIFIED to PATCHING: %v", err)
	}
}

func TestTerminalStatesHaveNoOutgoingTransitions(t *testing.T) {
	terminals := []models.JobState{
		models.StateRemediated,
		models.StateRolledBackHumanReview,
		models.StateHumanReview,
		models.StateEscalatedUrgent,
		models.StateCancelled,
	}

	targets := []models.JobState{
		models.StateDetected,
		models.StatePatching,
		models.StatePrechecking,
		models.StateRollingBack,
	}

	for _, term := range terminals {
		sm := NewStateMachine("term-test", term)
		if !sm.IsTerminal() {
			t.Errorf("expected %s to be recognized as terminal", term)
		}
		for _, tgt := range targets {
			if sm.CanTransition(tgt) {
				t.Errorf("terminal state %s allowed transition to %s", term, tgt)
			}
			if err := sm.Transition(tgt); err == nil {
				t.Errorf("terminal state %s succeeded transition to %s", term, tgt)
			}
		}
	}
}

func TestTransitionCallback(t *testing.T) {
	sm := NewStateMachine("cb-job", models.StateDetected)
	var recordedFrom, recordedTo models.JobState

	sm.SetTransitionCallback(func(from, to models.JobState) {
		recordedFrom = from
		recordedTo = to
	})

	if err := sm.Transition(models.StateFIXAvailable); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if recordedFrom != models.StateDetected || recordedTo != models.StateFIXAvailable {
		t.Fatalf("callback got from=%s, to=%s, expected DETECTED -> FIX_AVAILABLE", recordedFrom, recordedTo)
	}
}

func TestConcurrentStateTransitions(t *testing.T) {
	sm := NewStateMachine("conc-job", models.StatePatching)

	var wg sync.WaitGroup
	attempts := 10
	errCount := 0
	var mu sync.Mutex

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := sm.Transition(models.StateValidating)
			if err != nil {
				mu.Lock()
				errCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Exactly one transition should succeed, others should fail as state is now VALIDATING
	if errCount != attempts-1 {
		t.Errorf("expected %d failed transitions, got %d", attempts-1, errCount)
	}
	if sm.State() != models.StateValidating {
		t.Errorf("expected final state to be VALIDATING, got %s", sm.State())
	}
}
