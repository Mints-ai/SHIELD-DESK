package orchestrator

import (
	"fmt"
	"sync"

	"github.com/shielddesk/ssh-patch-orchestrator/internal/models"
)

// legalTransitions defines every legal state transition.
// This is the single source of truth for the state machine.
// CRITICAL SAFETY RULE: PATCHING is ONLY reachable from SNAPSHOT_VERIFIED.
var legalTransitions = map[models.JobState][]models.JobState{
	models.StateDetected: {
		models.StateFIXAvailable,
		models.StateHumanReview,
	},
	models.StateFIXAvailable: {
		models.StateAwaitingApproval,
		models.StatePrechecking,
	},
	models.StateAwaitingApproval: {
		models.StatePrechecking,
		models.StateCancelled,
	},
	models.StatePrechecking: {
		models.StateReadyForSnapshot,
		models.StatePrecheckFailed,
	},
	models.StatePrecheckFailed: {
		models.StateHumanReview,
	},
	models.StateReadyForSnapshot: {
		models.StateSnapshotCreating,
	},
	models.StateSnapshotCreating: {
		models.StateSnapshotVerified,
		models.StateSnapshotFailed,
	},
	models.StateSnapshotFailed: {
		models.StateHumanReview,
	},
	// CRITICAL: The ONLY legal path into PATCHING is from SNAPSHOT_VERIFIED
	models.StateSnapshotVerified: {
		models.StatePatching,
	},
	models.StatePatching: {
		models.StateValidating,
		models.StateRollbackRequired,
		models.StateStateUncertain,
	},
	models.StateValidating: {
		models.StateRemediated,
		models.StateRollbackRequired,
	},
	models.StateRollbackRequired: {
		models.StateRollingBack,
	},
	models.StateRollingBack: {
		models.StateVerifyingRestore,
		models.StateEscalatedUrgent,
	},
	models.StateVerifyingRestore: {
		models.StateRolledBackHumanReview,
		models.StateEscalatedUrgent,
	},
	models.StateStateUncertain: {
		models.StateValidating,
		models.StateRollbackRequired,
		models.StateEscalatedUrgent,
	},
}

// IllegalTransitionError represents an invalid state transition attempt.
type IllegalTransitionError struct {
	JobID string
	From  models.JobState
	To    models.JobState
}

func (e *IllegalTransitionError) Error() string {
	return fmt.Sprintf("job %s: illegal state transition from %s to %s", e.JobID, e.From, e.To)
}

// StateMachine enforces valid state transitions and triggers audit hooks.
type StateMachine struct {
	mu           sync.RWMutex
	jobID        string
	state        models.JobState
	onTransition func(from, to models.JobState)
}

// NewStateMachine creates a new state machine initialized to the provided state.
func NewStateMachine(jobID string, initial models.JobState) *StateMachine {
	return &StateMachine{
		jobID: jobID,
		state: initial,
	}
}

// SetTransitionCallback configures an audit callback executed after every successful transition.
func (sm *StateMachine) SetTransitionCallback(fn func(from, to models.JobState)) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.onTransition = fn
}

// State returns the current job state safely.
func (sm *StateMachine) State() models.JobState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state
}

// CanTransition returns true if moving from current state to target is legal.
func (sm *StateMachine) CanTransition(to models.JobState) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return canTransition(sm.state, to)
}

func canTransition(from, to models.JobState) bool {
	allowed, exists := legalTransitions[from]
	if !exists {
		return false
	}
	for _, s := range allowed {
		if s == to {
			return true
		}
	}
	return false
}

// Transition advances the state machine to target state if legal, or returns an error.
func (sm *StateMachine) Transition(to models.JobState) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !canTransition(sm.state, to) {
		return &IllegalTransitionError{
			JobID: sm.jobID,
			From:  sm.state,
			To:    to,
		}
	}

	from := sm.state
	sm.state = to

	if sm.onTransition != nil {
		sm.onTransition(from, to)
	}

	return nil
}

// IsTerminal returns true if current state is terminal.
func (sm *StateMachine) IsTerminal() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.state.IsTerminal()
}

// ValidNextStates returns the list of allowed destination states from current state.
func (sm *StateMachine) ValidNextStates() []models.JobState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	allowed := legalTransitions[sm.state]
	out := make([]models.JobState, len(allowed))
	copy(out, allowed)
	return out
}
