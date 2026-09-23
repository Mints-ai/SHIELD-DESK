package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AuditEntry represents a tamper-proof chained record of an executed action.
type AuditEntry struct {
	Index        int64                  `json:"index"`
	Timestamp    time.Time              `json:"timestamp"`
	ActorID      string                 `json:"actor_id"`
	ActionType   string                 `json:"action_type"`
	Payload      map[string]interface{} `json:"payload"`
	PreviousHash string                 `json:"prev_hash"`
	CurrentHash  string                 `json:"current_hash"`
}

// Chain manages the append-only cryptographic ledger on the local host.
type Chain struct {
	mu      sync.Mutex
	entries []AuditEntry
}

// NewChain initializes the hash chain with a standard genesis block.
func NewChain() *Chain {
	genesisHash := "0000000000000000000000000000000000000000000000000000000000000000"
	genesisEntry := AuditEntry{
		Index:        0,
		Timestamp:    time.Now().UTC(),
		ActorID:      "system-genesis",
		ActionType:   "GENESIS",
		Payload:      map[string]interface{}{"msg": "ShieldDesk Local Agent Ledger Genesis"},
		PreviousHash: genesisHash,
	}

	genesisEntry.CurrentHash = computeHash(genesisHash, genesisEntry.ActorID, genesisEntry.ActionType, genesisEntry.Payload)

	return &Chain{
		entries: []AuditEntry{genesisEntry},
	}
}

// Append adds a new action to the hash chain and recalculates the SHA-256 hash.
func (c *Chain) Append(actorID, actionType string, payload map[string]interface{}) AuditEntry {
	c.mu.Lock()
	defer c.mu.Unlock()

	last := c.entries[len(c.entries)-1]
	currentHash := computeHash(last.CurrentHash, actorID, actionType, payload)

	entry := AuditEntry{
		Index:        int64(len(c.entries)),
		Timestamp:    time.Now().UTC(),
		ActorID:      actorID,
		ActionType:   actionType,
		Payload:      payload,
		PreviousHash: last.CurrentHash,
		CurrentHash:  currentHash,
	}

	c.entries = append(c.entries, entry)
	return entry
}

// Verify validates the cryptographic integrity of the entire chain from index 0.
func (c *Chain) Verify() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := 1; i < len(c.entries); i++ {
		prev := c.entries[i-1]
		curr := c.entries[i]

		if curr.PreviousHash != prev.CurrentHash {
			return fmt.Errorf("hash chain broken at index %d: expected prev_hash %s, got %s",
				i, prev.CurrentHash, curr.PreviousHash)
		}

		expectedHash := computeHash(curr.PreviousHash, curr.ActorID, curr.ActionType, curr.Payload)
		if curr.CurrentHash != expectedHash {
			return fmt.Errorf("hash chain payload altered at index %d: expected %s, got %s",
				i, expectedHash, curr.CurrentHash)
		}
	}
	return nil
}

func computeHash(prevHash, actorID, actionType string, payload map[string]interface{}) string {
	payloadBytes, _ := json.Marshal(payload)
	raw := fmt.Sprintf("%s|%s|%s|%s", prevHash, actorID, actionType, string(payloadBytes))
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
