package main

import "time"

// Alert represents an actionable security incident detected by rules or anomaly models.
type Alert struct {
	ID        string                 `json:"id"`
	TenantID  string                 `json:"tenant_id"`
	AssetID   string                 `json:"asset_id"`
	Severity  string                 `json:"severity"`  // critical | high | medium | low | info
	Type      string                 `json:"type"`      // malware | intrusion | anomaly | policy | vuln
	RuleID    string                 `json:"rule_id"`
	RuleName  string                 `json:"rule_name"`
	Payload   map[string]interface{} `json:"payload"`
	CreatedAt time.Time              `json:"created_at"`
}

// IngestEvent represents the incoming event structure unmarshaled from NATS.
type IngestEvent struct {
	TenantId     string            `json:"tenant_id"`
	AssetId      string            `json:"asset_id"`
	EventType    string            `json:"event_type"`
	Timestamp    int64             `json:"timestamp"`
	Payload      map[string]string `json:"payload"`
	AgentVersion string            `json:"agent_version"`
}
