package events

import "fmt"

// NATS JetStream Stream and Subject Definitions for ShieldDesk
const (
	// StreamEvents is the durable stream name storing all incoming agent telemetry.
	StreamEvents = "SHIELDDESK_EVENTS"

	// StreamAlerts is the durable stream name storing threat detection alerts.
	StreamAlerts = "SHIELDDESK_ALERTS"

	// Event Types
	EventTypeProcess   = "process"
	EventTypeFile      = "file"
	EventTypeNetwork   = "network"
	EventTypeAuth      = "auth"
	EventTypeInventory = "inventory"

	// Alert Severity Levels
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"

	// Alert Types
	AlertTypeMalware   = "malware"
	AlertTypeIntrusion = "intrusion"
	AlertTypeAnomaly   = "anomaly"
	AlertTypePolicy    = "policy"
	AlertTypeVuln      = "vuln"
)

// EventSubject returns the NATS subject for agent events: events.{tenant_id}.{event_type}
func EventSubject(tenantID, eventType string) string {
	return fmt.Sprintf("events.%s.%s", tenantID, eventType)
}

// AllTenantEventsSubject returns the wildcard subject for all event types of a tenant: events.{tenant_id}.*
func AllTenantEventsSubject(tenantID string) string {
	return fmt.Sprintf("events.%s.*", tenantID)
}

// GlobalEventsSubject returns the global wildcard subject for all events across all tenants: events.*.*
func GlobalEventsSubject() string {
	return "events.*.*"
}

// AlertSubject returns the NATS subject for published alerts: alerts.{tenant_id}
func AlertSubject(tenantID string) string {
	return fmt.Sprintf("alerts.%s", tenantID)
}

// GlobalAlertsSubject returns the wildcard subject for all alerts: alerts.*
func GlobalAlertsSubject() string {
	return "alerts.*"
}
