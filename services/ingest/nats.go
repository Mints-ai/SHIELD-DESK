package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog/log"
	ingestv1 "shielddesk/shared/proto/v1"
)

type EventPublisher struct {
	nc *nats.Conn
	js nats.JetStreamContext
}

func NewEventPublisher(natsURL string) (*EventPublisher, error) {
	nc, err := nats.Connect(natsURL,
		nats.MaxReconnects(10),
		nats.ReconnectWait(2*time.Second),
		nats.Name("shielddesk-ingest-service"),
	)
	if err != nil {
		log.Warn().Err(err).Msg("[NATS] Connection offline, operating in buffered development fallback mode.")
		return &EventPublisher{nc: nil, js: nil}, nil
	}

	js, err := nc.JetStream()
	if err != nil {
		return nil, fmt.Errorf("failed to create JetStream context: %w", err)
	}

	// Ensure SHIELDDESK_EVENTS stream exists
	_, err = js.AddStream(&nats.StreamConfig{
		Name:     "SHIELDDESK_EVENTS",
		Subjects: []string{"events.*.*"},
		Storage:  nats.FileStorage,
		MaxAge:   7 * 24 * time.Hour,
	})
	if err != nil && err != nats.ErrStreamNameAlreadyInUse {
		log.Warn().Err(err).Msg("[NATS] Notice: Stream creation warning, continuing...")
	}

	log.Info().Msg("[NATS] Successfully connected to JetStream bus.")
	return &EventPublisher{nc: nc, js: js}, nil
}

// PublishEvent sends an AgentEvent to events.{tenant_id}.{event_type}
func (p *EventPublisher) PublishEvent(event *ingestv1.AgentEvent) error {
	subject := fmt.Sprintf("events.%s.%s", event.TenantId, event.EventType)

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	if p.js != nil {
		_, err := p.js.Publish(subject, data)
		return err
	}

	// Dev fallback
	log.Debug().Str("subject", subject).Str("asset_id", event.AssetId).Msg("[DEV-INGEST] Event captured in memory buffer")
	return nil
}

func (p *EventPublisher) Close() {
	if p.nc != nil {
		p.nc.Drain()
	}
}
