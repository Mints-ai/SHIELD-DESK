package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type ThreatEngine struct {
	nc       *nats.Conn
	js       nats.JetStreamContext
	db       *EventRepository
	yara     *YARAMatcher
	sigma    *SigmaMatcher
	anomaly  *AnomalyDetector
}

func NewThreatEngine(natsURL, dbURL string) (*ThreatEngine, error) {
	db, err := NewEventRepository(dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to init db repo: %w", err)
	}

	nc, err := nats.Connect(natsURL,
		nats.MaxReconnects(10),
		nats.ReconnectWait(2*time.Second),
		nats.Name("shielddesk-threat-service"),
	)
	var js nats.JetStreamContext
	if err == nil {
		js, _ = nc.JetStream()
		// Ensure SHIELDDESK_ALERTS stream exists
		_, _ = js.AddStream(&nats.StreamConfig{
			Name:     "SHIELDDESK_ALERTS",
			Subjects: []string{"alerts.*"},
			Storage:  nats.FileStorage,
		})
	} else {
		log.Warn().Err(err).Msg("[ThreatEngine] NATS connection offline, running in standalone mode")
	}

	return &ThreatEngine{
		nc:      nc,
		js:      js,
		db:      db,
		yara:    NewYARAMatcher(),
		sigma:   NewSigmaMatcher(),
		anomaly: NewAnomalyDetector(),
	}, nil
}

// ProcessEvent applies detection pipeline to a single incoming security event
func (te *ThreatEngine) ProcessEvent(ctx context.Context, event *IngestEvent) *Alert {
	// 1. Write raw event to TimescaleDB
	_ = te.db.WriteSecurityEvent(ctx, event)

	// 2. YARA rule matching on file events
	if event.EventType == "file" {
		if alert := te.yara.MatchFileEvent(event); alert != nil {
			return alert
		}
	}

	// 3. Sigma rule matching on process & auth events
	if event.EventType == "process" || event.EventType == "auth" {
		if alert := te.sigma.MatchProcessOrAuthEvent(event); alert != nil {
			return alert
		}
	}

	// 4. ML Anomaly Scoring (Baseline deviation)
	if alert := te.anomaly.ScoreEvent(event); alert != nil {
		return alert
	}

	return nil
}

// PublishAlert records and broadcasts an alert to NATS alerts.{tenant_id}
func (te *ThreatEngine) PublishAlert(ctx context.Context, alert *Alert) error {
	log.Warn().
		Str("alert_id", alert.ID).
		Str("tenant_id", alert.TenantID).
		Str("severity", alert.Severity).
		Str("rule", alert.RuleName).
		Msg("[THREAT-DETECTED] High-priority security alert triggered!")

	// 1. Persist to PostgreSQL tenant schema
	_ = te.db.WriteAlert(ctx, alert)

	// 2. Publish to NATS alerts.{tenant_id}
	if te.js != nil {
		alertJSON, err := json.Marshal(alert)
		if err != nil {
			return err
		}
		subject := fmt.Sprintf("alerts.%s", alert.TenantID)
		_, err = te.js.Publish(subject, alertJSON)
		return err
	}

	return nil
}

func (te *ThreatEngine) Start(ctx context.Context) error {
	if te.js == nil {
		log.Warn().Msg("[ThreatEngine] Ingesting in simulated standalone loop (NATS not bound)")
		<-ctx.Done()
		return nil
	}

	// Durable push consumer on SHIELDDESK_EVENTS
	sub, err := te.js.Subscribe("events.*.*", func(msg *nats.Msg) {
		var event IngestEvent
		if err := json.Unmarshal(msg.Data, &event); err != nil {
			log.Error().Err(err).Msg("Failed to unmarshal event from NATS")
			_ = msg.Ack()
			return
		}

		alert := te.ProcessEvent(ctx, &event)
		if alert != nil {
			_ = te.PublishAlert(ctx, alert)
		}
		_ = msg.Ack()
	}, nats.Durable("threat-detector-worker"), nats.ManualAck())

	if err != nil {
		return fmt.Errorf("failed to subscribe to NATS events: %w", err)
	}

	log.Info().Msg("[ThreatEngine] Threat Detection Engine subscribed to NATS events.*.*")
	<-ctx.Done()
	_ = sub.Unsubscribe()
	return nil
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgresql://postgres:postgres@localhost:5432/shielddesk"
	}

	log.Info().Msg("[ShieldDesk-Threat] Initializing Go Threat Detection & Anomaly Service...")

	engine, err := NewThreatEngine(natsURL, dbURL)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize Threat Engine")
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := engine.Start(ctx); err != nil {
			log.Error().Err(err).Msg("Threat engine worker stopped")
		}
	}()

	<-sigChan
	log.Info().Msg("[Threat-Shutdown] Stopping Threat Detection Service...")
	cancel()
	if engine.nc != nil {
		engine.nc.Drain()
	}
	engine.db.Close()
	log.Info().Msg("[Threat-Shutdown] Shutdown complete.")
}
