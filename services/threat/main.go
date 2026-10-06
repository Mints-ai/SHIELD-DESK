package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
		log.Info().Msg("[ThreatEngine] NATS not detected on localhost:4222. Running in standalone HTTP mode (ideal for local dev).")
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
		log.Info().Msg("[ThreatEngine] Ingesting in standalone in-memory mode on port 8003 (NATS not bound)")
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
		if os.Getenv("APP_ENV") == "production" {
			log.Fatal().Msg("FATAL: DATABASE_URL environment variable is required in production")
		}
		// Look for .env.local in repo root if present
		for _, envPath := range []string{".env.local", "../../.env.local", ".env", "../../.env"} {
			if envBytes, err := os.ReadFile(envPath); err == nil {
				for _, line := range strings.Split(string(envBytes), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "DATABASE_URL=") {
						val := strings.TrimPrefix(line, "DATABASE_URL=")
						val = strings.Trim(val, `"'`)
						if val != "" {
							dbURL = val
							break
						}
					}
				}
				if dbURL != "" {
					break
				}
			}
		}
		if dbURL == "" {
			dbURL = "postgresql://shielddesk:shielddesk_dev@localhost:5432/shielddesk?sslmode=disable"
		}
	}

	log.Info().Msg("[ShieldDesk-Threat] Initializing Go Threat Detection & Anomaly Service...")

	engine, err := NewThreatEngine(natsURL, dbURL)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize Threat Engine")
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	httpPort := 8003
	if p := os.Getenv("PORT"); p != "" {
		fmt.Sscanf(p, "%d", &httpPort)
	} else if p := os.Getenv("HTTP_PORT"); p != "" {
		fmt.Sscanf(p, "%d", &httpPort)
	}

	httpSrv := NewHTTPServer(httpPort, engine)
	go func() {
		if err := httpSrv.Start(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("[ThreatEngine] HTTP server stopped")
		}
	}()

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
