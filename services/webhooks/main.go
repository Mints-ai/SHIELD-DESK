package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type WebhookService struct {
	nc         *nats.Conn
	js         nats.JetStreamContext
	dispatcher *WebhookDispatcher
}

func NewWebhookService(natsURL string) (*WebhookService, error) {
	nc, err := nats.Connect(natsURL,
		nats.MaxReconnects(10),
		nats.ReconnectWait(2*time.Second),
		nats.Name("shielddesk-webhooks-service"),
	)
	var js nats.JetStreamContext
	if err == nil {
		js, _ = nc.JetStream()
	} else {
		log.Warn().Err(err).Msg("[Webhooks] NATS offline, running in development mode")
	}

	return &WebhookService{
		nc:         nc,
		js:         js,
		dispatcher: NewWebhookDispatcher(),
	}, nil
}

func (s *WebhookService) Start(ctx context.Context) error {
	if s.js == nil {
		log.Warn().Msg("[Webhooks] Standalone loop ready (NATS not bound)")
		<-ctx.Done()
		return nil
	}

	sub, err := s.js.Subscribe("alerts.*", func(msg *nats.Msg) {
		var rawAlert map[string]interface{}
		if err := json.Unmarshal(msg.Data, &rawAlert); err != nil {
			_ = msg.Ack()
			return
		}

		tenantID, _ := rawAlert["tenant_id"].(string)
		if tenantID == "" {
			tenantID = "unknown_tenant"
		}

		payload := &WebhookPayload{
			Event:     "alert.created",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			TenantID:  tenantID,
			Data:      rawAlert,
		}

		// Example customer target URL and secret (in production loaded from PostgreSQL customer settings)
		customerURL := os.Getenv("CUSTOMER_WEBHOOK_URL")
		secretKey := os.Getenv("CUSTOMER_WEBHOOK_SECRET")
		if customerURL != "" && secretKey != "" {
			go func() {
				_ = s.dispatcher.DispatchWithRetry(context.Background(), customerURL, secretKey, payload)
			}()
		}

		_ = msg.Ack()
	}, nats.Durable("webhooks-dispatcher-worker"), nats.ManualAck())

	if err != nil {
		return err
	}

	log.Info().Msg("[Webhooks] Subscribed to NATS alerts.* and active")
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

	log.Info().Msg("[ShieldDesk-Webhooks] Starting Webhooks Microservice...")

	svc, err := NewWebhookService(natsURL)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize Webhook Service")
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := svc.Start(ctx); err != nil {
			log.Error().Err(err).Msg("Webhook service worker error")
		}
	}()

	<-sigChan
	log.Info().Msg("[Webhooks-Shutdown] Gracefully terminating Webhook Service...")
	cancel()
	if svc.nc != nil {
		svc.nc.Drain()
	}
	log.Info().Msg("[Webhooks-Shutdown] Shutdown complete.")
}
