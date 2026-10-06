package main

import (
	"context"
	"encoding/json"
	"net/http"
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
	httpServer *http.Server
}

// InboundDispatchReq matches the payload sent from the Next.js app
type InboundDispatchReq struct {
	TargetURL string                 `json:"target_url"`
	SecretKey string                 `json:"secret_key,omitempty"`
	Event     string                 `json:"event"`
	TenantID  string                 `json:"tenant_id"`
	Data      map[string]interface{} `json:"data"`
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

func (s *WebhookService) setupHTTP(port string) *http.Server {
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "healthy",
			"service": "shielddesk-webhooks",
			"engine":  "Go 1.22 HMAC Dispatcher",
		})
	})

	// Fire-and-forget HTTP dispatch endpoint
	mux.HandleFunc("POST /dispatch", func(w http.ResponseWriter, r *http.Request) {
		var req InboundDispatchReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
			return
		}

		if req.TargetURL == "" {
			http.Error(w, `{"error":"missing target_url"}`, http.StatusBadRequest)
			return
		}

		secret := req.SecretKey
		if secret == "" {
			secret = os.Getenv("CUSTOMER_WEBHOOK_SECRET")
			if secret == "" {
				secret = "sd_webhook_dev_secret"
			}
		}

		tenantID := req.TenantID
		if tenantID == "" {
			tenantID = "default_tenant"
		}

		event := req.Event
		if event == "" {
			event = "alert.dispatched"
		}

		payload := &WebhookPayload{
			Event:     event,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			TenantID:  tenantID,
			Data:      req.Data,
		}

		// Fire-and-forget asynchronous dispatch with 3x retry and backoff in Go
		go func(target, sec string, p *WebhookPayload) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := s.dispatcher.DispatchWithRetry(ctx, target, sec, p); err != nil {
				log.Error().Err(err).Str("url", target).Msg("[Webhooks] Async dispatch failed after retries")
			}
		}(req.TargetURL, secret, payload)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "queued",
			"queued":   true,
			"target":   req.TargetURL,
			"tenant":   tenantID,
			"event":    event,
			"retry":    "3 attempts (500ms, 1s, 2s)",
			"signed":   true,
		})
	})

	return &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}
}

func (s *WebhookService) Start(ctx context.Context) error {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	s.httpServer = s.setupHTTP(port)
	go func() {
		log.Info().Str("port", port).Msg("[Webhooks] HTTP dispatcher API listening on :" + port)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("[Webhooks] HTTP server error")
		}
	}()

	if s.js != nil {
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

			customerURL := os.Getenv("CUSTOMER_WEBHOOK_URL")
			secretKey := os.Getenv("CUSTOMER_WEBHOOK_SECRET")
			if customerURL != "" && secretKey != "" {
				go func() {
					_ = s.dispatcher.DispatchWithRetry(context.Background(), customerURL, secretKey, payload)
				}()
			}

			_ = msg.Ack()
		}, nats.Durable("webhooks-dispatcher-worker"), nats.ManualAck())

		if err == nil {
			log.Info().Msg("[Webhooks] Subscribed to NATS alerts.* and active")
			defer sub.Unsubscribe()
		}
	} else {
		log.Warn().Msg("[Webhooks] Standalone loop ready (NATS not bound)")
	}

	<-ctx.Done()
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
	if svc.httpServer != nil {
		shutdownCtx, sCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer sCancel()
		svc.httpServer.Shutdown(shutdownCtx)
	}
	if svc.nc != nil {
		svc.nc.Drain()
	}
	log.Info().Msg("[Webhooks-Shutdown] Shutdown complete.")
}
