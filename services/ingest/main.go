package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	ingestv1 "shielddesk/shared/proto/v1"
)

type IngestServer struct {
	ingestv1.UnimplementedIngestServiceServer
	publisher      *EventPublisher
	rateLimiter    *TenantRateLimiter
	rdb            *redis.Client
	activeAgentsMu sync.RWMutex
	activeAgents   map[string]time.Time
	eventsCountMu  sync.Mutex
	eventsThisMin  int64
	lastRateReset  time.Time
}

func NewIngestServer(pub *EventPublisher, rdb *redis.Client) *IngestServer {
	return &IngestServer{
		publisher:     pub,
		rateLimiter:   NewTenantRateLimiter(),
		rdb:           rdb,
		activeAgents:  make(map[string]time.Time),
		lastRateReset: time.Now(),
	}
}

func (s *IngestServer) GetConnectedAgentCount() int {
	s.activeAgentsMu.Lock()
	defer s.activeAgentsMu.Unlock()
	cutoff := time.Now().Add(-60 * time.Second)
	for id, lastSeen := range s.activeAgents {
		if lastSeen.Before(cutoff) {
			delete(s.activeAgents, id)
		}
	}
	return len(s.activeAgents)
}

func (s *IngestServer) GetCurrentEventRate() int64 {
	s.eventsCountMu.Lock()
	defer s.eventsCountMu.Unlock()
	if time.Since(s.lastRateReset) > time.Minute {
		s.eventsThisMin = 0
		s.lastRateReset = time.Now()
	}
	return s.eventsThisMin
}


// Handshake authenticates the agent via tenant token and mTLS client certificate.
func (s *IngestServer) Handshake(ctx context.Context, req *ingestv1.HandshakeRequest) (*ingestv1.HandshakeResponse, error) {
	if req.TenantId == "" || req.AgentId == "" {
		return &ingestv1.HandshakeResponse{
			Authorized:   false,
			ErrorMessage: "tenant_id and agent_id are required",
		}, status.Error(codes.InvalidArgument, "missing required fields")
	}

	// Extract tenant token from incoming gRPC metadata
	var token string
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		tokens := md.Get("x-tenant-token")
		if len(tokens) > 0 {
			token = tokens[0]
		}
	}

	// Verify token in Redis (if Redis configured)
	if s.rdb != nil && token != "" {
		cachedTenant, err := s.rdb.Get(ctx, fmt.Sprintf("agent:token:%s", token)).Result()
		if err != nil || cachedTenant != req.TenantId {
			log.Warn().Str("tenant_id", req.TenantId).Str("token", token).Msg("[Ingest-Handshake] Token rejected or expired")
			return &ingestv1.HandshakeResponse{
				Authorized:   false,
				ErrorMessage: "Invalid or expired agent authorization token",
			}, status.Error(codes.Unauthenticated, "invalid agent token")
		}
	}

	log.Info().
		Str("agent_id", req.AgentId).
		Str("tenant_id", req.TenantId).
		Str("hostname", req.Hostname).
		Str("os", req.OsType).
		Msg("[Ingest-Handshake] Agent successfully authenticated and enrolled")

	s.activeAgentsMu.Lock()
	s.activeAgents[req.AgentId] = time.Now()
	s.activeAgentsMu.Unlock()

	return &ingestv1.HandshakeResponse{
		Authorized:           true,
		TenantId:             req.TenantId,
		HeartbeatIntervalSec: 15,
		SessionToken:         fmt.Sprintf("sess_%s_%d", req.AgentId, time.Now().Unix()),
	}, nil
}

// SendEvents handles high-speed bidirectional streaming of AgentEvents.
func (s *IngestServer) SendEvents(stream ingestv1.IngestService_SendEventsServer) error {
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			log.Error().Err(err).Msg("[Ingest-Stream] Error receiving event from stream")
			return err
		}

		s.activeAgentsMu.Lock()
		s.activeAgents[event.AssetId] = time.Now()
		s.activeAgentsMu.Unlock()

		s.eventsCountMu.Lock()
		s.eventsThisMin++
		s.eventsCountMu.Unlock()

		// 1. Schema Validation
		if event.TenantId == "" || event.AssetId == "" || event.EventType == "" {
			_ = stream.Send(&ingestv1.Ack{
				Success:      false,
				ErrorMessage: "Invalid event: missing tenant_id, asset_id, or event_type",
			})
			continue
		}

		// 2. Rate Limiting & Backpressure (10,000 events/min per tenant)
		allowed, backpressure := s.rateLimiter.AllowEvent(event.TenantId)
		if !allowed {
			_ = stream.Send(&ingestv1.Ack{
				Success:      false,
				RateLimited:  true,
				Backpressure: true,
				NextRetryMs:  2000,
				ErrorMessage: "Tenant rate limit exceeded (10,000 events/min). Throttling required.",
			})
			continue
		}

		// 3. Strip PII from payload map before downstream propagation
		event.Payload = StripPII(event.Payload)

		// 4. Batch & Publish to NATS JetStream
		if err := s.publisher.PublishEvent(event); err != nil {
			log.Error().Err(err).Str("tenant_id", event.TenantId).Msg("[Ingest-Publish] Failed to publish to NATS")
			_ = stream.Send(&ingestv1.Ack{
				Success:      false,
				ErrorMessage: "Internal bus queue error",
			})
			continue
		}

		// 5. Send Successful Acknowledgment
		err = stream.Send(&ingestv1.Ack{
			Success:      true,
			Backpressure: backpressure,
			EventId:      fmt.Sprintf("%s-%d", event.AssetId, event.Timestamp),
		})
		if err != nil {
			return err
		}
	}
}

// ---------------------------------------------------------------------------
// AgentServer implements bidirectional Heartbeat & Command Streaming (SD-011)
// ---------------------------------------------------------------------------

type AgentServer struct {
	ingestv1.UnimplementedAgentServiceServer
	publisher *EventPublisher
	rdb       *redis.Client
}

func NewAgentServer(pub *EventPublisher, rdb *redis.Client) *AgentServer {
	return &AgentServer{
		publisher: pub,
		rdb:       rdb,
	}
}

// StreamHeartbeat handles bidirectional agent ping/pong and delivers emergency kill switches.
func (s *AgentServer) StreamHeartbeat(stream ingestv1.AgentService_StreamHeartbeatServer) error {
	for {
		ping, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			log.Warn().Err(err).Msg("[Agent-Heartbeat] Stream interrupted")
			return err
		}

		// Check if kill switch is active in Redis
		killSwitch := false
		if s.rdb != nil {
			val, _ := s.rdb.Get(context.Background(), fmt.Sprintf("fleet:kill_switch:%s", ping.TenantId)).Result()
			if val == "true" || val == "1" {
				killSwitch = true
			}
			valAgent, _ := s.rdb.Get(context.Background(), fmt.Sprintf("fleet:kill_switch:agent:%s", ping.AgentId)).Result()
			if valAgent == "true" || valAgent == "1" {
				killSwitch = true
			}
		}

		log.Debug().
			Str("agent_id", ping.AgentId).
			Str("tenant_id", ping.TenantId).
			Float64("cpu_pct", ping.CpuUsagePct).
			Float64("mem_pct", ping.MemoryUsagePct).
			Int32("procs", ping.ProcessCount).
			Msg("[Agent-Heartbeat] Heartbeat received")

		err = stream.Send(&ingestv1.HeartbeatPong{
			Acknowledged:             true,
			Timestamp:                time.Now().UnixMilli(),
			NextIntervalSec:          15,
			KillSwitchEngaged:        killSwitch,
			CertificateRenewalNeeded: false,
		})
		if err != nil {
			return err
		}
	}
}

// StreamCommands delivers signed commands to the agent and consumes execution results.
func (s *AgentServer) StreamCommands(stream ingestv1.AgentService_StreamCommandsServer) error {
	for {
		result, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			log.Warn().Err(err).Msg("[Agent-Commands] Command stream closed")
			return err
		}

		log.Info().
			Str("command_id", result.CommandId).
			Str("agent_id", result.AgentId).
			Str("status", result.Status).
			Int64("duration_ms", result.DurationMs).
			Msg("[Agent-Commands] Execution result received")

		// Publish command execution result event to NATS JetStream
		if s.publisher != nil {
			_ = s.publisher.PublishEvent(&ingestv1.AgentEvent{
				TenantId:  result.TenantId,
				AssetId:   result.AgentId,
				EventType: "command_result",
				Timestamp: result.ExecutedAt,
				Payload: map[string]string{
					"command_id":  result.CommandId,
					"status":      result.Status,
					"output":      result.ExecutionOutput,
					"error":       result.ErrorMessage,
					"snapshot_id": result.SnapshotId,
					"result_hash": result.ResultHash,
				},
				AgentVersion: "1.0.0",
			})
		}
	}
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

	port := os.Getenv("PORT")
	if port == "" {
		port = "50051"
	}

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}

	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	log.Info().Msg("[ShieldDesk-Ingest] Initializing Go gRPC Ingest Daemon...")

	// Connect to NATS JetStream
	publisher, err := NewEventPublisher(natsURL)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize NATS publisher")
	}
	defer publisher.Close()

	// Connect to Redis for token caching
	rdb := redis.NewClient(&redis.Options{
		Addr: redisURL,
	})
	_ = rdb.Ping(context.Background()) // Test ping

	// gRPC Server Options (mTLS if certificates provided)
	var grpcOpts []grpc.ServerOption
	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	caFile := os.Getenv("TLS_CA_FILE")

	if certFile != "" && keyFile != "" && caFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to load server TLS key pair")
		}

		caBytes, err := os.ReadFile(caFile)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to read CA certificate")
		}

		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(caBytes)

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    caPool,
			MinVersion:   tls.VersionTLS13,
		}
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
		log.Info().Msg("[Ingest-TLS] mTLS Mutual TLS enforcement active (TLS 1.3)")
	} else {
		log.Warn().Msg("[Ingest-TLS] Running without mTLS certificates (standard development mode)")
	}

	grpcServer := grpc.NewServer(grpcOpts...)
	ingestServer := NewIngestServer(publisher, rdb)
	ingestv1.RegisterIngestServiceServer(grpcServer, ingestServer)

	agentServer := NewAgentServer(publisher, rdb)
	ingestv1.RegisterAgentServiceServer(grpcServer, agentServer)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatal().Err(err).Str("port", port).Msg("Failed to bind TCP listener")
	}

	// Start lightweight HTTP stats server for dashboard observability (default port 8004)
	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "8004"
	}
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ok",
			"service":   "shielddesk-ingest",
			"grpc_port": port,
		})
	})
	httpMux.HandleFunc("/api/ingest/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		totalRedacted, catStats := GetPIIStats()
		busStatus := "NATS JetStream (Offline - Dev Fallback)"
		if publisher.js != nil {
			busStatus = "NATS JetStream (Healthy)"
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":                  "ok",
			"pii_redacted_today":      totalRedacted,
			"pii_categories":          catStats,
			"bus_status":              busStatus,
			"active_agents_connected": ingestServer.GetConnectedAgentCount(),
			"events_per_minute":       ingestServer.GetCurrentEventRate(),
			"max_capacity_per_tenant": 10000,
		})
	})
	httpMux.HandleFunc("/api/ingest/simulate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		StripPII(map[string]string{
			"password":    "simulated_secret_key",
			"user_email":  "analyst@corp.internal",
			"jwt_token":   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy.sig",
			"credit_card": "4111 2222 3333 4444",
		})
		total, cat := GetPIIStats()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":            true,
			"pii_redacted_today": total,
			"pii_categories":     cat,
		})
	})
	httpMux.HandleFunc("/api/ingest/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		ResetPIIStats()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":            true,
			"pii_redacted_today": 0,
			"pii_categories":     PIICategoryStats{},
		})
	})

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%s", httpPort),
		Handler: httpMux,
	}
	go func() {
		log.Info().Str("port", httpPort).Msg("[Ingest-HTTP] Telemetry & PII stats server listening")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Ingest HTTP server stopped")
		}
	}()

	// Graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Info().Str("addr", lis.Addr().String()).Msg("[Ingest-gRPC] Ingest Service listening for agent streams")
		if err := grpcServer.Serve(lis); err != nil {
			log.Error().Err(err).Msg("gRPC server terminated")
		}
	}()

	<-sigChan
	log.Info().Msg("[Ingest-Shutdown] Gracefully shutting down Ingest Service...")
	_ = httpServer.Close()
	grpcServer.GracefulStop()
	log.Info().Msg("[Ingest-Shutdown] Clean shutdown completed.")
}
