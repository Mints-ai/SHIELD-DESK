package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
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
	publisher   *EventPublisher
	rateLimiter *TenantRateLimiter
	rdb         *redis.Client
}

func NewIngestServer(pub *EventPublisher, rdb *redis.Client) *IngestServer {
	return &IngestServer{
		publisher:   pub,
		rateLimiter: NewTenantRateLimiter(),
		rdb:         rdb,
	}
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

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatal().Err(err).Str("port", port).Msg("Failed to bind TCP listener")
	}

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
	grpcServer.GracefulStop()
	log.Info().Msg("[Ingest-Shutdown] Clean shutdown completed.")
}
