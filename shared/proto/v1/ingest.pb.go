package ingestv1

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AgentEvent represents a single endpoint security telemetry event.
type AgentEvent struct {
	TenantId     string            `json:"tenant_id,omitempty"`
	AssetId      string            `json:"asset_id,omitempty"`
	EventType    string            `json:"event_type,omitempty"` // process | file | network | auth | inventory
	Timestamp    int64             `json:"timestamp,omitempty"`  // Epoch ms UTC
	Payload      map[string]string `json:"payload,omitempty"`
	AgentVersion string            `json:"agent_version,omitempty"`
}

func (x *AgentEvent) GetTenantId() string {
	if x != nil {
		return x.TenantId
	}
	return ""
}

func (x *AgentEvent) GetAssetId() string {
	if x != nil {
		return x.AssetId
	}
	return ""
}

func (x *AgentEvent) GetEventType() string {
	if x != nil {
		return x.EventType
	}
	return ""
}

func (x *AgentEvent) GetTimestamp() int64 {
	if x != nil {
		return x.Timestamp
	}
	return 0
}

func (x *AgentEvent) GetPayload() map[string]string {
	if x != nil {
		return x.Payload
	}
	return nil
}

func (x *AgentEvent) GetAgentVersion() string {
	if x != nil {
		return x.AgentVersion
	}
	return ""
}

// Ack is the acknowledgment message returned back to the sending agent.
type Ack struct {
	Success      bool   `json:"success,omitempty"`
	EventId      string `json:"event_id,omitempty"`
	Backpressure bool   `json:"backpressure,omitempty"`
	RateLimited  bool   `json:"rate_limited,omitempty"`
	NextRetryMs  int64  `json:"next_retry_ms,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

func (x *Ack) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

func (x *Ack) GetBackpressure() bool {
	if x != nil {
		return x.Backpressure
	}
	return false
}

// HandshakeRequest initializes an authenticated agent session via mTLS.
type HandshakeRequest struct {
	TenantId               string `json:"tenant_id,omitempty"`
	AgentId                string `json:"agent_id,omitempty"`
	Hostname               string `json:"hostname,omitempty"`
	OsType                 string `json:"os_type,omitempty"`
	AgentVersion           string `json:"agent_version,omitempty"`
	ClientCertFingerprint  string `json:"client_cert_fingerprint,omitempty"`
}

// HandshakeResponse delivers enrollment status and operating parameters.
type HandshakeResponse struct {
	Authorized            bool   `json:"authorized,omitempty"`
	TenantId              string `json:"tenant_id,omitempty"`
	HeartbeatIntervalSec  int32  `json:"heartbeat_interval_sec,omitempty"`
	SessionToken          string `json:"session_token,omitempty"`
	ErrorMessage          string `json:"error_message,omitempty"`
}

// IngestServiceServer is the server API for IngestService.
type IngestServiceServer interface {
	SendEvents(IngestService_SendEventsServer) error
	Handshake(context.Context, *HandshakeRequest) (*HandshakeResponse, error)
	mustEmbedUnimplementedIngestServiceServer()
}

type UnimplementedIngestServiceServer struct{}

func (UnimplementedIngestServiceServer) SendEvents(IngestService_SendEventsServer) error {
	return status.Errorf(codes.Unimplemented, "method SendEvents not implemented")
}

func (UnimplementedIngestServiceServer) Handshake(context.Context, *HandshakeRequest) (*HandshakeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Handshake not implemented")
}

func (UnimplementedIngestServiceServer) mustEmbedUnimplementedIngestServiceServer() {}

type IngestService_SendEventsServer interface {
	Send(*Ack) error
	Recv() (*AgentEvent, error)
	grpc.ServerStream
}

type ingestServiceSendEventsServer struct {
	grpc.ServerStream
}

func (x *ingestServiceSendEventsServer) Send(m *Ack) error {
	return x.ServerStream.SendMsg(m)
}

func (x *ingestServiceSendEventsServer) Recv() (*AgentEvent, error) {
	m := new(AgentEvent)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// IngestService_ServiceDesc is the grpc.ServiceDesc for IngestService.
var IngestService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "shielddesk.ingest.v1.IngestService",
	HandlerType: (*IngestServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Handshake",
			Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
				in := new(HandshakeRequest)
				if err := dec(in); err != nil {
					return nil, err
				}
				if interceptor == nil {
					return srv.(IngestServiceServer).Handshake(ctx, in)
				}
				info := &grpc.UnaryServerInfo{
					Server:     srv,
					FullMethod: "/shielddesk.ingest.v1.IngestService/Handshake",
				}
				handler := func(ctx context.Context, req interface{}) (interface{}, error) {
					return srv.(IngestServiceServer).Handshake(ctx, req.(*HandshakeRequest))
				}
				return interceptor(ctx, in, info, handler)
			},
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "SendEvents",
			Handler: func(srv interface{}, stream grpc.ServerStream) error {
				return srv.(IngestServiceServer).SendEvents(&ingestServiceSendEventsServer{stream})
			},
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "shared/proto/ingest.proto",
}

func RegisterIngestServiceServer(s grpc.ServiceRegistrar, srv IngestServiceServer) {
	s.RegisterService(&IngestService_ServiceDesc, srv)
}
