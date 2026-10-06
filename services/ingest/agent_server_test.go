package main

import (
	"context"
	"io"
	"testing"
	"time"

	ingestv1 "shielddesk/shared/proto/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type mockHeartbeatServer struct {
	grpc.ServerStream
	incoming []*ingestv1.HeartbeatPing
	outgoing []*ingestv1.HeartbeatPong
	index    int
}

func (m *mockHeartbeatServer) Context() context.Context {
	return context.Background()
}

func (m *mockHeartbeatServer) SetHeader(metadata.MD) error  { return nil }
func (m *mockHeartbeatServer) SendHeader(metadata.MD) error { return nil }
func (m *mockHeartbeatServer) SetTrailer(metadata.MD)       {}

func (m *mockHeartbeatServer) Recv() (*ingestv1.HeartbeatPing, error) {
	if m.index >= len(m.incoming) {
		return nil, io.EOF
	}
	p := m.incoming[m.index]
	m.index++
	return p, nil
}

func (m *mockHeartbeatServer) Send(pong *ingestv1.HeartbeatPong) error {
	m.outgoing = append(m.outgoing, pong)
	return nil
}

func TestAgentServer_StreamHeartbeat(t *testing.T) {
	server := NewAgentServer(nil, nil)

	mockStream := &mockHeartbeatServer{
		incoming: []*ingestv1.HeartbeatPing{
			{
				TenantId:               "acme-tenant",
				AgentId:                "FIN-WS-042",
				Hostname:               "FIN-WS-042",
				OsType:                 "windows",
				AgentVersion:           "1.0.0",
				Timestamp:              time.Now().UnixMilli(),
				CpuUsagePct:            14.2,
				MemoryUsagePct:         42.5,
				ProcessCount:           180,
				NetworkConnectionCount: 35,
				ClientCertFingerprint:  "sha256:abc123def456",
			},
		},
	}

	err := server.StreamHeartbeat(mockStream)
	if err != nil {
		t.Fatalf("StreamHeartbeat returned error: %v", err)
	}

	if len(mockStream.outgoing) != 1 {
		t.Fatalf("expected 1 pong response, got %d", len(mockStream.outgoing))
	}

	pong := mockStream.outgoing[0]
	if !pong.Acknowledged {
		t.Errorf("expected Acknowledged = true, got false")
	}

	if pong.NextIntervalSec != 15 {
		t.Errorf("expected NextIntervalSec = 15, got %d", pong.NextIntervalSec)
	}

	if pong.KillSwitchEngaged {
		t.Errorf("expected KillSwitchEngaged = false by default, got true")
	}
}
