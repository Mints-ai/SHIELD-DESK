package ingestv1

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// HeartbeatPing represents live telemetry status emitted periodically by an endpoint agent.
type HeartbeatPing struct {
	TenantId               string  `json:"tenant_id,omitempty"`
	AgentId                string  `json:"agent_id,omitempty"`
	Hostname               string  `json:"hostname,omitempty"`
	OsType                 string  `json:"os_type,omitempty"`
	AgentVersion           string  `json:"agent_version,omitempty"`
	Timestamp              int64   `json:"timestamp,omitempty"`
	CpuUsagePct            float64 `json:"cpu_usage_pct,omitempty"`
	MemoryUsagePct         float64 `json:"memory_usage_pct,omitempty"`
	ProcessCount           int32   `json:"process_count,omitempty"`
	NetworkConnectionCount int32   `json:"network_connection_count,omitempty"`
	ClientCertFingerprint  string  `json:"client_cert_fingerprint,omitempty"`
}

func (x *HeartbeatPing) GetTenantId() string               { if x != nil { return x.TenantId }; return "" }
func (x *HeartbeatPing) GetAgentId() string                { if x != nil { return x.AgentId }; return "" }
func (x *HeartbeatPing) GetHostname() string               { if x != nil { return x.Hostname }; return "" }
func (x *HeartbeatPing) GetOsType() string                 { if x != nil { return x.OsType }; return "" }
func (x *HeartbeatPing) GetAgentVersion() string           { if x != nil { return x.AgentVersion }; return "" }
func (x *HeartbeatPing) GetTimestamp() int64              { if x != nil { return x.Timestamp }; return 0 }
func (x *HeartbeatPing) GetCpuUsagePct() float64           { if x != nil { return x.CpuUsagePct }; return 0 }
func (x *HeartbeatPing) GetMemoryUsagePct() float64        { if x != nil { return x.MemoryUsagePct }; return 0 }
func (x *HeartbeatPing) GetProcessCount() int32            { if x != nil { return x.ProcessCount }; return 0 }
func (x *HeartbeatPing) GetNetworkConnectionCount() int32  { if x != nil { return x.NetworkConnectionCount }; return 0 }
func (x *HeartbeatPing) GetClientCertFingerprint() string  { if x != nil { return x.ClientCertFingerprint }; return "" }

// HeartbeatPong represents control plane directives returned in response to an agent heartbeat.
type HeartbeatPong struct {
	Acknowledged             bool  `json:"acknowledged,omitempty"`
	Timestamp                int64 `json:"timestamp,omitempty"`
	NextIntervalSec          int32 `json:"next_interval_sec,omitempty"`
	KillSwitchEngaged        bool  `json:"kill_switch_engaged,omitempty"`
	CertificateRenewalNeeded bool  `json:"certificate_renewal_needed,omitempty"`
}

func (x *HeartbeatPong) GetAcknowledged() bool             { if x != nil { return x.Acknowledged }; return false }
func (x *HeartbeatPong) GetTimestamp() int64              { if x != nil { return x.Timestamp }; return 0 }
func (x *HeartbeatPong) GetNextIntervalSec() int32         { if x != nil { return x.NextIntervalSec }; return 0 }
func (x *HeartbeatPong) GetKillSwitchEngaged() bool        { if x != nil { return x.KillSwitchEngaged }; return false }
func (x *HeartbeatPong) GetCertificateRenewalNeeded() bool { if x != nil { return x.CertificateRenewalNeeded }; return false }

// AgentCommand represents an authoritative, signed instruction sent to an endpoint agent.
type AgentCommand struct {
	CommandId       string            `json:"command_id,omitempty"`
	TenantId        string            `json:"tenant_id,omitempty"`
	AgentId         string            `json:"agent_id,omitempty"`
	Tier            string            `json:"tier,omitempty"`
	Command         string            `json:"command,omitempty"`
	Arguments       map[string]string `json:"arguments,omitempty"`
	ApprovalTokenId string            `json:"approval_token_id,omitempty"`
	IssuedAt        int64             `json:"issued_at,omitempty"`
	ExpiresAt       int64             `json:"expires_at,omitempty"`
	Nonce           string            `json:"nonce,omitempty"`
	Signature       string            `json:"signature,omitempty"`
}

func (x *AgentCommand) GetCommandId() string             { if x != nil { return x.CommandId }; return "" }
func (x *AgentCommand) GetTenantId() string              { if x != nil { return x.TenantId }; return "" }
func (x *AgentCommand) GetAgentId() string               { if x != nil { return x.AgentId }; return "" }
func (x *AgentCommand) GetTier() string                  { if x != nil { return x.Tier }; return "" }
func (x *AgentCommand) GetCommand() string               { if x != nil { return x.Command }; return "" }
func (x *AgentCommand) GetArguments() map[string]string  { if x != nil { return x.Arguments }; return nil }
func (x *AgentCommand) GetApprovalTokenId() string       { if x != nil { return x.ApprovalTokenId }; return "" }
func (x *AgentCommand) GetIssuedAt() int64               { if x != nil { return x.IssuedAt }; return 0 }
func (x *AgentCommand) GetExpiresAt() int64              { if x != nil { return x.ExpiresAt }; return 0 }
func (x *AgentCommand) GetNonce() string                 { if x != nil { return x.Nonce }; return "" }
func (x *AgentCommand) GetSignature() string             { if x != nil { return x.Signature }; return "" }

// CommandResult represents the execution outcome reported by the endpoint agent.
type CommandResult struct {
	CommandId       string `json:"command_id,omitempty"`
	TenantId        string `json:"tenant_id,omitempty"`
	AgentId         string `json:"agent_id,omitempty"`
	Status          string `json:"status,omitempty"`
	ExecutionOutput string `json:"execution_output,omitempty"`
	ErrorMessage    string `json:"error_message,omitempty"`
	ExecutedAt      int64  `json:"executed_at,omitempty"`
	DurationMs      int64  `json:"duration_ms,omitempty"`
	SnapshotId      string `json:"snapshot_id,omitempty"`
	ResultHash      string `json:"result_hash,omitempty"`
}

func (x *CommandResult) GetCommandId() string       { if x != nil { return x.CommandId }; return "" }
func (x *CommandResult) GetTenantId() string        { if x != nil { return x.TenantId }; return "" }
func (x *CommandResult) GetAgentId() string         { if x != nil { return x.AgentId }; return "" }
func (x *CommandResult) GetStatus() string          { if x != nil { return x.Status }; return "" }
func (x *CommandResult) GetExecutionOutput() string { if x != nil { return x.ExecutionOutput }; return "" }
func (x *CommandResult) GetErrorMessage() string    { if x != nil { return x.ErrorMessage }; return "" }
func (x *CommandResult) GetExecutedAt() int64       { if x != nil { return x.ExecutedAt }; return 0 }
func (x *CommandResult) GetDurationMs() int64       { if x != nil { return x.DurationMs }; return 0 }
func (x *CommandResult) GetSnapshotId() string      { if x != nil { return x.SnapshotId }; return "" }
func (x *CommandResult) GetResultHash() string      { if x != nil { return x.ResultHash }; return "" }

// AgentServiceServer is the server API for AgentService.
type AgentServiceServer interface {
	StreamHeartbeat(AgentService_StreamHeartbeatServer) error
	StreamCommands(AgentService_StreamCommandsServer) error
}

type UnimplementedAgentServiceServer struct{}

func (UnimplementedAgentServiceServer) StreamHeartbeat(AgentService_StreamHeartbeatServer) error {
	return status.Errorf(codes.Unimplemented, "method StreamHeartbeat not implemented")
}

func (UnimplementedAgentServiceServer) StreamCommands(AgentService_StreamCommandsServer) error {
	return status.Errorf(codes.Unimplemented, "method StreamCommands not implemented")
}

type AgentService_StreamHeartbeatServer interface {
	Send(*HeartbeatPong) error
	Recv() (*HeartbeatPing, error)
	grpc.ServerStream
}

type agentServiceStreamHeartbeatServer struct {
	grpc.ServerStream
}

func (x *agentServiceStreamHeartbeatServer) Send(m *HeartbeatPong) error {
	return x.ServerStream.SendMsg(m)
}

func (x *agentServiceStreamHeartbeatServer) Recv() (*HeartbeatPing, error) {
	m := new(HeartbeatPing)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

type AgentService_StreamCommandsServer interface {
	Send(*AgentCommand) error
	Recv() (*CommandResult, error)
	grpc.ServerStream
}

type agentServiceStreamCommandsServer struct {
	grpc.ServerStream
}

func (x *agentServiceStreamCommandsServer) Send(m *AgentCommand) error {
	return x.ServerStream.SendMsg(m)
}

func (x *agentServiceStreamCommandsServer) Recv() (*CommandResult, error) {
	m := new(CommandResult)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// AgentService_ServiceDesc is the grpc.ServiceDesc for AgentService.
var AgentService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "shielddesk.agent.v1.AgentService",
	HandlerType: (*AgentServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamHeartbeat",
			Handler: func(srv interface{}, stream grpc.ServerStream) error {
				return srv.(AgentServiceServer).StreamHeartbeat(&agentServiceStreamHeartbeatServer{stream})
			},
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "StreamCommands",
			Handler: func(srv interface{}, stream grpc.ServerStream) error {
				return srv.(AgentServiceServer).StreamCommands(&agentServiceStreamCommandsServer{stream})
			},
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "shared/proto/agent.proto",
}

func RegisterAgentServiceServer(s grpc.ServiceRegistrar, srv AgentServiceServer) {
	s.RegisterService(&AgentService_ServiceDesc, srv)
}
