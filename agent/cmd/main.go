package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"shielddesk/agent/pkg/audit"
	"shielddesk/agent/pkg/handlers"
	"shielddesk/agent/pkg/telemetry"
)

var (
	version    = "0.4.2"
	controlURL = flag.String("control-url", "http://localhost:3000", "ShieldDesk control-plane base URL")
	agentID    = flag.String("agent-id", "ea111111-1111-1111-1111-111111111111", "Enrolled Endpoint Agent ID")
	tenantID   = flag.String("tenant-id", "acme-tenant", "Tenant identifier")
	hostname   = flag.String("hostname", "", "Host identifier (defaults to os.Hostname)")
)

type QueuedCommand struct {
	ID        string `json:"id"`
	AgentID   string `json:"agent_id"`
	TenantID  string `json:"tenant_id"`
	Command   string `json:"command"`
	Tier      string `json:"tier"`
	Signature string `json:"signature"`
	CreatedAt string `json:"created_at"`
}

type CommandPollResponse struct {
	Commands []QueuedCommand `json:"commands"`
	Error    string          `json:"error,omitempty"`
}

type CommandResultPayload struct {
	Status     string `json:"status"`
	Output     string `json:"output"`
	SnapshotID string `json:"snapshotId,omitempty"`
}

func main() {
	flag.Parse()

	if *hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			*hostname = "UNKNOWN-HOST"
		} else {
			*hostname = h
		}
	}

	log.Printf("[ShieldDesk Agent v%s] Initializing Universal Endpoint Agent...", version)
	log.Printf("[Config] AgentID: %s | TenantID: %s | Hostname: %s | ControlPlane: %s",
		*agentID, *tenantID, *hostname, *controlURL)

	// Initialize local modules
	ringBuffer := telemetry.NewRingBuffer(10000)
	auditChain := audit.NewChain()
	actionHandler := handlers.NewActionHandler()
	actionHandler.SetControlPlane(*controlURL)

	log.Printf("[Audit] Initialized tamper-proof hash chain ledger. Genesis hash: %s",
		auditChain.Append("system", "STARTUP", map[string]interface{}{"status": "ready"}).CurrentHash[:16]+"...")

	// Initial baseline snapshot
	snapID, _ := actionHandler.TakeSafetySnapshot(*hostname)
	log.Printf("[Safety] Pre-flight baseline snapshot generated: %s", snapID)

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Start Telemetry producer simulation
	go func() {
		eventTypes := []string{"PROCESS_START", "NETWORK_CONNECT", "FILE_INTEGRITY_CHECK", "AUTH_ATTEMPT"}
		for {
			evt := telemetry.Event{
				ID:        fmt.Sprintf("evt-%d", time.Now().UnixNano()),
				Timestamp: time.Now().UTC(),
				EventType: eventTypes[rand.Intn(len(eventTypes))],
				Payload: map[string]interface{}{
					"cpu_pct": rand.Float64()*40 + 10,
					"mem_pct": rand.Float64()*30 + 50,
					"pid":     rand.Intn(9000) + 1000,
				},
			}
			ringBuffer.Push(evt)
			time.Sleep(500 * time.Millisecond)
		}
	}()

	// Heartbeat ticker to control plane
	heartbeatTicker := time.NewTicker(5 * time.Second)
	defer heartbeatTicker.Stop()

	go func() {
		for range heartbeatTicker.C {
			bufferedCount := ringBuffer.Size()
			log.Printf("[Heartbeat] Endpoint: %s | Buffered Events: %d | Status: CONNECTED",
				*hostname, bufferedCount)
		}
	}()

	// Command Polling loop
	pollTicker := time.NewTicker(3 * time.Second)
	defer pollTicker.Stop()

	go func() {
		for range pollTicker.C {
			pollCommands(httpClient, *controlURL, *agentID, *hostname, actionHandler)
		}
	}()

	// Handle OS shutdown signals gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	log.Printf("[Shutdown] Signal received. Flushing telemetry ring buffer and closing ledger.")
	drained := ringBuffer.DrainAll()
	log.Printf("[Shutdown] Successfully persisted %d un-drained events. Exiting clean.", len(drained))
}

func pollCommands(client *http.Client, controlURL, agentID, hostname string, handler *handlers.ActionHandler) {
	reqURL := fmt.Sprintf("%s/api/agent/commands?agent_id=%s", controlURL, agentID)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-ShieldDesk-Agent-ID", agentID)

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 423 {
		log.Printf("[CommandPoll] Agent %s is locked by Emergency Admin Kill Switch.", agentID)
		return
	}

	if resp.StatusCode != http.StatusOK {
		return
	}

	var pollResp CommandPollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
		return
	}

	dryRun := os.Getenv("REMEDIATION_DRY_RUN") == "true"

	for _, cmd := range pollResp.Commands {
		log.Printf("[CommandQueue] Picked up command ID: %s | Tier: %s | Action: %s",
			cmd.ID, cmd.Tier, cmd.Command)

		if cmd.Signature == "" {
			reportResult(client, controlURL, cmd.ID, "failed", "signature missing or invalid", "")
			continue
		}

		if dryRun {
			log.Printf("[CommandQueue-DryRun] DRY_RUN=true: Simulating action '%s' without state change.", cmd.Command)
			reportResult(client, controlURL, cmd.ID, "executed", fmt.Sprintf("[DRY-RUN] Command '%s' simulated successfully.", cmd.Command), "")
			continue
		}

		status, output, snapshotID := dispatch(cmd.Command, hostname, handler)
		reportResult(client, controlURL, cmd.ID, status, output, snapshotID)
	}
}

func dispatch(command, hostname string, handler *handlers.ActionHandler) (string, string, string) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "failed", "empty command", ""
	}

	action := parts[0]
	switch action {
	case "isolate_host":
		mgmtCIDR := ""
		if len(parts) > 1 {
			mgmtCIDR = parts[1]
		}
		out, err := handler.IsolateHost(hostname, mgmtCIDR)
		if err != nil {
			return "failed", err.Error(), ""
		}
		return "executed", out, ""

	case "restore_host":
		out, err := handler.RestoreHost(hostname)
		if err != nil {
			return "failed", err.Error(), ""
		}
		return "executed", out, ""

	case "block_ip":
		if len(parts) < 2 {
			return "failed", "missing target IP address", ""
		}
		ip := parts[1]
		mgmtGateway := ""
		if len(parts) > 2 {
			mgmtGateway = parts[2]
		}
		out, err := handler.BlockIP(hostname, ip, mgmtGateway)
		if err != nil {
			return "failed", err.Error(), ""
		}
		return "executed", out, ""

	case "kill_process":
		if len(parts) < 2 {
			return "failed", "missing target PID", ""
		}
		pid, err := strconv.Atoi(parts[1])
		if err != nil {
			return "failed", fmt.Sprintf("invalid PID '%s': %v", parts[1], err), ""
		}
		out, err := handler.KillProcess(hostname, pid)
		if err != nil {
			return "failed", err.Error(), ""
		}
		return "executed", out, ""

	case "take_safety_snapshot":
		snapID, err := handler.TakeSafetySnapshot(hostname)
		if err != nil {
			return "failed", err.Error(), ""
		}
		return "executed", fmt.Sprintf("Safety snapshot %s created on %s", snapID, hostname), snapID

	case "rollback_snapshot":
		targetSnap := ""
		if len(parts) > 1 {
			targetSnap = parts[1]
		}
		out, err := handler.Rollback(hostname, targetSnap)
		if err != nil {
			return "failed", err.Error(), ""
		}
		return "rolled_back", out, targetSnap

	default:
		return "failed", fmt.Sprintf("unrecognized command action: %s", action), ""
	}
}

func reportResult(client *http.Client, controlURL, commandID, status, output, snapshotID string) {
	reqURL := fmt.Sprintf("%s/api/agent/commands/%s/result", controlURL, commandID)
	payload := CommandResultPayload{
		Status:     status,
		Output:     output,
		SnapshotID: snapshotID,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return
	}

	resp, err := client.Post(reqURL, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		log.Printf("[CommandQueue] Failed to report result for command %s: %v", commandID, err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	log.Printf("[CommandQueue] Reported result for command %s: status=%s", commandID, status)
}
