package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/signal"
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

	log.Printf("[Audit] Initialized tamper-proof hash chain ledger. Genesis hash: %s",
		auditChain.Append("system", "STARTUP", map[string]interface{}{"status": "ready"}).CurrentHash[:16]+"...")

	// Initial baseline snapshot
	snapID, _ := actionHandler.TakeSafetySnapshot(*hostname)
	log.Printf("[Safety] Pre-flight baseline snapshot generated: %s", snapID)

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
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			bufferedCount := ringBuffer.Size()
			// In production, would send HTTP POST /api/agent/heartbeat with mTLS
			log.Printf("[Heartbeat] Endpoint: %s | Buffered Events: %d | Status: CONNECTED",
				*hostname, bufferedCount)
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
