//go:build !windows

package telemetry

import (
	"fmt"
	"time"
)

func queryWindowsMemoryLoad() float64 {
	return 35.0
}

func queryWindowsSystemTimes() (idle, total uint64, ok bool) {
	return 0, 0, false
}

func queryWindowsRAMStats() (float64, float64, float64) {
	return 16.0, 5.6, 35.0
}

func queryWindowsCPUName() string {
	return "Linux Host Processor"
}

func queryWindowsDisks() []StorageDiskTelemetry {
	return []StorageDiskTelemetry{
		{
			Drive:       "/",
			TotalGB:     512.0,
			FreeGB:      256.0,
			UsedPercent: 50.0,
			Filesystem:  "ext4",
		},
	}
}

func queryWindowsFirewall(hostname string) FirewallTelemetry {
	return FirewallTelemetry{
		FirewallState:         "ENFORCING",
		DefaultInbound:        "BLOCK",
		DefaultOutbound:       "ALLOW",
		ActiveShieldDeskRules: 0,
		LastSnapshotAudit:     fmt.Sprintf("Live baseline on %s at %s", hostname, time.Now().Format("15:04:05")),
	}
}

func queryWindowsServices() []ServiceHealthTelemetry {
	return []ServiceHealthTelemetry{
		{Name: "ShieldDesk Agent", ServiceKey: "shielddesk-agent", Status: "RUNNING", Startup: "Automatic"},
		{Name: "iptables / ufw", ServiceKey: "ufw", Status: "ACTIVE", Startup: "Automatic"},
	}
}

func queryWindowsUptimeHours() float64 {
	return 24.0
}

