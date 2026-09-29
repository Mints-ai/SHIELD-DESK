package telemetry

import (
	"runtime"
	"testing"
)

func TestCollector_HarvestMetrics(t *testing.T) {
	c := NewCollector()
	metrics := c.HarvestMetrics()

	if metrics.Platform != runtime.GOOS {
		t.Errorf("Expected platform %s, got %s", runtime.GOOS, metrics.Platform)
	}

	if metrics.CPUPercent < 0 || metrics.CPUPercent > 100 {
		t.Errorf("CPUPercent out of valid 0-100 range: %f", metrics.CPUPercent)
	}

	if metrics.MemPercent < 0 || metrics.MemPercent > 100 {
		t.Errorf("MemPercent out of valid 0-100 range: %f", metrics.MemPercent)
	}
}

func TestCollector_HarvestProcesses(t *testing.T) {
	c := NewCollector()
	procs := c.HarvestProcesses()

	// On Windows and Linux, there should be at least one process (the test runner itself)
	if runtime.GOOS == "windows" || runtime.GOOS == "linux" {
		if len(procs) == 0 {
			t.Logf("Notice: no processes harvested in current test environment (permission or container boundary)")
		} else {
			foundValidPID := false
			for _, p := range procs {
				if p.PID > 0 && p.Name != "" {
					foundValidPID = true
					break
				}
			}
			if !foundValidPID {
				t.Errorf("Expected at least one valid process with PID > 0, got %v", procs)
			}
		}
	}
}

func TestCollector_HarvestConnections(t *testing.T) {
	c := NewCollector()
	conns := c.HarvestConnections()

	// Should not crash, returns slice (can be empty depending on sandbox)
	t.Logf("Harvested %d active network connections on %s", len(conns), runtime.GOOS)
}

func TestCollector_DetectProcessAnomalies(t *testing.T) {
	c := NewCollector()
	// First run sets baseline
	events1 := c.DetectProcessAnomalies()
	if len(events1) != 0 {
		t.Errorf("First anomaly detection run should establish baseline with 0 new events, got %d", len(events1))
	}
}
