package main

import (
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

type AssetBaseline struct {
	AssetID      string
	AuthMean     float64
	AuthStdDev   float64
	NetMean      float64
	NetStdDev    float64
	KnownIPs     map[string]bool
	KnownProcess map[string]bool
}

type AnomalyDetector struct {
	mu        sync.RWMutex
	baselines map[string]*AssetBaseline
}

func NewAnomalyDetector() *AnomalyDetector {
	ad := &AnomalyDetector{
		baselines: make(map[string]*AssetBaseline),
	}
	return ad
}

func (ad *AnomalyDetector) getOrCreateBaseline(assetID string) *AssetBaseline {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	b, exists := ad.baselines[assetID]
	if !exists {
		// Default baseline: mean auth hour ~13 (1 PM), stddev ~3 hours; normal net bytes ~5000, stddev ~2000
		b = &AssetBaseline{
			AssetID:      assetID,
			AuthMean:     13.0,
			AuthStdDev:   3.0,
			NetMean:      5000.0,
			NetStdDev:    2000.0,
			KnownIPs:     make(map[string]bool),
			KnownProcess: make(map[string]bool),
		}
		ad.baselines[assetID] = b
	}
	return b
}

// ScoreEvent computes standard score (z-score) deviation = (observed - mean) / stddev
// Alerts if deviation > 3σ for auth events, > 2σ for network events.
func (ad *AnomalyDetector) ScoreEvent(event *IngestEvent) *Alert {
	b := ad.getOrCreateBaseline(event.AssetId)

	// 1. Auth Anomaly Check (e.g. login at 3 AM on an office workstation)
	if event.EventType == "auth" {
		t := time.UnixMilli(event.Timestamp).UTC()
		hour := float64(t.Hour())

		// Calculate hour difference wrapped around 24h clock
		diff := math.Abs(hour - b.AuthMean)
		if diff > 12 {
			diff = 24 - diff
		}

		zScore := diff / b.AuthStdDev
		if zScore > 3.0 { // > 3 sigma deviation
			return &Alert{
				ID:        uuid.New().String(),
				TenantID:  event.TenantId,
				AssetID:   event.AssetId,
				Severity:  "high",
				Type:      "anomaly",
				RuleID:    "ML-ANOMALY-AUTH-3SIGMA",
				RuleName:  fmt.Sprintf("Anomalous Off-Hours Authentication (%.1fσ Deviation)", zScore),
				Payload: map[string]interface{}{
					"observed_hour": hour,
					"baseline_mean": b.AuthMean,
					"z_score":       zScore,
					"deviation":     "> 3σ",
				},
				CreatedAt: time.Now().UTC(),
			}
		}
	}

	// 2. Network Outbound Bytes Anomaly Check
	if event.EventType == "network" {
		bytesStr := event.Payload["bytes_out"]
		if bytesStr != "" {
			bytesVal, err := strconv.ParseFloat(bytesStr, 64)
			if err == nil && bytesVal > b.NetMean {
				zScore := (bytesVal - b.NetMean) / b.NetStdDev
				if zScore > 2.0 { // > 2 sigma deviation for network
					return &Alert{
						ID:        uuid.New().String(),
						TenantID:  event.TenantId,
						AssetID:   event.AssetId,
						Severity:  "medium",
						Type:      "anomaly",
						RuleID:    "ML-ANOMALY-NET-2SIGMA",
						RuleName:  fmt.Sprintf("Unusual Outbound Data Spike (%.1fσ Deviation)", zScore),
						Payload: map[string]interface{}{
							"observed_bytes": bytesVal,
							"baseline_mean":  b.NetMean,
							"z_score":        zScore,
							"deviation":      "> 2σ",
							"destination":    event.Payload["dest_ip"],
						},
						CreatedAt: time.Now().UTC(),
					}
				}
			}
		}
	}

	return nil
}
