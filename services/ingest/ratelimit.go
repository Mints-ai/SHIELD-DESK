package main

import (
	"sync"
	"time"
)

const (
	MaxEventsPerMinute = 10000
	WindowDuration     = time.Minute
)

type TenantRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tenantBucket
}

type tenantBucket struct {
	count     int
	windowEnd time.Time
}

func NewTenantRateLimiter() *TenantRateLimiter {
	rl := &TenantRateLimiter{
		buckets: make(map[string]*tenantBucket),
	}
	// Background cleanup of expired buckets every 2 minutes
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		for range ticker.C {
			rl.mu.Lock()
			now := time.Now()
			for tenantID, b := range rl.buckets {
				if now.After(b.windowEnd) {
					delete(rl.buckets, tenantID)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

// AllowEvent checks if a tenant is within the 10,000 events/min rate limit.
// Returns (allowed, backpressure).
func (rl *TenantRateLimiter) AllowEvent(tenantID string) (bool, bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.buckets[tenantID]

	if !exists || now.After(bucket.windowEnd) {
		rl.buckets[tenantID] = &tenantBucket{
			count:     1,
			windowEnd: now.Add(WindowDuration),
		}
		return true, false
	}

	bucket.count++
	if bucket.count > MaxEventsPerMinute {
		// Backpressure engaged: agent must slow down
		return false, true
	}

	// If over 80% capacity, signal proactive backpressure
	backpressure := bucket.count > (MaxEventsPerMinute * 8 / 10)
	return true, backpressure
}
