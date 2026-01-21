package rpc

import (
	"sync"
	"time"
)

// RateLimiter limits the rate of requests per client
type RateLimiter struct {
	mu             sync.RWMutex
	requests       map[string]*clientState
	maxRequests    int
	windowDuration time.Duration
	cleanupInterval time.Duration
	lastCleanup     time.Time
}

// clientState tracks request state for a single client
type clientState struct {
	requests  []time.Time
	lastSeen  time.Time
}

// NewRateLimiter creates a new rate limiter
// maxRequests: maximum number of requests allowed per window
// windowDuration: time window for rate limiting (e.g., 1 minute)
func NewRateLimiter(maxRequests int, windowDuration time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests:        make(map[string]*clientState),
		maxRequests:     maxRequests,
		windowDuration:  windowDuration,
		cleanupInterval: 5 * time.Minute, // Cleanup stale entries every 5 minutes
		lastCleanup:     time.Now(),
	}

	// Start cleanup goroutine
	go rl.cleanupLoop()

	return rl
}

// Allow checks if a request from the given clientID is allowed
// Returns true if allowed, false if rate limit exceeded
func (rl *RateLimiter) Allow(clientID string) bool {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Periodic cleanup of stale entries
	if now.Sub(rl.lastCleanup) > rl.cleanupInterval {
		rl.cleanup(now)
		rl.lastCleanup = now
	}

	// Get or create client state
	state, exists := rl.requests[clientID]
	if !exists {
		state = &clientState{
			requests: make([]time.Time, 0, rl.maxRequests),
			lastSeen: now,
		}
		rl.requests[clientID] = state
	}

	// Remove old requests outside the window
	cutoff := now.Add(-rl.windowDuration)
	validRequests := state.requests[:0]
	for _, reqTime := range state.requests {
		if reqTime.After(cutoff) {
			validRequests = append(validRequests, reqTime)
		}
	}
	state.requests = validRequests

	// Check if rate limit exceeded
	if len(state.requests) >= rl.maxRequests {
		return false
	}

	// Add current request
	state.requests = append(state.requests, now)
	state.lastSeen = now

	return true
}

// cleanup removes stale client entries
func (rl *RateLimiter) cleanup(now time.Time) {
	staleThreshold := now.Add(-rl.cleanupInterval)
	for clientID, state := range rl.requests {
		if state.lastSeen.Before(staleThreshold) {
			delete(rl.requests, clientID)
		}
	}
}

// cleanupLoop periodically cleans up stale client entries
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		rl.mu.Lock()
		rl.cleanup(now)
		rl.lastCleanup = now
		rl.mu.Unlock()
	}
}

// GetStats returns statistics about the rate limiter
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	activeClients := len(rl.requests)
	totalRequests := 0
	for _, state := range rl.requests {
		totalRequests += len(state.requests)
	}

	return map[string]interface{}{
		"active_clients":  activeClients,
		"total_requests":  totalRequests,
		"max_requests":    rl.maxRequests,
		"window_duration": rl.windowDuration.String(),
	}
}

// Reset clears all rate limiting state
func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.requests = make(map[string]*clientState)
}
