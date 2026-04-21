// Package ratelimit implements the token-bucket rate limiter shared between
// the HTTP S3 API and the native TCP protocol. Both transports used to have
// separate limiters (sliding window in proto, token bucket in api). The proto
// side tracked a rateBurst field but never applied it. This package is the
// single source of truth — both transports import it and burst is now real.
//
// Keys are transport-specific: the HTTP middleware uses "ip:<client>" for
// anonymous requests and "<token_id>" for authenticated ones; the proto
// server uses "<token_id>@<remote_addr>" so per-connection bursts can't be
// evaded by opening multiple connections with the same token.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Config holds rate-limiter configuration.
//
// Rate is requests per second. If Rate <= 0 the limiter is disabled (Allow
// always returns true). Burst is the maximum token-bucket capacity; if Burst
// <= 0 it defaults to 2 * Rate (matching the historical api/ratelimit.go
// behaviour so operators don't see a silent capacity change).
type Config struct {
	Rate  float64
	Burst int
}

// Limiter is a token-bucket limiter keyed by an opaque caller-supplied string.
// Safe for concurrent use. Buckets are lazily allocated per key and an idle
// cleanup goroutine evicts entries unused for more than 1 hour every 5 min.
type Limiter struct {
	config  Config
	buckets sync.Map // key string → *bucket

	stopCleanup chan struct{}
	stopOnce    sync.Once
}

type bucket struct {
	mu       sync.Mutex
	tokens   float64
	maxBurst float64
	rate     float64
	lastTime time.Time
}

// New constructs a Limiter. If cfg.Rate <= 0 the returned limiter permits all
// calls (this is the cheapest disabled state — no allocation per request).
//
// The cleanup goroutine is started automatically and stopped with Stop.
func New(cfg Config) *Limiter {
	if cfg.Burst <= 0 {
		cfg.Burst = int(cfg.Rate * 2)
		if cfg.Burst < 1 {
			cfg.Burst = 1
		}
	}
	l := &Limiter{
		config:      cfg,
		stopCleanup: make(chan struct{}),
	}
	if cfg.Rate > 0 {
		go l.cleanupLoop()
	}
	return l
}

// Enabled reports whether this limiter will ever return false from Allow.
func (l *Limiter) Enabled() bool {
	return l != nil && l.config.Rate > 0
}

// Allow deducts one token for key and returns whether the request is permitted.
// If the limiter is disabled, Allow returns true without touching any state.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.config.Rate <= 0 {
		return true
	}

	val, _ := l.buckets.LoadOrStore(key, &bucket{
		tokens:   float64(l.config.Burst),
		maxBurst: float64(l.config.Burst),
		rate:     l.config.Rate,
		lastTime: time.Now(),
	})
	b := val.(*bucket)

	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens = math.Min(b.maxBurst, b.tokens+elapsed*b.rate)
	b.lastTime = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// RetryAfterSeconds returns a hint (in whole seconds) for the Retry-After
// header. Returns 0 when the limiter is disabled.
func (l *Limiter) RetryAfterSeconds() int {
	if l == nil || l.config.Rate <= 0 {
		return 0
	}
	return int(math.Ceil(1.0 / l.config.Rate))
}

// Stop halts the background cleanup goroutine. Safe to call multiple times.
func (l *Limiter) Stop() {
	if l == nil {
		return
	}
	l.stopOnce.Do(func() { close(l.stopCleanup) })
}

func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-l.stopCleanup:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-1 * time.Hour)
			l.buckets.Range(func(key, value any) bool {
				b := value.(*bucket)
				b.mu.Lock()
				idle := b.lastTime.Before(cutoff)
				b.mu.Unlock()
				if idle {
					l.buckets.Delete(key)
				}
				return true
			})
		}
	}
}
