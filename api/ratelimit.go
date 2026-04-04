package api

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RateLimiterConfig holds rate limiting configuration.
type RateLimiterConfig struct {
	Rate  float64 // requests per second per token (0 = disabled)
	Burst int     // maximum burst size
}

// rateLimiter implements per-token token bucket rate limiting.
type rateLimiter struct {
	config  RateLimiterConfig
	buckets sync.Map // map[string]*tokenBucket (key = token ID or "__anonymous__")
}

type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	maxBurst float64
	rate     float64
	lastTime time.Time
}

func newRateLimiter(cfg RateLimiterConfig) *rateLimiter {
	if cfg.Burst <= 0 {
		cfg.Burst = int(cfg.Rate * 2)
	}
	return &rateLimiter{config: cfg}
}

func (rl *rateLimiter) allow(key string) bool {
	if rl == nil || rl.config.Rate <= 0 {
		return true
	}

	val, _ := rl.buckets.LoadOrStore(key, &tokenBucket{
		tokens:   float64(rl.config.Burst),
		maxBurst: float64(rl.config.Burst),
		rate:     rl.config.Rate,
		lastTime: time.Now(),
	})
	bucket := val.(*tokenBucket)

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(bucket.lastTime).Seconds()
	bucket.tokens = math.Min(bucket.maxBurst, bucket.tokens+elapsed*bucket.rate)
	bucket.lastTime = now

	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (rl *rateLimiter) retryAfter(key string) float64 {
	if rl == nil || rl.config.Rate <= 0 {
		return 0
	}
	return 1.0 / rl.config.Rate
}

// withRateLimit is the rate limiting middleware. Must be called after auth
// so the token ID is available in context.
func (h *Handler) withRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.rateLimiter == nil || h.rateLimiter.config.Rate <= 0 {
			next(w, r)
			return
		}

		key := "__anonymous__"
		if token := tokenFromContext(r.Context()); token != nil {
			key = token.TokenID
		}

		if !h.rateLimiter.allow(key) {
			retryAfter := h.rateLimiter.retryAfter(key)
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter))))
			writeS3Error(w, r, http.StatusTooManyRequests, "SlowDown", "Rate limit exceeded", r.URL.Path)
			return
		}
		next(w, r)
	}
}
