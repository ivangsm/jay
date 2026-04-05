package api

import (
	"math"
	"net"
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
	buckets sync.Map // map[string]*tokenBucket (key = token ID or "ip:<addr>")
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

		var key string
		if token := tokenFromContext(r.Context()); token != nil {
			key = token.TokenID
		} else {
			key = "ip:" + clientIP(r)
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

// clientIP extracts the client IP address from the request.
// It checks X-Forwarded-For (using only the rightmost/last entry, which is
// the most recently appended by a trusted proxy) and falls back to
// r.RemoteAddr with the port stripped.
func clientIP(r *http.Request) string {
	// X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2".
	// The last entry is the one appended by the closest (most trusted) proxy.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Find the last comma-separated value.
		for i := len(xff) - 1; i >= 0; i-- {
			if xff[i] == ',' {
				ip := trimSpace(xff[i+1:])
				if ip != "" {
					return ip
				}
			}
		}
		// No comma found — single value.
		ip := trimSpace(xff)
		if ip != "" {
			return ip
		}
	}

	// Fall back to RemoteAddr, stripping the port.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr may already lack a port.
		return r.RemoteAddr
	}
	return host
}

// trimSpace trims leading and trailing ASCII spaces (avoids importing strings).
func trimSpace(s string) string {
	for len(s) > 0 && s[0] == ' ' {
		s = s[1:]
	}
	for len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1]
	}
	return s
}
