package api

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/ivangsm/jay/internal/ratelimit"
)

// RateLimiterConfig is retained for backward compatibility with existing
// main.go wiring. It is a thin alias over internal/ratelimit.Config.
type RateLimiterConfig struct {
	Rate  float64 // requests per second per token (0 = disabled)
	Burst int     // maximum burst size
}

// newRateLimiter constructs the shared token-bucket limiter. The proto server
// instantiates the same type via the internal/ratelimit package directly.
func newRateLimiter(cfg RateLimiterConfig) *ratelimit.Limiter {
	return ratelimit.New(ratelimit.Config{Rate: cfg.Rate, Burst: cfg.Burst})
}

// withRateLimit is the HTTP rate-limiting middleware. Must run after auth so
// that the token ID is available in context. For anonymous requests the limit
// key falls back to the client IP.
func (h *Handler) withRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.rateLimiter.Enabled() {
			next(w, r)
			return
		}

		var key string
		if token := tokenFromContext(r.Context()); token != nil {
			key = token.TokenID
		} else {
			key = "ip:" + clientIP(r, h.trustProxyHeaders)
		}

		if !h.rateLimiter.Allow(key) {
			retry := h.rateLimiter.RetryAfterSeconds()
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Max(float64(retry), 1))))
			writeS3Error(w, r, http.StatusTooManyRequests, "SlowDown", "Rate limit exceeded", r.URL.Path)
			return
		}
		next(w, r)
	}
}

// clientIP extracts the client IP from the request.
//
// When trustProxyHeaders is false, X-Forwarded-For is IGNORED entirely and
// the direct TCP peer (RemoteAddr) is used. This is the safe default — the
// old behaviour, which auto-trusted XFF whenever RemoteAddr looked "private
// or loopback", was a spoofable heuristic that bypassed rate limiting and
// source-IP policies for any caller able to reach jay over a private network
// (which is... every deployment behind a docker-compose network).
//
// When trustProxyHeaders is true, XFF is honoured only when the direct peer
// is loopback or RFC1918 private — the standard "trust the proxy that
// terminates TLS for us" arrangement. Set JAY_TRUST_PROXY_HEADERS=1 only
// when you actually front jay with a reverse proxy you control.
func clientIP(r *http.Request, trustProxyHeaders bool) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !trustProxyHeaders {
		return host
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && isTrustedProxy(host) {
		// Leftmost non-empty token is the original client IP.
		for _, part := range strings.Split(xff, ",") {
			ip := strings.TrimSpace(part)
			if ip != "" {
				return ip
			}
		}
	}
	return host
}

// isTrustedProxy reports whether ip is loopback or RFC1918 private, indicating
// the connection came through a trusted reverse proxy. Only consulted when
// trustProxyHeaders is true.
func isTrustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() || parsed.IsPrivate()
}
