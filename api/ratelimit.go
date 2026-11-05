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

// withIPRateLimit is the PRE-authentication rate-limiting middleware, keyed by
// client IP. Authentication is expensive (bcrypt per Bearer, bbolt + HMAC per
// SigV4), so a limiter that ran only after it would let a caller with no valid
// credentials burn the CPU budget.
//
// Every request consumes one token from the "ip:<addr>" bucket; authenticated
// ones additionally consume one from their "<token_id>" bucket in
// withRateLimit. Both use the same Rate/Burst, so a single source IP can never
// exceed JAY_RATE_LIMIT req/s however many tokens it holds: a proxy or NAT in
// front of jay needs JAY_RATE_LIMIT sized for it and JAY_TRUST_PROXY_HEADERS
// set so the real client IP is the key.
func (h *Handler) withIPRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.ipRateLimiter.Enabled() {
			next(w, r)
			return
		}
		if !h.ipRateLimiter.Allow("ip:" + clientIP(r, h.trustProxyHeaders)) {
			writeRateLimited(w, r, h.ipRateLimiter.RetryAfterSeconds())
			return
		}
		next(w, r)
	}
}

// withRateLimit is the POST-authentication rate-limiting middleware, keyed by
// token ID. Anonymous requests are skipped here — they were already accounted
// for by withIPRateLimit, which is the only limiter that can see them before
// any CPU is spent.
func (h *Handler) withRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.rateLimiter.Enabled() {
			next(w, r)
			return
		}

		token := tokenFromContext(r.Context())
		if token == nil {
			next(w, r)
			return
		}

		if !h.rateLimiter.Allow(token.TokenID) {
			writeRateLimited(w, r, h.rateLimiter.RetryAfterSeconds())
			return
		}
		next(w, r)
	}
}

func writeRateLimited(w http.ResponseWriter, r *http.Request, retryAfter int) {
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Max(float64(retryAfter), 1))))
	writeS3Error(w, r, http.StatusTooManyRequests, "SlowDown", "Rate limit exceeded", r.URL.Path)
}

// clientIP extracts the client IP from the request.
//
// When trustProxyHeaders is false, X-Forwarded-For is IGNORED entirely and
// the direct TCP peer (RemoteAddr) is used. Trusting XFF automatically
// whenever the peer looks private is not an option: on a compose network every
// caller is private, and a spoofed header bypasses rate limiting and source-IP
// policies.
//
// When trustProxyHeaders is true, XFF is honoured only when the direct peer
// is loopback or RFC1918 private. Set JAY_TRUST_PROXY_HEADERS=1 only when a
// reverse proxy you control fronts jay.
//
//nolint:revive // trustProxyHeaders is deployment config, not a behaviour flag
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
		for part := range strings.SplitSeq(xff, ",") {
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
