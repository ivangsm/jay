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
// client IP.
//
// It exists because authentication is expensive: a Bearer credential costs one
// bcrypt comparison (~60-100ms of CPU) and SigV4 costs a bbolt read plus HMAC
// derivation. With the limiter running only *after* auth, a caller with no
// valid credentials at all could burn the whole CPU budget — every request paid
// for bcrypt before the limiter ever saw it. This middleware is therefore the
// outermost gate: nothing is authenticated until the source IP has a token in
// its bucket.
//
// Accounting (deliberate, documented): every request consumes one token from
// the "ip:<addr>" bucket. Authenticated requests additionally consume one token
// from their "<token_id>" bucket in withRateLimit. There is no double counting
// inside a single bucket — anonymous requests are limited by IP only (the
// post-auth middleware skips them), authenticated ones by IP *and* token.
//
// Both buckets use the same configured Rate/Burst, which gives one statable
// invariant: a single source IP can never exceed JAY_RATE_LIMIT req/s, no
// matter how many tokens it holds. Deployments that front jay with a proxy or
// NAT many clients behind one address must size JAY_RATE_LIMIT accordingly (and
// set JAY_TRUST_PROXY_HEADERS so the real client IP is used as the key).
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
