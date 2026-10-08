package console

import (
	"crypto/subtle"
	"net/http"
)

// csrfHeader carries the per-session CSRF token on every unsafe request.
const csrfHeader = "X-Jay-Console-CSRF"

// setCommonHeaders applies what every response under /console gets, whatever
// it carries. Nothing here sets Access-Control-*: the console never serves
// another origin.
func setCommonHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
}

const (
	// cspDocument is the policy of index.html: scripts and styles only from
	// the console's own origin, never inline.
	cspDocument = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; " +
		"font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
	// cspLocked is for responses that are data, not documents.
	cspLocked = "default-src 'none'; frame-ancestors 'none'"
	// cspObject is for bytes of stored objects served from the console's
	// origin: sandboxed, so an uploaded HTML file cannot run as the console.
	cspObject = "sandbox; default-src 'none'"
)

// safeMethod reports whether m is a read-only method: no CSRF token and no
// Origin check, because it cannot change anything.
func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead
}

// checkFetchMetadata refuses a request the browser itself says is cross-site.
// A client that sends no Sec-Fetch-Site (curl, old browsers) passes: the other
// layers still apply.
func checkFetchMetadata(r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	return site == "" || site == "same-origin" || site == "none"
}

// checkOrigin refuses an unsafe request whose Origin is not this server.
func checkOrigin(r *http.Request) bool {
	if safeMethod(r.Method) {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return origin == scheme+"://"+r.Host
}

// checkCSRF compares the request's CSRF header with the session's token in
// constant time.
func checkCSRF(r *http.Request, want string) bool {
	got := r.Header.Get(csrfHeader)
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// refuseCrossSite is the one answer for both fetch-metadata and Origin failures.
func refuseCrossSite(w http.ResponseWriter) {
	writeJSONError(w, http.StatusForbidden, "cross-site request refused")
}
