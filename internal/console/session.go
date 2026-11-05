package console

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	sessionIdle     = 30 * time.Minute
	sessionAbsolute = 8 * time.Hour
	maxSessions     = 32

	cookieName     = "jay_console"
	cookieNameHost = "__Host-jay_console"
)

// Reasons a request has no session, as the UI sees them in the 401 body.
const (
	reasonMissing         = "missing"
	reasonUnknown         = "unknown"
	reasonExpiredIdle     = "expired_idle"
	reasonExpiredAbsolute = "expired_absolute"
)

type session struct {
	csrf     string
	created  time.Time
	lastSeen time.Time
}

// sessionStore keeps sessions in memory only. That is the point: signing out
// really revokes, and a restart (which is also how JAY_ADMIN_TOKEN rotates)
// ends every session. There is no sweeper goroutine; expired entries are
// dropped when touched and swept on every sign-in, and the store never holds
// more than maxSessions.
type sessionStore struct {
	mu sync.Mutex
	m  map[string]*session
}

func newSessionStore() *sessionStore {
	return &sessionStore{m: make(map[string]*session)}
}

// randomToken returns 32 bytes of crypto/rand as 43 base64url characters.
func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:]) // cannot fail since Go 1.24
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// sessionKey is how a session is stored and logged: the SHA-256 of its id, so
// a memory dump or an accidental print of the map holds nothing usable as a
// cookie.
func sessionKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// shortKey is the 8-hex form that audit and eviction lines name a session by.
func shortKey(key string) string {
	if len(key) > 8 {
		return key[:8]
	}
	return key
}

func (s *sessionStore) expiryReason(sess *session, now time.Time) string {
	if now.Sub(sess.created) >= sessionAbsolute {
		return reasonExpiredAbsolute
	}
	if now.Sub(sess.lastSeen) >= sessionIdle {
		return reasonExpiredIdle
	}
	return ""
}

// create starts a session. It sweeps expired ones first and, when the store is
// still full, evicts the one idle the longest; evicted is that session's key
// ("" when nobody was evicted).
func (s *sessionStore) create(now time.Time) (id string, sess session, evicted string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, old := range s.m {
		if s.expiryReason(old, now) != "" {
			delete(s.m, k)
		}
	}
	if len(s.m) >= maxSessions {
		var oldestKey string
		var oldest time.Time
		for k, cand := range s.m {
			if oldestKey == "" || cand.lastSeen.Before(oldest) {
				oldestKey, oldest = k, cand.lastSeen
			}
		}
		delete(s.m, oldestKey)
		evicted = oldestKey
	}

	id = randomToken()
	created := &session{csrf: randomToken(), created: now, lastSeen: now}
	s.m[sessionKey(id)] = created
	return id, *created, evicted
}

// lookup authenticates id and, when it is valid, slides its idle window. A
// session found expired is deleted on the spot, so it cannot be revived by a
// clock that moves back.
func (s *sessionStore) lookup(id string, now time.Time) (sess session, reason string) {
	if id == "" {
		return session{}, reasonMissing
	}
	key := sessionKey(id)

	s.mu.Lock()
	defer s.mu.Unlock()

	cur, ok := s.m[key]
	if !ok {
		return session{}, reasonUnknown
	}
	if why := s.expiryReason(cur, now); why != "" {
		delete(s.m, key)
		return session{}, why
	}
	cur.lastSeen = now
	return *cur, ""
}

func (s *sessionStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, sessionKey(id))
}

func (s *sessionStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// sessionCookie builds the cookie that carries id. It is a browser-session
// cookie (no Max-Age, no Domain): the server decides when it dies.
func (h *Handler) sessionCookie(id string) *http.Cookie {
	return &http.Cookie{
		Name:     h.cookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.info.TLS,
		SameSite: http.SameSiteStrictMode,
	}
}

// clearCookie expires the session cookie in the browser.
func (h *Handler) clearCookie(w http.ResponseWriter) {
	c := h.sessionCookie("")
	c.MaxAge = -1
	http.SetCookie(w, c)
}

// requireSession authenticates the request's cookie. On failure it has already
// written the 401 (and dropped a stale cookie) and ok is false.
func (h *Handler) requireSession(w http.ResponseWriter, r *http.Request) (sess session, ok bool) {
	id := ""
	if c, err := r.Cookie(h.cookieName); err == nil {
		id = c.Value
	}
	sess, reason := h.sessions.lookup(id, h.now())
	if reason == "" {
		return sess, true
	}
	if id != "" {
		h.clearCookie(w)
	}
	writeJSONReason(w, http.StatusUnauthorized, "not signed in", reason)
	return session{}, false
}

// requireSessionCSRF is requireSession plus the CSRF token check that every
// unsafe request needs.
func (h *Handler) requireSessionCSRF(w http.ResponseWriter, r *http.Request) (session, bool) {
	sess, ok := h.requireSession(w, r)
	if !ok {
		return session{}, false
	}
	if !safeMethod(r.Method) && !checkCSRF(r, sess.csrf) {
		writeJSONError(w, http.StatusForbidden, "missing or invalid CSRF token")
		return session{}, false
	}
	return sess, true
}

// sessionAttr names a session in a log line by the first 8 hex of its key.
func sessionAttr(id string) slog.Attr {
	return slog.String("session", shortKey(sessionKey(id)))
}
