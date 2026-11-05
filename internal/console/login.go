package console

import (
	jsonv2 "encoding/json/v2"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/ivangsm/jay/internal/jsonx"
)

// maxLoginBody bounds the login body: a token is 32+ bytes, never kilobytes.
const maxLoginBody = 4 << 10

// retryAfterLockout is what a locked-out address is told. It mirrors the admin
// API's 15-minute backoff window.
const retryAfterLockout = 15 * time.Minute

// SessionInfo is the body of a successful login and of GET /console/api/session.
type SessionInfo struct {
	CSRFToken          string    `json:"csrf_token"`
	ExpiresAt          time.Time `json:"expires_at"`
	IdleTimeoutSeconds int       `json:"idle_timeout_seconds"`
	Version            string    `json:"version"`
	Commit             string    `json:"commit"`
	Ready              bool      `json:"ready"`
	TLS                bool      `json:"tls"`
	S3ListenAddr       string    `json:"s3_listen_addr"`
	MaxObjectSize      int64     `json:"max_object_size"`
	Actions            []string  `json:"actions"`
}

func (h *Handler) sessionInfo(sess session) SessionInfo {
	actions := h.info.Actions
	if actions == nil {
		actions = []string{}
	}
	return SessionInfo{
		CSRFToken:          sess.csrf,
		ExpiresAt:          sess.created.Add(sessionAbsolute).UTC(),
		IdleTimeoutSeconds: int(sessionIdle / time.Second),
		Version:            h.info.Version,
		Commit:             h.info.Commit,
		Ready:              h.ready(),
		TLS:                h.info.TLS,
		S3ListenAddr:       h.info.S3ListenAddr,
		MaxObjectSize:      h.info.MaxObjectSize,
		Actions:            actions,
	}
}

// serveSession dispatches /console/api/session by method.
func (h *Handler) serveSession(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.login(w, r)
	case http.MethodGet:
		sess, ok := h.requireSession(w, r)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, h.sessionInfo(sess))
	case http.MethodDelete:
		h.logout(w, r)
	default:
		methodNotAllowed(w, "GET, POST, DELETE")
	}
}

// login exchanges the admin token for a session. The check goes through the
// admin API's own authenticator so this door shares its failure counter
// instead of being a second place to guess the token.
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := jsonv2.UnmarshalRead(http.MaxBytesReader(w, r.Body, maxLoginBody), &req, jsonx.Strict); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Token == "" {
		writeJSONError(w, http.StatusBadRequest, "token is required")
		return
	}

	switch h.authenticate(r, req.Token) {
	case LoginAccepted:
		id, sess, evicted := h.sessions.create(h.now())
		if evicted != "" {
			h.log.Info("console session evicted", "session", shortKey(evicted))
		}
		http.SetCookie(w, h.sessionCookie(id))
		h.audit(r, "console.login", sessionAttr(id))
		writeJSON(w, http.StatusCreated, h.sessionInfo(sess))
	case LoginLockedOut:
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfterLockout/time.Second)))
		writeJSONError(w, http.StatusTooManyRequests, "too many failed attempts from this address; try again in 15 minutes")
	default:
		// LoginRejected, and anything the authenticator may grow later: only an
		// explicit acceptance opens a session.
		writeJSONError(w, http.StatusUnauthorized, "invalid admin token")
	}
}

// logout ends the session for real: it leaves the store, so the old cookie is
// worthless even if someone kept a copy.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireSessionCSRF(w, r); !ok {
		return
	}
	id := ""
	if c, err := r.Cookie(h.cookieName); err == nil {
		id = c.Value
	}
	h.sessions.delete(id)
	h.clearCookie(w)
	h.audit(r, "console.logout", sessionAttr(id))
	w.WriteHeader(http.StatusNoContent)
}
