package admin

// The admin listener's trail: a request ID and an access line for every
// request, and an audit line for every change an operator made.
//
// Before this, the admin listener wrote nothing at all for a request that
// succeeded. Creating an account, minting a token, revoking one, issuing a
// presigned URL — the only trace any of them left was the credential itself,
// which is no help when the question after an incident is "when did this token
// appear, and from where?".

import (
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/ivangsm/jay/internal/accesslog"
)

// Trace wraps the whole admin listener — /_jay, /metrics, pprof and the health
// probes alike — in a request ID minted at the edge and one access line per
// request.
//
// The ID comes back in the x-amz-request-id header, as on the S3 listener. The
// access line, the audit line, the auth-failure line, the panic line and the
// quarantine manager's own lines all carry it.
//
// The access line names method, path, status, duration, response bytes,
// remote_ip and request_id — never a body and never a query string: the body
// of POST /_jay/tokens carries a secret, and a presigned URL carries its
// signature in the query.
//
// probePaths are logged at DEBUG while they answer 200: an orchestrator that
// probes every five seconds would otherwise write some seventeen thousand lines
// a day that bury everything else. They are not excluded, so turning on debug
// shows them. A probe that answers anything else is logged at WARN, because a
// failing readiness check is exactly the line someone will go looking for.
func (h *Handler) Trace(next http.Handler, probePaths ...string) http.Handler {
	probes := make(map[string]bool, len(probePaths))
	for _, p := range probePaths {
		probes[p] = true
	}
	inner := h.recoverPanics(next)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = accesslog.Stamp(w, r)
		rec := accesslog.NewRecorder(w)
		start := time.Now()
		// Deferred so the request that panicked still gets its line: a panic
		// that recoverPanics hands back to net/http unwinds through here.
		defer func() {
			level := slog.LevelInfo
			if probes[r.URL.Path] {
				level = slog.LevelDebug
				if rec.Status() != http.StatusOK {
					level = slog.LevelWarn
				}
			}
			h.log.LogAttrs(r.Context(), level, "admin request",
				slog.String("request_id", accesslog.RequestID(r.Context())),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("remote_ip", accesslog.PeerIP(r)),
				slog.Int("status", rec.Status()),
				slog.Int64("bytes", rec.Bytes()),
				slog.Duration("duration", time.Since(start)),
			)
		}()
		inner.ServeHTTP(rec, r)
	})
}

// recoverPanics turns a panic below it into a JSON 500 that names the request,
// instead of leaving net/http to close the connection with no response. Without
// it the access line above would report the 200 a Recorder starts with — a
// success line for a request that crashed.
//
// If the response had already started, no honest status is left to send, so
// the connection is torn down with http.ErrAbortHandler instead.
func (h *Handler) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			p := recover()
			if p == nil {
				return
			}
			if err, ok := p.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(p)
			}
			// debug.Stack has to run inside the deferred call: that is the
			// only moment the panicking frames are still on the stack.
			stack := debug.Stack()
			started := false
			if rec, ok := w.(*accesslog.Recorder); ok {
				started = rec.Started()
			}
			h.metrics.RecordPanicRecovered()
			h.log.Error("panic recovered",
				slog.String("request_id", accesslog.RequestID(r.Context())),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("remote_ip", accesslog.PeerIP(r)),
				slog.Bool("response_started", started),
				slog.Any("panic", p),
				slog.String("stack", string(stack)),
			)
			if started {
				panic(http.ErrAbortHandler)
			}
			writeJSONError(w, http.StatusInternalServerError, "internal error")
		}()
		next.ServeHTTP(w, r)
	})
}

// requestLog is h.log with the request's ID attached, for work that logs on
// its own — the quarantine manager — so its lines join the access line.
func (h *Handler) requestLog(r *http.Request) *slog.Logger {
	return h.log.With(slog.String("request_id", accesslog.RequestID(r.Context())))
}

// audit writes the trail line of an admin operation that changed something.
// See auditAt.
func (h *Handler) audit(r *http.Request, action string, attrs ...slog.Attr) {
	h.auditAt(r, slog.LevelInfo, action, attrs...)
}

// auditAt writes one "audit" line: what was done (action), the IDs it touched,
// and the request it came from — the same request_id as the access line, so
// the two join.
//
// Handlers call it only AFTER the change has committed. An operation that
// failed leaves its access line, with its status, and no audit line: a trail
// that records attempts as if they were changes is worse than none. And no
// attribute ever carries a secret, a presigned URL or a signature.
func (h *Handler) auditAt(r *http.Request, level slog.Level, action string, attrs ...slog.Attr) {
	line := make([]slog.Attr, 0, 3+len(attrs))
	line = append(line,
		slog.String("request_id", accesslog.RequestID(r.Context())),
		slog.String("action", action),
		slog.String("remote_ip", accesslog.PeerIP(r)),
	)
	h.log.LogAttrs(r.Context(), level, "audit", append(line, attrs...)...)
}

// expiryAttr renders a token expiry for the audit line: RFC 3339, or "never".
// Omitting the attribute would read as "not logged", not as "does not expire".
func expiryAttr(t *time.Time) slog.Attr {
	if t == nil {
		return slog.String("expires_at", "never")
	}
	return slog.String("expires_at", t.UTC().Format(time.RFC3339))
}
