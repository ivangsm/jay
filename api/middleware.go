package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/meta"
)

type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyToken
)

func requestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		return id
	}
	return ""
}

func tokenFromContext(ctx context.Context) *meta.Token {
	if t, ok := ctx.Value(ctxKeyToken).(*meta.Token); ok {
		return t
	}
	return nil
}

// generateRequestID produces a cryptographically random hex request ID.
//
// crypto/rand.Read's error is discarded because as of Go 1.24 it cannot happen:
// the function is documented as "never returns an error, and always fills b
// entirely" — if the OS cannot supply entropy, the runtime kills the process.
// The `_, _` is for the linter, not to paper over a possible failure.
func generateRequestID() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// withRequestID mints the request ID and is the OUTERMOST middleware of the
// chain. Everything else — the access log, the x-amz-request-id header, the
// <RequestId> inside every error document — reads it from the context this
// middleware installs, so all three carry the same value by construction.
//
// It has to be first because a middleware only ever sees the request it was
// handed. While the ID was minted halfway down the chain (in the old
// withRequestIDAndAuth), the logger wrapping it kept reading the ORIGINAL
// request and logged request_id="" on every single line, while the client got
// a real ID in its header: the one thing a request ID is for — finding the
// request someone reports by the ID the server gave them — did not work.
//
// Minting it here also covers the paths that never reach the credential
// middleware, all of which used to answer with no ID at all: the pre-auth IP
// rate limiter's 429, the aws-chunked 501, and a presigned URL that fails to
// verify.
//
// The ID is always generated, never taken from an inbound header: a client
// that could choose its own request ID could collide with someone else's or
// forge log entries.
func (h *Handler) withRequestID(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := generateRequestID()
		w.Header().Set("x-amz-request-id", reqID)
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKeyRequestID, reqID)))
	}
}

// withAuth authenticates the request and puts the resulting token (possibly
// nil) in the context. The request ID is already there — see withRequestID.
//
// Authentication never fails here: an unauthenticated request carries a nil
// token and every handler refuses it through requireAuth, which is also what
// lets a public-read bucket answer without credentials.
func (h *Handler) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, _ := h.auth.Authenticate(r)
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKeyToken, token)))
	}
}

// withLogging logs each request with structured logging and adds security
// headers. It must stay INSIDE withRequestID: the ID it logs is the one that
// travelled to the client, and it can only read it from a context an outer
// middleware installed.
func (h *Handler) withLogging(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		// Deferred, not written after next() returns: a panic below skips
		// everything after the call, so the ONE request that broke the process
		// was the only one with no access line at all. withRecover normally
		// absorbs the panic before it gets here, but the defer is what makes
		// that a belt rather than the only strap — including for a panic
		// raised by withRecover's own re-panic path.
		defer func() {
			// remote_ip is the key the pre-auth rate limiter buckets by, so
			// without it a 429 names no one and JAY_TRUST_PROXY_HEADERS cannot
			// be verified from the outside. It is derived exactly like the
			// limiter derives it, from the same function, so the log cannot
			// disagree with the decision.
			//
			// The token is deliberately NOT logged: withAuth resolves it
			// further down the chain, into a context this middleware never
			// sees, and the only way to hoist it back out is the shared mutable
			// pointer the request-ID fix just removed. An identity in the log is
			// not worth re-introducing the bug the log line is here to expose.
			h.log.Info("request",
				slog.String("request_id", requestIDFromContext(r.Context())),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("remote_ip", clientIP(r, h.trustProxyHeaders)),
				slog.Int("status", sw.status),
				slog.Duration("duration", time.Since(start)),
			)
		}()
		next(sw, r)
	}
}

// withRecover turns a panic below it into a 500 that names the request.
//
// Three things have to happen and none of them happened before: net/http's own
// recovery closes the connection with no response at all, and writes its stack
// to the package-level `log` — plain text on a stream that is JSON everywhere
// else, which a collector that parses JSON drops on the floor. So the request
// that broke the process was the only one leaving no trace, on exactly the
// occasion when knowing which request it was matters most.
//
//   - The client gets a real S3 error document whose <RequestId> is the same
//     string as the x-amz-request-id header it already received.
//   - One Error line goes out in the same JSON stream as everything else,
//     carrying the request id, the panic value and the stack.
//   - The counter moves, so /_jay/metrics shows a process that is panicking.
//
// It sits INSIDE withLogging, so the access line still comes out and carries
// status 500 — the recovered response goes through the same statusWriter.
//
// Recovering keeps the process alive with state that may be inconsistent, which
// in an object store is a real trade rather than an obvious win. It is taken
// deliberately: dying takes every other in-flight request down as well and
// still explains nothing, whereas this answers the broken request honestly,
// counts it, and leaves /health/ready as the thing that decides whether this
// instance keeps taking traffic.
func (h *Handler) withRecover(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			// http.ErrAbortHandler is net/http's documented way of abandoning a
			// response on purpose. It is not a fault, and net/http suppresses
			// its stack, so it is handed straight back untouched.
			if err, ok := rec.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(rec)
			}

			// debug.Stack() has to be called from inside the deferred function:
			// that is the only window in which the panicking frames are still
			// on the goroutine's stack.
			stack := debug.Stack()
			started := responseStarted(w)
			h.metrics.RecordPanicRecovered()
			h.log.Error("panic recovered",
				slog.String("request_id", requestIDFromContext(r.Context())),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("remote_ip", clientIP(r, h.trustProxyHeaders)),
				slog.Bool("response_started", started),
				slog.Any("panic", rec),
				slog.String("stack", string(stack)),
			)

			if started {
				// Half a body already went out under a status that promised a
				// whole one. Appending an error document to it would hand the
				// client a truncated object with a success code on top, which is
				// the exact defect this repo refuses. Aborting tears the
				// connection down so the transfer fails the way it actually did.
				panic(http.ErrAbortHandler)
			}
			writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
				"Internal error", r.URL.Path)
		}()
		next(w, r)
	}
}

// responseStarted reports whether any part of the response has reached the
// client already. Only a statusWriter can answer, and withRecover always sits
// below the one withLogging installs; anything else is assumed untouched, which
// is the reading that still produces an answer for the client.
func responseStarted(w http.ResponseWriter) bool {
	sw, ok := w.(*statusWriter)
	return ok && sw.wroteHeader
}

// requireAuth returns 401/403 if no valid token is present and the operation
// doesn't qualify for public access. Call this inside handlers that need auth.
//
// It is the single authorization gate of the HTTP surface: every handler in
// this package goes through it, so both halves of the decision live here — what
// the token is scoped to (auth.Authorize) and whether the token's account may
// reach this bucket at all (auth.AuthorizeBucketAccess). A handler added later
// inherits both by calling requireAuth, which it must do anyway to obtain the
// token.
func (h *Handler) requireAuth(r *http.Request, w http.ResponseWriter, action, bucketName, objectKey string) (*meta.Token, bool) {
	token := tokenFromContext(r.Context())

	// For read operations on public buckets, allow without token
	if token == nil {
		if (action == meta.ActionObjectGet || action == meta.ActionObjectList) && h.auth.IsPublicRead(bucketName) {
			return nil, true
		}
		if h.metrics != nil {
			h.metrics.AuthFailures.Add(1)
		}
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Authentication required", r.URL.Path)
		return nil, false
	}

	if err := h.auth.Authorize(token, action, bucketName, objectKey); err != nil {
		if h.metrics != nil {
			h.metrics.AuthFailures.Add(1)
		}
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Access denied", r.URL.Path)
		return nil, false
	}

	if !h.authorizeBucketAccess(r, w, token, action, bucketName, objectKey) {
		return nil, false
	}

	return token, true
}

// authorizeBucketAccess resolves the named bucket and applies the cross-account
// gate. Reports whether the request may proceed; writes the error response when
// it may not.
//
// A bucket that does not exist is NOT refused here: CreateBucket arrives with
// nothing to own, and every other handler answers its own 404 a few lines
// later. Turning a missing bucket into a 403 here would replace those with a
// misleading "access denied".
func (h *Handler) authorizeBucketAccess(
	r *http.Request, w http.ResponseWriter,
	token *meta.Token, action, bucketName, objectKey string,
) bool {
	if bucketName == "" {
		// Account-wide operation (ListBuckets); there is no bucket to own.
		return true
	}

	bucket, err := h.db.GetBucket(bucketName)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return true
		}
		h.log.Error("authorize bucket access: get bucket", "err", err, "bucket", bucketName)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", r.URL.Path)
		return false
	}

	return h.authorizeLoadedBucket(r, w, token, bucket, action, objectKey)
}

// authorizeLoadedBucket applies the cross-account gate to a bucket the caller
// already resolved. Handlers that load the bucket themselves use it so the
// decision keeps coming from one function — never from a second, slightly
// different rule.
func (h *Handler) authorizeLoadedBucket(
	r *http.Request, w http.ResponseWriter,
	token *meta.Token, bucket *meta.Bucket, action, objectKey string,
) bool {
	if err := auth.AuthorizeBucketAccess(token, bucket, action, objectKey, clientIP(r, h.trustProxyHeaders)); err != nil {
		if h.metrics != nil {
			h.metrics.AuthFailures.Add(1)
		}
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Access denied", r.URL.Path)
		return false
	}
	return true
}

// statusWriter wraps ResponseWriter to capture the status code and enable sendfile.
//
// wroteHeader records whether anything has reached the client yet. It is what
// lets withRecover tell a panic that happened before the response started
// (answerable with a 500) from one that happened halfway through a body
// (answerable only by tearing the connection down).
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (sw *statusWriter) WriteHeader(code int) {
	// The FIRST status is the one the client sees: net/http ignores every
	// later WriteHeader. Recording the last one would have made the access log
	// disagree with the response on any handler that tried twice.
	if !sw.wroteHeader {
		sw.status = code
		sw.wroteHeader = true
	}
	sw.ResponseWriter.WriteHeader(code)
}

// Write records that the response has begun. A handler that writes without
// calling WriteHeader first has implicitly sent a 200.
func (sw *statusWriter) Write(b []byte) (int, error) {
	sw.wroteHeader = true
	return sw.ResponseWriter.Write(b)
}

// ReadFrom enables sendfile(2) when copying from *os.File to the response.
func (sw *statusWriter) ReadFrom(r io.Reader) (int64, error) {
	sw.wroteHeader = true
	if rf, ok := sw.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(sw.ResponseWriter, r)
}

// Ensure statusWriter implements http.Flusher if the underlying writer does.
func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Compile-time interface checks.
var (
	_ http.ResponseWriter = (*statusWriter)(nil)
	_ io.ReaderFrom       = (*statusWriter)(nil)
)

// sanitizeHeaderValue removes \r and \n characters to prevent CRLF header injection.
var headerSanitizer = strings.NewReplacer("\r", "", "\n", "")

func sanitizeHeaderValue(v string) string {
	return headerSanitizer.Replace(v)
}
