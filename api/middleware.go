package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/internal/accesslog"
	"github.com/ivangsm/jay/meta"
)

type ctxKey int

const ctxKeyToken ctxKey = iota

// requestIDFromContext returns the ID withRequestID installed. The ID itself —
// how it is minted, where it lives in the context, which header carries it —
// is internal/accesslog's, shared with the admin listener so the two cannot
// drift.
func requestIDFromContext(ctx context.Context) string {
	return accesslog.RequestID(ctx)
}

func tokenFromContext(ctx context.Context) *meta.Token {
	if t, ok := ctx.Value(ctxKeyToken).(*meta.Token); ok {
		return t
	}
	return nil
}

// withRequestID mints the request ID and is the OUTERMOST middleware of the
// chain. Everything else — the access log, the x-amz-request-id header, the
// <RequestId> inside every error document — reads it from the context this
// middleware installs, so all three carry the same value by construction.
//
// It has to be first because a middleware only ever sees the request it was
// handed: an ID minted further down the chain leaves an outer logger reading
// the ORIGINAL request and logging request_id="". Minting it here also covers
// the paths that never reach the credential middleware: the pre-auth IP rate
// limiter's 429, a refused aws-chunked body, and a presigned URL that fails to
// verify.
//
// The ID is always generated, never taken from an inbound header: a client
// that could choose its own request ID could collide with someone else's or
// forge log entries.
func (h *Handler) withRequestID(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(w, accesslog.Stamp(w, r))
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
		sw := accesslog.NewRecorder(w)
		// Deferred, not written after next() returns: a panic below skips
		// everything after the call, and the request that panicked is the one
		// that most needs an access line. withRecover normally absorbs the
		// panic first; the defer also covers its own re-panic path.
		defer func() {
			// remote_ip is the key the pre-auth rate limiter buckets by, so
			// without it a 429 names no one and JAY_TRUST_PROXY_HEADERS cannot
			// be verified from the outside. It is derived exactly like the
			// limiter derives it, from the same function, so the log cannot
			// disagree with the decision.
			//
			// The token is NOT logged: withAuth resolves it further down the
			// chain, into a context this middleware never sees, and hoisting
			// it back out would take a shared mutable pointer across the chain.
			h.log.Info("request",
				slog.String("request_id", requestIDFromContext(r.Context())),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("remote_ip", clientIP(r, h.trustProxyHeaders)),
				slog.Int("status", sw.Status()),
				slog.Duration("duration", time.Since(start)),
			)
		}()
		next(sw, r)
	}
}

// withRecover turns a panic below it into a 500 that names the request. Left
// to net/http, a panic closes the connection with no response and writes its
// stack as plain text to the package-level `log`. Here the client gets an S3
// error document with the same <RequestId> as its header, one Error line goes
// out in the JSON stream with the panic value and the stack, and the counter
// moves. It sits INSIDE withLogging, so the access line still comes out with
// status 500 through the same statusWriter.
//
// Recovering keeps the process alive with state that may be inconsistent:
// /health/ready and the panic counter decide whether this instance keeps
// taking traffic.
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
	return ok && sw.Started()
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

// statusWriter is the recorder withLogging installs: the status that reached
// the client, whether the response has started (what withRecover asks), and a
// ReadFrom that keeps sendfile(2) reachable. It is accesslog.Recorder, shared
// with the admin listener; the name stays because the sendfile comments in
// object_handlers.go and the middleware order in router.go refer to it.
type statusWriter = accesslog.Recorder

// sanitizeHeaderValue removes \r and \n characters to prevent CRLF header injection.
var headerSanitizer = strings.NewReplacer("\r", "", "\n", "")

func sanitizeHeaderValue(v string) string {
	return headerSanitizer.Replace(v)
}
