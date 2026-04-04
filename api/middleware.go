package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

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

func generateRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// withRequestID adds a unique request ID to the context and response headers.
func (h *Handler) withRequestID(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := generateRequestID()
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, reqID)
		w.Header().Set("x-amz-request-id", reqID)
		next(w, r.WithContext(ctx))
	}
}

// withLogging logs each request with structured logging.
func (h *Handler) withLogging(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next(sw, r)
		h.log.Info("request",
			slog.String("request_id", requestIDFromContext(r.Context())),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", sw.status),
			slog.Duration("duration", time.Since(start)),
		)
	}
}

// withAuth authenticates the request. If auth fails and the bucket is not public-read,
// it returns an error. The token (or nil for public access) is stored in context.
func (h *Handler) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := h.auth.Authenticate(r)
		if err != nil {
			// Store nil token — handlers check public access separately
			ctx := context.WithValue(r.Context(), ctxKeyToken, (*meta.Token)(nil))
			next(w, r.WithContext(ctx))
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyToken, token)
		next(w, r.WithContext(ctx))
	}
}

// requireAuth returns 401/403 if no valid token is present and the operation
// doesn't qualify for public access. Call this inside handlers that need auth.
func (h *Handler) requireAuth(r *http.Request, w http.ResponseWriter, action, bucketName, objectKey string) (*meta.Token, bool) {
	token := tokenFromContext(r.Context())

	// For read operations on public buckets, allow without token
	if token == nil {
		if (action == meta.ActionObjectGet || action == meta.ActionObjectList) && h.auth.IsPublicRead(bucketName) {
			return nil, true
		}
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Authentication required", r.URL.Path)
		return nil, false
	}

	if err := h.auth.Authorize(token, action, bucketName, objectKey); err != nil {
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Access denied", r.URL.Path)
		return nil, false
	}

	return token, true
}

// statusWriter wraps ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

// Ensure statusWriter implements http.Flusher if the underlying writer does.
func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Compile-time interface check.
var _ http.ResponseWriter = (*statusWriter)(nil)
