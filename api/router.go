package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

// Handler is the S3-compatible HTTP handler.
type Handler struct {
	db            *meta.DB
	store         *store.Store
	auth          *auth.Auth
	log           *slog.Logger
	readChecker   *maintenance.ReadChecker
	metrics       *maintenance.Metrics
	signingSecret string
	rateLimiter   *rateLimiter
}

// NewHandler creates a new S3 API handler.
func NewHandler(db *meta.DB, st *store.Store, au *auth.Auth, log *slog.Logger, metrics *maintenance.Metrics, signingSecret string, rlCfg *RateLimiterConfig) *Handler {
	var rl *rateLimiter
	if rlCfg != nil && rlCfg.Rate > 0 {
		rl = newRateLimiter(*rlCfg)
	}
	return &Handler{
		db:            db,
		store:         st,
		auth:          au,
		log:           log,
		readChecker:   maintenance.NewReadChecker(0.05),
		metrics:       metrics,
		signingSecret: signingSecret,
		rateLimiter:   rl,
	}
}

// ServeHTTP dispatches S3 requests based on path and method.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler := h.withLogging(h.withPresigned(h.withRequestIDAndAuth(h.withRateLimit(h.dispatch))))
	handler(w, r)
}

// withPresigned checks for presigned URL query params before falling through
// to the normal auth middleware.
func (h *Handler) withPresigned(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.signingSecret != "" && r.URL.Query().Get("X-Jay-Token") != "" {
			token, err := validatePresignedRequest(r, h.signingSecret, h.db)
			if err != nil {
				writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Invalid presigned URL", r.URL.Path)
				return
			}
			// Set request ID and token, then go straight to rate limit + dispatch
			reqID := generateRequestID()
			ctx := context.WithValue(r.Context(), ctxKeyRequestID, reqID)
			ctx = context.WithValue(ctx, ctxKeyToken, token)
			w.Header().Set("x-amz-request-id", reqID)
			h.withRateLimit(h.dispatch)(w, r.WithContext(ctx))
			return
		}
		next(w, r)
	}
}

func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request) {
	// Custom JSON endpoint: GET /buckets/{name}/stats
	// This is NOT an S3 API path; it returns JSON and is auth'd by bucket:read-meta.
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/buckets/") && strings.HasSuffix(r.URL.Path, "/stats") {
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/buckets/"), "/stats")
		if name != "" && !strings.Contains(name, "/") {
			h.handleBucketStats(w, r, name)
			return
		}
	}

	// Parse path: /<bucket> or /<bucket>/<key...>
	path := strings.TrimPrefix(r.URL.Path, "/")

	// Root: list buckets
	if path == "" {
		if r.Method == http.MethodGet {
			h.handleListBuckets(w, r)
			return
		}
		writeS3Error(w, r, http.StatusMethodNotAllowed, S3ErrMethodNotAllowed, "Method not allowed", "/")
		return
	}

	// Split into bucket and key
	bucketName, objectKey, _ := strings.Cut(path, "/")

	if objectKey == "" {
		// Bucket-level operation
		switch r.Method {
		case http.MethodPut:
			h.handleCreateBucket(w, r, bucketName)
		case http.MethodDelete:
			h.handleDeleteBucket(w, r, bucketName)
		case http.MethodHead:
			h.handleHeadBucket(w, r, bucketName)
		case http.MethodGet:
			h.handleListObjectsV2(w, r, bucketName)
		default:
			writeS3Error(w, r, http.StatusMethodNotAllowed, S3ErrMethodNotAllowed, "Method not allowed", "/"+bucketName)
		}
		return
	}

	q := r.URL.Query()

	// Multipart operations (detected by query params)
	if q.Get("uploads") != "" || q.Has("uploads") {
		// POST /<bucket>/<key>?uploads → CreateMultipartUpload
		if r.Method == http.MethodPost {
			h.handleCreateMultipartUpload(w, r, bucketName, objectKey)
			return
		}
	}
	if uploadID := q.Get("uploadId"); uploadID != "" {
		switch r.Method {
		case http.MethodPut:
			// PUT /<bucket>/<key>?uploadId=X&partNumber=N → UploadPart
			h.handleUploadPart(w, r, bucketName, objectKey, uploadID)
		case http.MethodPost:
			// POST /<bucket>/<key>?uploadId=X → CompleteMultipartUpload
			h.handleCompleteMultipartUpload(w, r, bucketName, objectKey, uploadID)
		case http.MethodDelete:
			// DELETE /<bucket>/<key>?uploadId=X → AbortMultipartUpload
			h.handleAbortMultipartUpload(w, r, bucketName, objectKey, uploadID)
		case http.MethodGet:
			// GET /<bucket>/<key>?uploadId=X → ListParts
			h.handleListParts(w, r, bucketName, objectKey, uploadID)
		default:
			writeS3Error(w, r, http.StatusMethodNotAllowed, S3ErrMethodNotAllowed, "Method not allowed", "/"+bucketName+"/"+objectKey)
		}
		return
	}

	// Object-level operation
	switch r.Method {
	case http.MethodPut:
		if r.Header.Get("x-amz-copy-source") != "" {
			h.handleCopyObject(w, r, bucketName, objectKey)
		} else {
			h.handlePutObject(w, r, bucketName, objectKey)
		}
	case http.MethodGet:
		h.handleGetObject(w, r, bucketName, objectKey)
	case http.MethodHead:
		h.handleHeadObject(w, r, bucketName, objectKey)
	case http.MethodDelete:
		h.handleDeleteObject(w, r, bucketName, objectKey)
	case http.MethodPost:
		// POST without uploadId query is invalid for objects
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument, "Invalid request", "/"+bucketName+"/"+objectKey)
	default:
		writeS3Error(w, r, http.StatusMethodNotAllowed, S3ErrMethodNotAllowed, "Method not allowed", "/"+bucketName+"/"+objectKey)
	}
}
