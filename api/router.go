package api

import (
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
	db           *meta.DB
	store        *store.Store
	auth         *auth.Auth
	log          *slog.Logger
	readChecker  *maintenance.ReadChecker
	metrics      *maintenance.Metrics
}

// NewHandler creates a new S3 API handler.
func NewHandler(db *meta.DB, st *store.Store, au *auth.Auth, log *slog.Logger, metrics *maintenance.Metrics) *Handler {
	return &Handler{
		db:          db,
		store:       st,
		auth:        au,
		log:         log,
		readChecker: maintenance.NewReadChecker(0.05),
		metrics:     metrics,
	}
}

// ServeHTTP dispatches S3 requests based on path and method.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler := h.withRequestID(h.withLogging(h.withAuth(h.dispatch)))
	handler(w, r)
}

func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request) {
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
