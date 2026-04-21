package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ivangsm/jay/internal/objops"
	"github.com/ivangsm/jay/meta"
)

// buildIdentity snapshots the request-bound context needed by objops for
// bucket-policy evaluation. It is called by every object handler after
// requireAuth has populated the token (or confirmed public-read fallback).
//
// TokenID / AccountID may be empty when the request is an anonymous read on
// a public-read bucket — in that case policy statements that match "*" as
// subject still apply with an empty token ID, which is the intended S3-like
// behaviour for deny-over-anonymous.
func (h *Handler) buildIdentity(r *http.Request, action string) objops.Identity {
	id := objops.Identity{
		SourceIP: clientIP(r, h.trustProxyHeaders),
		Action:   action,
	}
	if tok := tokenFromContext(r.Context()); tok != nil {
		id.TokenID = tok.TokenID
		id.AccountID = tok.AccountID
	}
	return id
}

// mapObjopsErr translates an objops.* error into an S3 HTTP response. Returns
// true if the error was handled (and a response written), false otherwise —
// in the latter case the caller should emit a generic 500.
func (h *Handler) mapObjopsErr(w http.ResponseWriter, r *http.Request, err error, bucketName, objectKey string) bool {
	switch {
	case errors.Is(err, objops.ErrBucketNotFound):
		writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchBucket, "Bucket not found", "/"+bucketName)
	case errors.Is(err, objops.ErrObjectNotFound):
		writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchKey, "Object not found", "/"+bucketName+"/"+objectKey)
	case errors.Is(err, objops.ErrPolicyDenied), errors.Is(err, objops.ErrAccessDenied):
		if h.metrics != nil {
			h.metrics.AuthFailures.Add(1)
		}
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Access denied", "/"+bucketName+"/"+objectKey)
	default:
		return false
	}
	return true
}

// handlePutObject handles PUT /<bucket>/<key>. Delegates to objops.Service for
// the authorize → write → commit path. Preserves the existing response
// headers: ETag (quoted per S3), x-amz-checksum-sha256, 200 OK.
func (h *Handler) handlePutObject(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
	token, ok := h.requireAuth(r, w, meta.ActionObjectPut, bucketName, objectKey)
	if !ok {
		return
	}

	// Collect user metadata (x-amz-meta-*) from the request headers. Keys are
	// already lower-cased by the map iteration; we sanitize values to strip
	// CR/LF so they can't inject further headers on echo-back.
	userMeta := make(map[string]string)
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-meta-") && len(v) > 0 {
			userMeta[lk] = sanitizeHeaderValue(v[0])
		}
	}

	contentType := r.Header.Get("Content-Type")

	obj, err := h.objops.PutObject(
		r.Context(), token,
		bucketName, objectKey, contentType,
		r.Body,
		objops.PutOptions{UserMetadata: userMeta},
		h.buildIdentity(r, meta.ActionObjectPut),
	)
	if err != nil {
		if h.mapObjopsErr(w, r, err, bucketName, objectKey) {
			return
		}
		h.log.Error("put object", "err", err, "bucket", bucketName, "key", objectKey)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Failed to store object", "/"+bucketName+"/"+objectKey)
		return
	}

	if h.metrics != nil {
		h.metrics.PutObjectTotal.Add(1)
		h.metrics.BytesUploaded.Add(obj.SizeBytes)
	}

	w.Header().Set("ETag", formatETag(obj.ETag))
	w.Header().Set("x-amz-checksum-sha256", obj.ChecksumSHA256)
	w.WriteHeader(http.StatusOK)
}

// handleGetObject handles GET /<bucket>/<key>. Range requests are served by
// seeking into the physical file; full-object GETs are streamed via io.Copy
// so the kernel sendfile(2) path is reached (statusWriter implements
// ReadFrom). No per-read checksum verification — the scrubber owns integrity.
func (h *Handler) handleGetObject(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
	token, ok := h.requireAuth(r, w, meta.ActionObjectGet, bucketName, objectKey)
	if !ok {
		return
	}

	// HEAD-style metadata resolution first — we need Size/ContentType before
	// we can set the headers and decide if this is a Range request.
	obj, err := h.objops.HeadObject(r.Context(), token, bucketName, objectKey, h.buildIdentity(r, meta.ActionObjectGet))
	if err != nil {
		if h.mapObjopsErr(w, r, err, bucketName, objectKey) {
			return
		}
		h.log.Error("get object meta", "err", err, "bucket", bucketName, "key", objectKey)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", "/"+bucketName+"/"+objectKey)
		return
	}

	f, err := h.objops.OpenObjectFile(obj)
	if err != nil {
		h.log.Error("read object", "err", err, "location", obj.LocationRef)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Failed to read object", "/"+bucketName+"/"+objectKey)
		return
	}
	defer func() { _ = f.Close() }()

	w.Header().Set("Content-Type", obj.ContentType)
	w.Header().Set("ETag", formatETag(obj.ETag))
	w.Header().Set("Last-Modified", obj.UpdatedAt.UTC().Format(http.TimeFormat))
	w.Header().Set("x-amz-checksum-sha256", obj.ChecksumSHA256)
	w.Header().Set("Accept-Ranges", "bytes")

	for k, v := range obj.MetadataHeaders {
		w.Header().Set(k, v)
	}

	if h.metrics != nil {
		h.metrics.GetObjectTotal.Add(1)
	}

	// Range support. We still set Content-Range/Content-Length explicitly
	// because io.CopyN writes exactly the range; sendfile kicks in for those
	// bytes too (statusWriter.ReadFrom → *net.TCPConn.ReadFrom → *os.File).
	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		start, end, ok := parseRange(rangeHeader, obj.SizeBytes)
		if !ok {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", obj.SizeBytes))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		length := end - start + 1
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
				"Failed to seek", "/"+bucketName+"/"+objectKey)
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, obj.SizeBytes))
		if h.metrics != nil {
			h.metrics.BytesDownloaded.Add(length)
		}
		w.WriteHeader(http.StatusPartialContent)
		if _, err := io.CopyN(w, f, length); err != nil {
			h.log.Warn("send object range", "err", err, "bucket", bucketName, "key", objectKey)
		}
		return
	}

	w.Header().Set("Content-Length", strconv.FormatInt(obj.SizeBytes, 10))

	if h.metrics != nil {
		h.metrics.BytesDownloaded.Add(obj.SizeBytes)
	}

	w.WriteHeader(http.StatusOK)
	// io.Copy → statusWriter.ReadFrom → TCPConn.ReadFrom → sendfile(2) on Linux.
	// No re-hashing: read-time integrity is the scrubber's job (maintenance/scrub.go).
	if _, err := io.Copy(w, f); err != nil {
		h.log.Warn("send object", "err", err, "bucket", bucketName, "key", objectKey)
	}
}

// handleHeadObject handles HEAD /<bucket>/<key>. Returns the same headers as
// GET minus the body. x-amz-checksum-sha256 is exposed so clients can verify
// post-download without a second round-trip.
func (h *Handler) handleHeadObject(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
	if h.metrics != nil {
		h.metrics.HeadObjectTotal.Add(1)
	}
	token, ok := h.requireAuth(r, w, meta.ActionObjectGet, bucketName, objectKey)
	if !ok {
		return
	}

	obj, err := h.objops.HeadObject(r.Context(), token, bucketName, objectKey, h.buildIdentity(r, meta.ActionObjectGet))
	if err != nil {
		switch {
		case errors.Is(err, objops.ErrBucketNotFound), errors.Is(err, objops.ErrObjectNotFound):
			// HEAD cannot carry an XML error body — only the status.
			w.WriteHeader(http.StatusNotFound)
		case errors.Is(err, objops.ErrPolicyDenied), errors.Is(err, objops.ErrAccessDenied):
			if h.metrics != nil {
				h.metrics.AuthFailures.Add(1)
			}
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", obj.ContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(obj.SizeBytes, 10))
	w.Header().Set("ETag", formatETag(obj.ETag))
	w.Header().Set("Last-Modified", obj.UpdatedAt.UTC().Format(http.TimeFormat))
	w.Header().Set("x-amz-checksum-sha256", obj.ChecksumSHA256)
	for k, v := range obj.MetadataHeaders {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusOK)
}

// handleDeleteObject handles DELETE /<bucket>/<key>. Returns 204 No Content
// whether or not the object existed — mirrors S3 semantics (idempotent).
func (h *Handler) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
	token, ok := h.requireAuth(r, w, meta.ActionObjectDelete, bucketName, objectKey)
	if !ok {
		return
	}

	err := h.objops.DeleteObject(r.Context(), token, bucketName, objectKey, h.buildIdentity(r, meta.ActionObjectDelete))
	if err != nil {
		if h.mapObjopsErr(w, r, err, bucketName, objectKey) {
			return
		}
		h.log.Error("delete object", "err", err, "bucket", bucketName, "key", objectKey)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", fmt.Sprintf("/%s/%s", bucketName, objectKey))
		return
	}

	if h.metrics != nil {
		h.metrics.DeleteObjectTotal.Add(1)
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseRange parses a Range header value like "bytes=0-499" or "bytes=-500" or
// "bytes=500-". Returns start, end (inclusive), and whether the range is valid.
func parseRange(rangeHeader string, totalSize int64) (start, end int64, ok bool) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, 0, false
	}
	spec := strings.TrimPrefix(rangeHeader, "bytes=")
	if strings.Contains(spec, ",") {
		// Multi-range is valid per RFC 7233 but we only support single range.
		return 0, 0, false
	}

	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}

	if parts[0] == "" {
		// Suffix range: bytes=-500 means last 500 bytes.
		suffix, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || suffix <= 0 {
			return 0, 0, false
		}
		start = max(totalSize-suffix, 0)
		return start, totalSize - 1, true
	}

	start, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || start < 0 || start >= totalSize {
		return 0, 0, false
	}

	if parts[1] == "" {
		// Open-ended: bytes=500-
		return start, totalSize - 1, true
	}

	end, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil || end < start {
		return 0, 0, false
	}
	if end >= totalSize {
		end = totalSize - 1
	}
	return start, end, true
}
