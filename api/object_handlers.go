package api

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
)

// handlePutObject handles PUT /<bucket>/<key>
func (h *Handler) handlePutObject(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
	_, ok := h.requireAuth(r, w, meta.ActionObjectPut, bucketName, objectKey)
	if !ok {
		return
	}

	bucket, err := h.db.GetBucket(bucketName)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchBucket,
				"Bucket not found", "/"+bucketName)
			return
		}
		h.log.Error("get bucket", "err", err)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", "/"+bucketName+"/"+objectKey)
		return
	}

	objectID := uuid.New().String()

	// Calculate MD5 for ETag while the store calculates SHA-256
	md5Hash := md5.New()
	body := io.TeeReader(r.Body, md5Hash)

	// Write to store (atomic: temp → fsync → rename → fsync dir)
	checksum, size, locationRef, err := h.store.WriteObject(bucket.ID, objectID, body)
	if err != nil {
		h.log.Error("write object", "err", err, "bucket", bucketName, "key", objectKey)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Failed to store object", "/"+bucketName+"/"+objectKey)
		return
	}

	etag := hex.EncodeToString(md5Hash.Sum(nil))

	// Determine content type
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Collect user metadata (x-amz-meta-*)
	userMeta := make(map[string]string)
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-meta-") && len(v) > 0 {
			userMeta[lk] = sanitizeHeaderValue(v[0])
		}
	}

	obj := &meta.Object{
		BucketID:        bucket.ID,
		Key:             objectKey,
		ObjectID:        objectID,
		State:           "active",
		SizeBytes:       size,
		ContentType:     contentType,
		ETag:            etag,
		ChecksumSHA256:  checksum,
		LocationRef:     locationRef,
		CreatedAt:       time.Now().UTC(),
		MetadataHeaders: userMeta,
	}

	// Commit metadata (returns previous version if overwriting)
	prev, err := h.db.PutObjectMeta(obj)
	if err != nil {
		// Metadata commit failed — clean up the physical file
		h.store.Cleanup(locationRef)
		h.log.Error("put object meta", "err", err, "bucket", bucketName, "key", objectKey)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Failed to store metadata", "/"+bucketName+"/"+objectKey)
		return
	}

	// GC the previous version's physical file if overwriting
	if prev != nil && prev.LocationRef != locationRef {
		if err := h.store.DeleteObject(prev.LocationRef); err != nil {
			h.log.Warn("gc previous object", "err", err, "location", prev.LocationRef)
		}
	}

	if h.metrics != nil {
		h.metrics.PutObjectTotal.Add(1)
		h.metrics.BytesUploaded.Add(size)
	}

	w.Header().Set("ETag", formatETag(etag))
	w.Header().Set("x-amz-checksum-sha256", checksum)
	w.WriteHeader(http.StatusOK)
}

// handleGetObject handles GET /<bucket>/<key>
func (h *Handler) handleGetObject(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
	_, ok := h.requireAuth(r, w, meta.ActionObjectGet, bucketName, objectKey)
	if !ok {
		return
	}

	bucket, err := h.db.GetBucket(bucketName)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchBucket,
				"Bucket not found", "/"+bucketName)
			return
		}
		h.log.Error("get bucket", "err", err)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", "/"+bucketName+"/"+objectKey)
		return
	}

	obj, err := h.db.GetObjectMeta(bucket.ID, objectKey)
	if err != nil {
		if errors.Is(err, meta.ErrObjectNotFound) {
			writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchKey,
				"Object not found", "/"+bucketName+"/"+objectKey)
			return
		}
		h.log.Error("get object meta", "err", err)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", "/"+bucketName+"/"+objectKey)
		return
	}

	f, err := h.store.ReadObject(obj.LocationRef)
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

	// Set user metadata headers
	for k, v := range obj.MetadataHeaders {
		w.Header().Set(k, v)
	}

	if h.metrics != nil {
		h.metrics.GetObjectTotal.Add(1)
	}

	// Range request support
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		start, end, ok := parseRange(rangeHeader, obj.SizeBytes)
		if !ok {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", obj.SizeBytes))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}

		// Probabilistic checksum verification for range requests (files <= 64MB)
		if h.readChecker.ShouldVerify() && obj.SizeBytes <= 64<<20 {
			verifier := maintenance.NewReadVerifier(f, obj.ChecksumSHA256)
			if _, err := io.Copy(io.Discard, verifier); err != nil {
				h.log.Error("range read verify", "err", err, "bucket", bucketName, "key", objectKey)
				writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
					"Failed to read object", "/"+bucketName+"/"+objectKey)
				h.readChecker.RecordCheck(false)
				return
			}
			if !verifier.Valid() {
				h.log.Error("checksum mismatch on range read",
					"bucket", bucketName, "key", objectKey,
					"expected", obj.ChecksumSHA256,
					"actual", verifier.ActualChecksum(),
					"location", obj.LocationRef,
				)
				h.readChecker.RecordCheck(false)
				if err := h.db.QuarantineObject(bucket.ID, objectKey); err != nil {
					h.log.Error("quarantine object meta", "err", err, "bucket", bucketName, "key", objectKey)
				}
				if err := h.store.Quarantine(obj.LocationRef); err != nil {
					h.log.Error("quarantine object file", "err", err, "location", obj.LocationRef)
				}
				writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
					"Object integrity check failed", "/"+bucketName+"/"+objectKey)
				return
			}
			h.readChecker.RecordCheck(true)
			// Seek back to serve the range
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
					"Failed to seek", "/"+bucketName+"/"+objectKey)
				return
			}
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

	// Probabilistic checksum verification on read (skip for range requests)
	if h.readChecker.ShouldVerify() && obj.SizeBytes <= 64<<20 {
		var buf bytes.Buffer
		verifier := maintenance.NewReadVerifier(f, obj.ChecksumSHA256)
		if _, err := io.Copy(&buf, verifier); err != nil {
			h.log.Error("read verify", "err", err, "bucket", bucketName, "key", objectKey)
			writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
				"Failed to read object", "/"+bucketName+"/"+objectKey)
			h.readChecker.RecordCheck(false)
			return
		}
		if !verifier.Valid() {
			h.log.Error("checksum mismatch on read",
				"bucket", bucketName, "key", objectKey,
				"expected", obj.ChecksumSHA256,
				"actual", verifier.ActualChecksum(),
				"location", obj.LocationRef,
			)
			h.readChecker.RecordCheck(false)
			if err := h.db.QuarantineObject(bucket.ID, objectKey); err != nil {
				h.log.Error("quarantine object meta", "err", err, "bucket", bucketName, "key", objectKey)
			}
			if err := h.store.Quarantine(obj.LocationRef); err != nil {
				h.log.Error("quarantine object file", "err", err, "location", obj.LocationRef)
			}
			writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
				"Object integrity check failed", "/"+bucketName+"/"+objectKey)
			return
		}
		h.readChecker.RecordCheck(true)
		w.WriteHeader(http.StatusOK)
		if _, err := io.Copy(w, &buf); err != nil {
			h.log.Warn("send verified object", "err", err, "bucket", bucketName, "key", objectKey)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, f); err != nil {
		h.log.Warn("send object", "err", err, "bucket", bucketName, "key", objectKey)
	}
}

// handleHeadObject handles HEAD /<bucket>/<key>
func (h *Handler) handleHeadObject(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
	if h.metrics != nil {
		h.metrics.HeadObjectTotal.Add(1)
	}
	_, ok := h.requireAuth(r, w, meta.ActionObjectGet, bucketName, objectKey)
	if !ok {
		return
	}

	bucket, err := h.db.GetBucket(bucketName)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	obj, err := h.db.GetObjectMeta(bucket.ID, objectKey)
	if err != nil {
		if errors.Is(err, meta.ErrObjectNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
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

// handleDeleteObject handles DELETE /<bucket>/<key>
func (h *Handler) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
	_, ok := h.requireAuth(r, w, meta.ActionObjectDelete, bucketName, objectKey)
	if !ok {
		return
	}

	bucket, err := h.db.GetBucket(bucketName)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchBucket,
				"Bucket not found", "/"+bucketName)
			return
		}
		h.log.Error("get bucket", "err", err)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", fmt.Sprintf("/%s/%s", bucketName, objectKey))
		return
	}

	obj, err := h.db.DeleteObjectMeta(bucket.ID, objectKey)
	if err != nil {
		if errors.Is(err, meta.ErrObjectNotFound) {
			// S3 returns 204 even if the object doesn't exist
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.log.Error("delete object meta", "err", err)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", fmt.Sprintf("/%s/%s", bucketName, objectKey))
		return
	}

	// Delete physical file
	if err := h.store.DeleteObject(obj.LocationRef); err != nil {
		h.log.Warn("gc deleted object", "err", err, "location", obj.LocationRef)
	}

	if h.metrics != nil {
		h.metrics.DeleteObjectTotal.Add(1)
	}

	w.WriteHeader(http.StatusNoContent)
}


// parseRange parses a Range header value like "bytes=0-499" or "bytes=-500" or "bytes=500-".
// Returns start, end (inclusive), and whether the range is valid.
func parseRange(rangeHeader string, totalSize int64) (start, end int64, ok bool) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, 0, false
	}
	spec := strings.TrimPrefix(rangeHeader, "bytes=")
	// Only support single range
	if strings.Contains(spec, ",") {
		return 0, 0, false
	}

	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}

	if parts[0] == "" {
		// Suffix range: bytes=-500 means last 500 bytes
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
