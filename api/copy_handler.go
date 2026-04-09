package api

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/meta"
)

// handleCopyObject handles PUT /<bucket>/<key> with x-amz-copy-source header
func (h *Handler) handleCopyObject(w http.ResponseWriter, r *http.Request, dstBucket, dstKey string) {
	_, ok := h.requireAuth(r, w, meta.ActionObjectPut, dstBucket, dstKey)
	if !ok {
		return
	}

	// Parse source: /bucket/key or bucket/key
	copySource := r.Header.Get("x-amz-copy-source")
	copySource = strings.TrimPrefix(copySource, "/")
	srcBucket, srcKey, found := strings.Cut(copySource, "/")
	if !found || srcKey == "" {
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument,
			"Invalid x-amz-copy-source", "/"+dstBucket+"/"+dstKey)
		return
	}

	// URL-decode source bucket and key
	srcBucket, err := url.PathUnescape(srcBucket)
	if err != nil {
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument,
			"Invalid copy source", copySource)
		return
	}
	srcKey, err = url.PathUnescape(srcKey)
	if err != nil {
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument,
			"Invalid copy source", copySource)
		return
	}

	// Auth on source
	_, ok = h.requireAuth(r, w, meta.ActionObjectGet, srcBucket, srcKey)
	if !ok {
		return
	}

	// Get source bucket and object
	srcBucketMeta, err := h.db.GetBucket(srcBucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchBucket,
				"Source bucket not found", copySource)
			return
		}
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Internal error", copySource)
		return
	}

	srcObj, err := h.db.GetObjectMeta(srcBucketMeta.ID, srcKey)
	if err != nil {
		if errors.Is(err, meta.ErrObjectNotFound) {
			writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchKey,
				"Source object not found", copySource)
			return
		}
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Internal error", copySource)
		return
	}

	// Get destination bucket
	dstBucketMeta, err := h.db.GetBucket(dstBucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchBucket,
				"Destination bucket not found", "/"+dstBucket)
			return
		}
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Internal error", "/"+dstBucket)
		return
	}

	// Open source file and copy to new object
	srcFile, err := h.store.ReadObject(srcObj.LocationRef)
	if err != nil {
		h.log.Error("copy: read source", "err", err)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Failed to read source", copySource)
		return
	}
	defer func() { _ = srcFile.Close() }()

	newObjectID := uuid.New().String()
	checksum, size, locationRef, err := h.store.WriteObject(dstBucketMeta.ID, newObjectID, srcFile)
	if err != nil {
		h.log.Error("copy: write dest", "err", err)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Failed to write copy", "/"+dstBucket+"/"+dstKey)
		return
	}

	now := time.Now().UTC()
	newObj := &meta.Object{
		BucketID:        dstBucketMeta.ID,
		Key:             dstKey,
		ObjectID:        newObjectID,
		State:           "active",
		SizeBytes:       size,
		ContentType:     srcObj.ContentType,
		ETag:            srcObj.ETag,
		ChecksumSHA256:  checksum,
		LocationRef:     locationRef,
		CreatedAt:       now,
		MetadataHeaders: srcObj.MetadataHeaders,
	}

	prev, err := h.db.PutObjectMeta(newObj)
	if err != nil {
		if delErr := h.store.DeleteObject(locationRef); delErr != nil {
			h.log.Error("copy: rollback delete after meta failure", "err", delErr, "location", locationRef)
		}
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Failed to store metadata", "/"+dstBucket+"/"+dstKey)
		return
	}

	if prev != nil && prev.LocationRef != locationRef {
		if err := h.store.DeleteObject(prev.LocationRef); err != nil {
			h.log.Error("copy: delete previous version", "err", err, "location", prev.LocationRef)
		}
	}

	writeXML(w, r, http.StatusOK, CopyObjectResult{
		XMLNS:        s3Namespace,
		LastModified: formatS3Time(now),
		ETag:         formatETag(newObj.ETag),
	})
}

// Ensure io package is used
var _ = io.EOF
