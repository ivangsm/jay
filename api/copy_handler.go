package api

import (
	jsonv2 "encoding/json/v2"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"uuid"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/internal/jsonx"
	"github.com/ivangsm/jay/internal/objops"
	"github.com/ivangsm/jay/meta"
)

// denyCopyPolicy evaluates the bucket-policy deny overlay for one side of a
// copy (source or destination). requireAuth only checks the token scope; bucket
// policies are an additional deny layer that PUT/GET/DELETE get through
// objops.Service.authorize. Copy talks to the store directly, so it has to
// evaluate the overlay itself or a token denied object:get on the source bucket
// could still exfiltrate objects into a bucket it controls.
//
// A policy that fails to unmarshal is fail-closed (deny), matching objops.
// Returns true when the request was denied and a response has been written.
func (h *Handler) denyCopyPolicy(w http.ResponseWriter, r *http.Request, bucket *meta.Bucket, action, objectKey, resource string) bool {
	if len(bucket.PolicyJSON) == 0 {
		return false
	}

	// Lenient rather than v2's defaults: bucket policies are written by hand,
	// and v1 matched field names case-insensitively. Under v2's case-sensitive
	// defaults an AWS-style policy ("Effect"/"Statements") would stop parsing
	// and its Deny statement would vanish silently — opening access where it
	// used to be refused. Lenient preserves v1's matching.
	var policy auth.BucketPolicy
	if err := jsonv2.Unmarshal(bucket.PolicyJSON, &policy, jsonx.Lenient); err != nil {
		h.log.Warn("copy: malformed bucket policy, failing closed", "bucket", bucket.Name, "err", err)
		if h.metrics != nil {
			h.metrics.AuthFailures.Add(1)
		}
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Access denied", resource)
		return true
	}
	policy.Compile()

	tokenID := ""
	if tok := tokenFromContext(r.Context()); tok != nil {
		tokenID = tok.TokenID
	}
	if auth.EvaluatePolicyDeny(&policy, tokenID, action, objectKey, clientIP(r, h.trustProxyHeaders)) {
		if h.metrics != nil {
			h.metrics.AuthFailures.Add(1)
		}
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Access denied", resource)
		return true
	}
	return false
}

// handleCopyObject handles PUT /<bucket>/<key> with x-amz-copy-source header
func (h *Handler) handleCopyObject(w http.ResponseWriter, r *http.Request, dstBucket, dstKey string) {
	_, ok := h.requireAuth(r, w, meta.ActionObjectPut, dstBucket, dstKey)
	if !ok {
		return
	}

	// What the client asked for is read before anything is copied: an algorithm
	// jay cannot compute has to be refused with nothing written, the same rule
	// PutObject follows. The AWS CLI only sends the header when someone passes
	// --checksum-algorithm, so this whole branch is dormant on the default path.
	checksumReq, cerr := copyChecksumRequest(r)
	if cerr != nil {
		h.writeChecksumError(w, r, cerr, "/"+dstBucket+"/"+dstKey)
		return
	}
	digester, cerr := objops.NewChecksumVerifier(checksumReq)
	if cerr != nil {
		h.writeChecksumError(w, r, cerr, "/"+dstBucket+"/"+dstKey)
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

	// Bucket-policy deny overlay on the source (read side).
	if h.denyCopyPolicy(w, r, srcBucketMeta, meta.ActionObjectGet, srcKey, "/"+copySource) {
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

	// Bucket-policy deny overlay on the destination (write side).
	if h.denyCopyPolicy(w, r, dstBucketMeta, meta.ActionObjectPut, dstKey, "/"+dstBucket+"/"+dstKey) {
		return
	}

	// Open source file and copy to new object
	srcFile, err := h.store.ReadObject(srcObj.LocationRef)
	if err != nil {
		// Metadata without a backing file (GC race, manual removal): report the
		// object as missing rather than as an internal error.
		if errors.Is(err, os.ErrNotExist) {
			h.log.Warn("copy: source file missing for existing metadata",
				"bucket", srcBucket, "key", srcKey, "location", srcObj.LocationRef)
			writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchKey,
				"Source object not found", copySource)
			return
		}
		h.log.Error("copy: read source", "err", err)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Failed to read source", copySource)
		return
	}
	defer func() { _ = srcFile.Close() }()

	newObjectID := uuid.New().String()
	// digester.Wrap is a no-op unless an algorithm was named, and when one was
	// it hashes in the SAME pass that writes the bytes: nothing is buffered and
	// nothing is read twice.
	checksum, size, locationRef, err := h.store.WriteObject(dstBucketMeta.ID, newObjectID, digester.Wrap(srcFile))
	if err != nil {
		h.log.Error("copy: write dest", "err", err)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Failed to write copy", "/"+dstBucket+"/"+dstKey)
		return
	}

	// The requested digest has to exist before the copy is committed. Answering
	// 200 without it is the defect PND-0194 names; answering 500 after the
	// metadata is in bbolt would report a failure for a copy that landed. Here
	// nothing is committed yet, so the rollback is one file removal.
	checksumValue, err := copyChecksumValue(digester, checksumReq.Algorithm, checksum)
	if err != nil {
		h.log.Error("copy: cannot produce the requested checksum",
			"err", err, "algorithm", string(checksumReq.Algorithm))
		if delErr := h.store.DeleteObject(locationRef); delErr != nil {
			h.log.Error("copy: rollback delete after checksum failure", "err", delErr, "location", locationRef)
		}
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Failed to compute the requested checksum", "/"+dstBucket+"/"+dstKey)
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

	result := CopyObjectResult{
		XMLNS:        s3Namespace,
		LastModified: formatS3Time(now),
		ETag:         formatETag(newObj.ETag),
	}
	if checksumValue != "" {
		// The copy is already committed, so this cannot refuse the request any
		// more. It can only fail if an algorithm exists that CopyObjectResult
		// has no element for, which the closed set in objops rules out — the
		// error is logged rather than swallowed so that day is not silent.
		if err := result.SetChecksum(checksumReq.Algorithm, checksumValue); err != nil {
			h.log.Error("copy: checksum has no response element", "err", err)
		}
	}
	writeXML(w, r, http.StatusOK, result)
}
