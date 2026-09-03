package api

import (
	"crypto/md5"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/internal/jsonx"
	"github.com/ivangsm/jay/internal/objops"
	"github.com/ivangsm/jay/meta"
)

// s3ErrInvalidPart is returned by CompleteMultipartUpload when a part listed by
// the client is unknown or its ETag does not match the stored one.
const s3ErrInvalidPart = "InvalidPart"

// normalizeETag strips the surrounding quotes (and any surrounding whitespace)
// clients wrap ETags in, so a client-supplied `"abc"` compares equal to the
// bare `abc` we store. Inverse of formatETag.
func normalizeETag(etag string) string {
	return strings.Trim(strings.TrimSpace(etag), `"`)
}

func (h *Handler) denyMultipartPolicy(w http.ResponseWriter, r *http.Request, bucket *meta.Bucket, action, objectKey string) bool {
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
		h.log.Warn("multipart: malformed bucket policy, failing closed", "bucket", bucket.Name, "err", err)
		if h.metrics != nil {
			h.metrics.AuthFailures.Add(1)
		}
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Access denied", r.URL.Path)
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
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Access denied", r.URL.Path)
		return true
	}
	return false
}

func (h *Handler) multipartUploadForRequest(w http.ResponseWriter, r *http.Request, bucketName, objectKey, uploadID string) (*meta.Bucket, *meta.MultipartUpload, bool) {
	upload, err := h.db.GetMultipartUpload(uploadID)
	if err != nil {
		if errors.Is(err, meta.ErrUploadNotFound) {
			writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "Upload not found", "/"+bucketName+"/"+objectKey)
			return nil, nil, false
		}
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Internal error", "/"+bucketName+"/"+objectKey)
		return nil, nil, false
	}

	bucket, err := h.db.GetBucketByID(upload.BucketID)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "Upload not found", "/"+bucketName+"/"+objectKey)
			return nil, nil, false
		}
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Internal error", "/"+bucketName+"/"+objectKey)
		return nil, nil, false
	}

	if bucket.Name != bucketName || upload.ObjectKey != objectKey {
		writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "Upload not found", "/"+bucketName+"/"+objectKey)
		return nil, nil, false
	}
	return bucket, upload, true
}

// handleCreateMultipartUpload handles POST /<bucket>/<key>?uploads
func (h *Handler) handleCreateMultipartUpload(w http.ResponseWriter, r *http.Request, bucketName, objectKey string) {
	_, ok := h.requireAuth(r, w, meta.ActionMultipartCreate, bucketName, objectKey)
	if !ok {
		return
	}

	bucket, err := h.db.GetBucket(bucketName)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchBucket, "Bucket not found", "/"+bucketName)
			return
		}
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Internal error", "/"+bucketName)
		return
	}
	if h.denyMultipartPolicy(w, r, bucket, meta.ActionMultipartCreate, objectKey) {
		return
	}

	// S3 lets the client name here the algorithm every part will carry. jay
	// does not need to remember it — each part is verified against the digest
	// it declares — but an algorithm jay cannot compute has to be refused now
	// rather than after the client has uploaded a gigabyte of parts. The AWS
	// CLI sends CRC64NVME on every multipart it starts.
	if declared := strings.TrimSpace(r.Header.Get(checksumAlgorithmHeader)); declared != "" {
		if _, ok := objops.ParseChecksumAlgorithm(declared); !ok {
			writeS3Error(w, r, http.StatusBadRequest, s3ErrInvalidRequest,
				"Invalid checksum declaration: unknown checksum algorithm "+declared,
				"/"+bucketName+"/"+objectKey)
			return
		}
	}

	uploadID := uuid.New().String()

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	token := tokenFromContext(r.Context())
	initiatedBy := ""
	if token != nil {
		initiatedBy = token.AccountID
	}

	upload := &meta.MultipartUpload{
		UploadID:    uploadID,
		BucketID:    bucket.ID,
		ObjectKey:   objectKey,
		ContentType: contentType,
		InitiatedBy: initiatedBy,
		CreatedAt:   time.Now().UTC(),
		State:       "initiated",
	}

	if err := h.db.CreateMultipartUpload(upload); err != nil {
		h.log.Error("create multipart upload", "err", err)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Internal error", "/"+bucketName+"/"+objectKey)
		return
	}

	writeXML(w, r, http.StatusOK, InitiateMultipartUploadResult{
		XMLNS:    s3Namespace,
		Bucket:   bucketName,
		Key:      objectKey,
		UploadID: uploadID,
	})
}

// handleUploadPart handles PUT /<bucket>/<key>?uploadId=X&partNumber=N
//
// A part carries its own client-declared checksum and is verified exactly like
// a whole object: a part accepted with a digest nobody checked corrupts the
// assembled object just as thoroughly, and by then the client has an ETag and a
// 200 for every part it sent. The AWS CLI declares a CRC64NVME on every part.
func (h *Handler) handleUploadPart(w http.ResponseWriter, r *http.Request, bucketName, objectKey, uploadID string) {
	token, ok := h.requireAuth(r, w, meta.ActionMultipartUpload, bucketName, objectKey)
	if !ok {
		return
	}

	resource := "/" + bucketName + "/" + objectKey
	verifier, ok := h.checksumVerifierFor(w, r, resource)
	if !ok {
		return
	}

	partNumberStr := r.URL.Query().Get("partNumber")
	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument, "Invalid part number", "/"+bucketName+"/"+objectKey)
		return
	}

	bucket, upload, ok := h.multipartUploadForRequest(w, r, bucketName, objectKey, uploadID)
	if !ok {
		return
	}
	if h.denyMultipartPolicy(w, r, bucket, meta.ActionMultipartUpload, objectKey) {
		return
	}

	if token == nil || upload.InitiatedBy != token.AccountID {
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Access denied", "/"+bucketName+"/"+objectKey)
		return
	}

	if upload.State != "initiated" {
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument, "Upload is not active", "/"+bucketName+"/"+objectKey)
		return
	}

	// Write part to disk. The same ceiling that guards PutObject applies per
	// part — otherwise multipart would be a trivial bypass of the size limit.
	// Read at most max+1 bytes so we can tell "at the limit" from "over it".
	var src io.Reader = r.Body
	maxSize := h.objops.MaxObjectSize()
	if maxSize > 0 {
		src = io.LimitReader(r.Body, maxSize+1)
	}

	md5Hash := md5.New()
	body := verifier.Wrap(io.TeeReader(src, md5Hash))

	// Both refusals — over the ceiling, or a digest that does not describe the
	// bytes — run between the fsync and the rename, so a rejected part never
	// takes the place of the part it is retrying. See store.WriteVerifier.
	var seenSize int64
	verify := func(sha256Hex string, size int64) error {
		seenSize = size
		if maxSize > 0 && size > maxSize {
			return objops.ErrObjectTooLarge
		}
		return verifier.Verify(sha256Hex, hex.EncodeToString(md5Hash.Sum(nil)))
	}

	checksum, size, locationRef, err := h.store.WritePartVerified(uploadID, partNumber, body, verify)
	if err != nil {
		switch {
		case errors.Is(err, objops.ErrObjectTooLarge):
			h.log.Warn("upload part exceeds max size",
				"upload", uploadID, "part", partNumber, "size", seenSize, "max", maxSize)
			writeS3Error(w, r, http.StatusBadRequest, s3ErrEntityTooLarge,
				"Your proposed upload exceeds the maximum allowed object size", resource)
		case errors.Is(err, objops.ErrBadDigest):
			h.log.Warn("upload part checksum mismatch, nothing written",
				"err", err, "upload", uploadID, "part", partNumber)
			h.writeChecksumError(w, r, err, resource)
		default:
			h.log.Error("write part", "err", err, "upload", uploadID, "part", partNumber)
			writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Failed to write part", resource)
		}
		return
	}

	etag := hex.EncodeToString(md5Hash.Sum(nil))

	part := meta.MultipartPart{
		PartNumber:     partNumber,
		Size:           size,
		ETag:           etag,
		ChecksumSHA256: checksum,
		LocationRef:    locationRef,
		CreatedAt:      time.Now().UTC(),
	}

	if err := h.db.AddMultipartPart(uploadID, part); err != nil {
		h.store.Cleanup(locationRef)
		h.log.Error("add part meta", "err", err, "upload", uploadID, "part", partNumber)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Failed to register part", "/"+bucketName+"/"+objectKey)
		return
	}

	w.Header().Set("ETag", formatETag(etag))
	setDeclaredChecksumHeader(w, verifier)
	w.WriteHeader(http.StatusOK)
}

// handleCompleteMultipartUpload handles POST /<bucket>/<key>?uploadId=X
func (h *Handler) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request, bucketName, objectKey, uploadID string) {
	token, ok := h.requireAuth(r, w, meta.ActionMultipartComplete, bucketName, objectKey)
	if !ok {
		return
	}

	// multipartUploadForRequest already loaded the upload record — reuse it
	// instead of issuing a second GetMultipartUpload for the ownership check.
	bucket, existing, ok := h.multipartUploadForRequest(w, r, bucketName, objectKey, uploadID)
	if !ok {
		return
	}
	if h.denyMultipartPolicy(w, r, bucket, meta.ActionMultipartComplete, objectKey) {
		return
	}
	if token == nil || existing.InitiatedBy != token.AccountID {
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Access denied", "/"+bucketName+"/"+objectKey)
		return
	}

	// A checksum declared here describes the ASSEMBLED object, and S3 computes
	// it by composing the part digests rather than by hashing the result. jay
	// does not implement that composition, and accepting the header would mean
	// answering 200 to a verification that never happened — the exact defect
	// PND-0189 removed from PutObject. 501, the same answer every other
	// unimplemented S3 feature gets here. No measured client sends it: the AWS
	// CLI's CompleteMultipartUpload carries part numbers and ETags only.
	for _, candidate := range checksumValueHeaders {
		if strings.TrimSpace(r.Header.Get(candidate.header)) == "" {
			continue
		}
		writeS3Error(w, r, http.StatusNotImplemented, S3ErrNotImplemented,
			"Whole-object checksum verification on CompleteMultipartUpload is not implemented; "+
				"jay verifies each part instead", "/"+bucketName+"/"+objectKey)
		return
	}

	// Parse request body
	var input CompleteMultipartUploadInput
	if err := xml.NewDecoder(r.Body).Decode(&input); err != nil {
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument, "Invalid request body", "/"+bucketName+"/"+objectKey)
		return
	}

	// S3 validates that the ETag the client reports for each part matches the
	// one the server stored, and answers InvalidPart on mismatch. An empty
	// client ETag is tolerated (some minimal clients omit it).
	storedETags := make(map[int]string, len(existing.Parts))
	for _, p := range existing.Parts {
		storedETags[p.PartNumber] = p.ETag
	}

	partNumbers := make([]int, len(input.Parts))
	for i, p := range input.Parts {
		partNumbers[i] = p.PartNumber
		if normalizeETag(p.ETag) == "" {
			continue
		}
		stored, found := storedETags[p.PartNumber]
		if !found || !strings.EqualFold(normalizeETag(p.ETag), stored) {
			writeS3Error(w, r, http.StatusBadRequest, s3ErrInvalidPart,
				"One or more of the specified parts could not be found or the ETag did not match",
				"/"+bucketName+"/"+objectKey)
			return
		}
	}

	upload, err := h.db.CompleteMultipartUpload(uploadID, partNumbers)
	if err != nil {
		if errors.Is(err, meta.ErrUploadNotFound) {
			writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "Upload not found", "/"+bucketName+"/"+objectKey)
			return
		}
		h.log.Error("complete multipart", "err", err, "upload", uploadID)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Failed to complete upload", "/"+bucketName+"/"+objectKey)
		return
	}

	// Assemble parts into final object
	objectID := uuid.New().String()
	var partLocations []string
	for _, p := range upload.Parts {
		partLocations = append(partLocations, p.LocationRef)
	}

	checksum, size, locationRef, err := h.store.AssembleParts(bucket.ID, objectID, partLocations)
	if err != nil {
		h.log.Error("assemble parts", "err", err, "upload", uploadID)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Failed to assemble object", "/"+bucketName+"/"+objectKey)
		return
	}

	// Compute multipart ETag: md5 of concatenated part md5s + "-N"
	etag := computeMultipartETag(upload.Parts)

	obj := &meta.Object{
		BucketID:       bucket.ID,
		Key:            objectKey,
		ObjectID:       objectID,
		State:          "active",
		SizeBytes:      size,
		ContentType:    upload.ContentType,
		ETag:           etag,
		ChecksumSHA256: checksum,
		LocationRef:    locationRef,
		CreatedAt:      time.Now().UTC(),
	}

	prev, err := h.db.PutObjectMeta(obj)
	if err != nil {
		h.store.Cleanup(locationRef)
		h.log.Error("put object meta", "err", err, "upload", uploadID)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Failed to store metadata", "/"+bucketName+"/"+objectKey)
		return
	}

	if prev != nil && prev.LocationRef != locationRef {
		if err := h.store.DeleteObject(prev.LocationRef); err != nil {
			h.log.Warn("delete previous object version", "err", err, "location", prev.LocationRef)
		}
	}

	if err := h.db.MarkMultipartUploadCompleted(uploadID); err != nil {
		// The object is already durably committed at this point (PutObjectMeta
		// succeeded). If the upload record is no longer active — because a
		// concurrent Complete for the same uploadID won the race, or a retry
		// arrived after the record was deleted — failing with a 500 would be a
		// lie: the client's object IS in place. Complete is therefore treated
		// as idempotent from here on; we log and return the success response.
		// Any other error (bbolt failure) is still a real 500.
		if errors.Is(err, meta.ErrUploadNotActive) || errors.Is(err, meta.ErrUploadNotFound) {
			h.log.Warn("multipart upload already finalized by a concurrent complete; object committed, responding success",
				"err", err, "upload_id", uploadID, "bucket", bucketName, "key", objectKey)
		} else {
			h.log.Error("mark multipart completed", "err", err, "upload_id", uploadID)
			writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Failed to finalize upload", "/"+bucketName+"/"+objectKey)
			return
		}
	}

	// Cleanup parts (best-effort)
	if err := h.store.CleanupUploadParts(uploadID); err != nil {
		h.log.Warn("cleanup upload parts", "err", err, "upload_id", uploadID)
	}
	if err := h.db.DeleteMultipartUpload(uploadID); err != nil {
		h.log.Warn("delete multipart upload record", "err", err, "upload_id", uploadID)
	}

	writeXML(w, r, http.StatusOK, CompleteMultipartUploadResult{
		XMLNS:    s3Namespace,
		Location: fmt.Sprintf("/%s/%s", bucketName, objectKey),
		Bucket:   bucketName,
		Key:      objectKey,
		ETag:     formatETag(etag),
	})
}

// handleAbortMultipartUpload handles DELETE /<bucket>/<key>?uploadId=X
func (h *Handler) handleAbortMultipartUpload(w http.ResponseWriter, r *http.Request, bucketName, objectKey, uploadID string) {
	token, ok := h.requireAuth(r, w, meta.ActionMultipartAbort, bucketName, objectKey)
	if !ok {
		return
	}

	bucket, existing, ok := h.multipartUploadForRequest(w, r, bucketName, objectKey, uploadID)
	if !ok {
		return
	}
	if h.denyMultipartPolicy(w, r, bucket, meta.ActionMultipartAbort, objectKey) {
		return
	}
	if token == nil || existing.InitiatedBy != token.AccountID {
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Access denied", "/"+bucketName+"/"+objectKey)
		return
	}

	upload, err := h.db.AbortMultipartUpload(uploadID)
	if err != nil {
		// ErrUploadNotActive means the upload was already completed (or already
		// aborted): there is no active upload left to abort, and its parts must
		// not be touched — the completed object may still reference them mid
		// cleanup. S3 answers NoSuchUpload in that situation.
		if errors.Is(err, meta.ErrUploadNotFound) || errors.Is(err, meta.ErrUploadNotActive) {
			writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "Upload not found", "/"+bucketName+"/"+objectKey)
			return
		}
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Internal error", "/"+bucketName+"/"+objectKey)
		return
	}

	// Cleanup part files (best-effort)
	if err := h.store.CleanupUploadParts(upload.UploadID); err != nil {
		h.log.Warn("cleanup upload parts", "err", err, "upload_id", upload.UploadID)
	}
	if err := h.db.DeleteMultipartUpload(uploadID); err != nil {
		h.log.Warn("delete multipart upload record", "err", err, "upload_id", uploadID)
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleListParts handles GET /<bucket>/<key>?uploadId=X
func (h *Handler) handleListParts(w http.ResponseWriter, r *http.Request, bucketName, objectKey, uploadID string) {
	token, ok := h.requireAuth(r, w, meta.ActionMultipartUpload, bucketName, objectKey)
	if !ok {
		return
	}

	bucket, upload, ok := h.multipartUploadForRequest(w, r, bucketName, objectKey, uploadID)
	if !ok {
		return
	}
	if h.denyMultipartPolicy(w, r, bucket, meta.ActionMultipartUpload, objectKey) {
		return
	}
	if token == nil || upload.InitiatedBy != token.AccountID {
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Access denied", "/"+bucketName+"/"+objectKey)
		return
	}

	result := ListPartsResult{
		XMLNS:    s3Namespace,
		Bucket:   bucketName,
		Key:      objectKey,
		UploadID: uploadID,
	}

	for _, p := range upload.Parts {
		result.Parts = append(result.Parts, S3Part{
			PartNumber:   p.PartNumber,
			LastModified: formatS3Time(upload.CreatedAt),
			ETag:         formatETag(p.ETag),
			Size:         p.Size,
		})
	}

	writeXML(w, r, http.StatusOK, result)
}

func computeMultipartETag(parts []meta.MultipartPart) string {
	h := md5.New()
	for _, p := range parts {
		partMD5, _ := hex.DecodeString(p.ETag)
		h.Write(partMD5)
	}
	return fmt.Sprintf("%s-%d", hex.EncodeToString(h.Sum(nil)), len(parts))
}
