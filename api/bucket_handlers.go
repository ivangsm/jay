// Package api implements jay's S3-compatible HTTP surface: objects, buckets,
// multipart uploads, presigned URLs and SigV4 authentication.
//
// Compatibility is the point — the AWS CLI and SDKs have to work unmodified — so
// the XML shapes and error codes here follow S3's, not jay's preferences.
package api

import (
	"errors"
	"io"
	"net/http"
	"uuid"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/meta"
)

// handleCreateBucket handles PUT /<bucket>
func (h *Handler) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucketName string) {
	// Drain request body — AWS CLI sends LocationConstraint XML
	_, _ = io.Copy(io.Discard, r.Body)

	token, ok := h.requireAuth(r, w, meta.ActionBucketWriteMeta, bucketName, "")
	if !ok {
		return
	}

	if !meta.ValidBucketName(bucketName) {
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidBucketName,
			"Bucket name is invalid", "/"+bucketName)
		return
	}

	accountID := ""
	if token != nil {
		accountID = token.AccountID
	}

	bucket := &meta.Bucket{
		ID:             uuid.New().String(),
		Name:           bucketName,
		OwnerAccountID: accountID,
		Visibility:     "private",
		Status:         "active",
	}

	if err := h.db.CreateBucket(bucket); err != nil {
		if errors.Is(err, meta.ErrBucketExists) {
			writeS3Error(w, r, http.StatusConflict, S3ErrBucketAlreadyExists,
				"Bucket already exists", "/"+bucketName)
			return
		}
		h.log.Error("create bucket", "err", err, "bucket", bucketName)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", "/"+bucketName)
		return
	}

	// Create the physical directory
	if err := h.store.EnsureBucketDir(bucket.ID); err != nil {
		h.log.Error("create bucket dir", "err", err, "bucket", bucketName)
		// Best effort: metadata is already committed
	}

	if h.metrics != nil {
		h.metrics.CreateBucketTotal.Add(1)
	}

	w.Header().Set("Location", "/"+bucketName)
	w.WriteHeader(http.StatusOK)
}

// handleDeleteBucket handles DELETE /<bucket>
func (h *Handler) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucketName string) {
	token, ok := h.requireAuth(r, w, meta.ActionBucketWriteMeta, bucketName, "")
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
			"Internal error", "/"+bucketName)
		return
	}

	// Tenant isolation: "bucket:write-meta" says *what* the token may do, not
	// *whose* buckets it may do it to. Deleting an existing bucket owned by
	// another account requires ownership (or explicit BucketScope delegation,
	// or a bucket policy that says so). requireAuth already applied this gate;
	// repeating it on the bucket in hand is what keeps destroying a stranger's
	// bucket from depending on a caller further up remembering to ask.
	if !h.authorizeLoadedBucket(r, w, token, bucket, meta.ActionBucketWriteMeta, "") {
		return
	}

	if err := h.db.DeleteBucket(bucketName); err != nil {
		if errors.Is(err, meta.ErrBucketNotEmpty) {
			writeS3Error(w, r, http.StatusConflict, S3ErrBucketNotEmpty,
				"Bucket is not empty", "/"+bucketName)
			return
		}
		h.log.Error("delete bucket", "err", err)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", "/"+bucketName)
		return
	}

	// Clean up physical directory (best-effort; metadata is already deleted)
	if err := h.store.RemoveBucketDir(bucket.ID); err != nil {
		h.log.Error("remove bucket dir", "err", err, "bucket", bucketName)
	}

	if h.metrics != nil {
		h.metrics.DeleteBucketTotal.Add(1)
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleHeadBucket handles HEAD /<bucket>
func (h *Handler) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucketName string) {
	token, ok := h.requireAuth(r, w, meta.ActionBucketReadMeta, bucketName, "")
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

	// Reading another account's bucket metadata is still cross-tenant access.
	// HEAD carries no XML body, so the gate is applied by hand here to answer
	// with a bare 403.
	if err := auth.AuthorizeBucketAccess(token, bucket, meta.ActionBucketReadMeta, "", clientIP(r, h.trustProxyHeaders)); err != nil {
		if h.metrics != nil {
			h.metrics.AuthFailures.Add(1)
		}
		w.WriteHeader(http.StatusForbidden)
		return
	}

	w.Header().Set("x-amz-bucket-region", "us-east-1")
	w.WriteHeader(http.StatusOK)
}

// handleListBuckets handles GET /
func (h *Handler) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	token, ok := h.requireAuth(r, w, meta.ActionBucketList, "", "")
	if !ok {
		return
	}

	accountID := ""
	if token != nil {
		accountID = token.AccountID
	}

	buckets, err := h.db.ListBuckets(accountID)
	if err != nil {
		h.log.Error("list buckets", "err", err)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", "/")
		return
	}

	result := ListAllMyBucketsResult{
		XMLNS: s3Namespace,
		Owner: S3Owner{ID: accountID, DisplayName: accountID},
	}
	for _, b := range buckets {
		result.Buckets.Bucket = append(result.Buckets.Bucket, S3BucketEntry{
			Name:         b.Name,
			CreationDate: formatS3Time(b.CreatedAt),
		})
	}

	writeXML(w, r, http.StatusOK, result)
}

// handleGetBucketLocation handles GET /<bucket>?location.
//
// jay has no regions, so the answer is always the empty <LocationConstraint/>,
// which is how S3 itself spells us-east-1. SDKs call this before their first
// real operation to decide where to send it; a 501 there stops the client
// before it ever tries.
//
// Authorization mirrors HeadBucket: the location of a bucket is bucket
// metadata, and confirming it exists to another account's token is the same
// cross-tenant disclosure.
func (h *Handler) handleGetBucketLocation(w http.ResponseWriter, r *http.Request, bucketName string) {
	token, ok := h.requireAuth(r, w, meta.ActionBucketReadMeta, bucketName, "")
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
		h.log.Error("get bucket location", "err", err, "bucket", bucketName)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", "/"+bucketName)
		return
	}

	if !h.authorizeLoadedBucket(r, w, token, bucket, meta.ActionBucketReadMeta, "") {
		return
	}

	writeXML(w, r, http.StatusOK, LocationConstraint{XMLNS: s3Namespace})
}
