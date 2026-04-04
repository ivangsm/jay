package api

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/ivangsm/jay/meta"
	"github.com/google/uuid"
)

var validBucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)

// handleCreateBucket handles PUT /<bucket>
func (h *Handler) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucketName string) {
	token, ok := h.requireAuth(r, w, meta.ActionBucketWriteMeta, bucketName, "")
	if !ok {
		return
	}

	if !validBucketName.MatchString(bucketName) {
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

	w.Header().Set("Location", "/"+bucketName)
	w.WriteHeader(http.StatusOK)
}

// handleDeleteBucket handles DELETE /<bucket>
func (h *Handler) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucketName string) {
	_, ok := h.requireAuth(r, w, meta.ActionBucketWriteMeta, bucketName, "")
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

	// Clean up physical directory
	h.store.RemoveBucketDir(bucket.ID)

	w.WriteHeader(http.StatusNoContent)
}

// handleHeadBucket handles HEAD /<bucket>
func (h *Handler) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucketName string) {
	_, ok := h.requireAuth(r, w, meta.ActionBucketReadMeta, bucketName, "")
	if !ok {
		return
	}

	_, err := h.db.GetBucket(bucketName)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
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
