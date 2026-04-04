package proto

import (
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/meta"
)

var validBucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)

type bucketRequest struct {
	Bucket string `json:"bucket"`
}

type bucketInfoResponse struct {
	BucketID   string `json:"bucket_id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	Visibility string `json:"visibility"`
}

func (h *connHandler) handleCreateBucket(req *request) error {
	var params bucketRequest
	if err := json.Unmarshal(req.meta, &params); err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionBucketWriteMeta, params.Bucket, ""); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	if !validBucketName.MatchString(params.Bucket) {
		return h.writeError(StatusBadRequest, req.streamID, "invalid bucket name", "InvalidBucketName")
	}

	bucket := &meta.Bucket{
		ID:             uuid.New().String(),
		Name:           params.Bucket,
		OwnerAccountID: h.token.AccountID,
		Visibility:     "private",
		Status:         "active",
	}

	if err := h.db.CreateBucket(bucket); err != nil {
		if errors.Is(err, meta.ErrBucketExists) {
			return h.writeError(StatusConflict, req.streamID, "bucket already exists", "BucketAlreadyExists")
		}
		h.log.Error("create bucket", "err", err)
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	h.store.EnsureBucketDir(bucket.ID)

	resp, _ := json.Marshal(bucketInfoResponse{
		BucketID:   bucket.ID,
		Name:       bucket.Name,
		CreatedAt:  bucket.CreatedAt.Format(time.RFC3339),
		Visibility: bucket.Visibility,
	})
	return h.writeResponse(StatusOK, req.streamID, resp, nil, 0)
}

func (h *connHandler) handleDeleteBucket(req *request) error {
	var params bucketRequest
	if err := json.Unmarshal(req.meta, &params); err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionBucketWriteMeta, params.Bucket, ""); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bucket, err := h.db.GetBucket(params.Bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	if err := h.db.DeleteBucket(params.Bucket); err != nil {
		if errors.Is(err, meta.ErrBucketNotEmpty) {
			return h.writeError(StatusConflict, req.streamID, "bucket is not empty", "BucketNotEmpty")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	h.store.RemoveBucketDir(bucket.ID)
	return h.writeResponse(StatusOK, req.streamID, nil, nil, 0)
}

func (h *connHandler) handleHeadBucket(req *request) error {
	var params bucketRequest
	if err := json.Unmarshal(req.meta, &params); err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionBucketReadMeta, params.Bucket, ""); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bucket, err := h.db.GetBucket(params.Bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	resp, _ := json.Marshal(bucketInfoResponse{
		BucketID:   bucket.ID,
		Name:       bucket.Name,
		CreatedAt:  bucket.CreatedAt.Format(time.RFC3339),
		Visibility: bucket.Visibility,
	})
	return h.writeResponse(StatusOK, req.streamID, resp, nil, 0)
}

func (h *connHandler) handleListBuckets(req *request) error {
	if err := h.auth.Authorize(h.token, meta.ActionBucketList, "", ""); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	buckets, err := h.db.ListBuckets(h.token.AccountID)
	if err != nil {
		h.log.Error("list buckets", "err", err)
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	type entry struct {
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}
	type listResp struct {
		Buckets []entry `json:"buckets"`
	}

	result := listResp{}
	for _, b := range buckets {
		result.Buckets = append(result.Buckets, entry{
			Name:      b.Name,
			CreatedAt: b.CreatedAt.Format(time.RFC3339),
		})
	}

	resp, _ := json.Marshal(result)
	return h.writeResponse(StatusOK, req.streamID, resp, nil, 0)
}
