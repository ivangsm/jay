package proto

import (
	"errors"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/meta"
)

var validBucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)

func (h *connHandler) handleCreateBucket(req *request) error {
	bucket, err := DecodeBucket(req.meta)
	if err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionBucketWriteMeta, bucket, ""); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	if !validBucketName.MatchString(bucket) ||
		strings.Contains(bucket, "..") ||
		strings.Contains(bucket, "--") ||
		net.ParseIP(bucket) != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid bucket name", "InvalidBucketName")
	}

	b := &meta.Bucket{
		ID:             uuid.New().String(),
		Name:           bucket,
		OwnerAccountID: h.token.AccountID,
		Visibility:     "private",
		Status:         "active",
	}

	if err := h.db.CreateBucket(b); err != nil {
		if errors.Is(err, meta.ErrBucketExists) {
			return h.writeError(StatusConflict, req.streamID, "bucket already exists", "BucketAlreadyExists")
		}
		h.log.Error("create bucket", "err", err)
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	if err := h.store.EnsureBucketDir(b.ID); err != nil {
		h.log.Error("ensure bucket dir", "err", err, "bucket", b.Name)
	}

	resp := EncodeBucketInfo(b.ID, b.Name, b.CreatedAt.Format(time.RFC3339), b.Visibility)
	return h.writeResponseCombined(StatusOK, req.streamID, resp)
}

func (h *connHandler) handleDeleteBucket(req *request) error {
	bucket, err := DecodeBucket(req.meta)
	if err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionBucketWriteMeta, bucket, ""); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bkt, err := h.db.GetBucket(bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	if err := h.db.DeleteBucket(bucket); err != nil {
		if errors.Is(err, meta.ErrBucketNotEmpty) {
			return h.writeError(StatusConflict, req.streamID, "bucket is not empty", "BucketNotEmpty")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	if err := h.store.RemoveBucketDir(bkt.ID); err != nil {
		h.log.Error("remove bucket dir", "err", err, "bucket", bucket)
	}
	return h.writeResponse(StatusOK, req.streamID, nil, nil, 0)
}

func (h *connHandler) handleHeadBucket(req *request) error {
	bucket, err := DecodeBucket(req.meta)
	if err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionBucketReadMeta, bucket, ""); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bkt, err := h.db.GetBucket(bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	resp := EncodeBucketInfo(bkt.ID, bkt.Name, bkt.CreatedAt.Format(time.RFC3339), bkt.Visibility)
	return h.writeResponseCombined(StatusOK, req.streamID, resp)
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

	names := make([]string, len(buckets))
	createdAts := make([]string, len(buckets))
	for i, b := range buckets {
		names[i] = b.Name
		createdAts[i] = b.CreatedAt.Format(time.RFC3339)
	}

	return h.writeResponseCombined(StatusOK, req.streamID, EncodeBucketList(names, createdAts))
}
