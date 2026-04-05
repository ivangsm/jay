package proto

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/meta"
)

func (h *connHandler) handlePutObject(req *request) error {
	bucket, key, contentType, metadata, err := DecodePutObjectRequest(req.meta)
	if err != nil {
		if derr := drainData(req); derr != nil {
			return derr
		}
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionObjectPut, bucket, key); err != nil {
		if derr := drainData(req); derr != nil {
			return derr
		}
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bkt, err := h.db.GetBucket(bucket)
	if err != nil {
		if derr := drainData(req); derr != nil {
			return derr
		}
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	objectID := uuid.New().String()

	md5Hash := md5.New()
	var body io.Reader
	if req.data != nil {
		body = io.TeeReader(req.data, md5Hash)
	} else {
		body = &emptyReader{}
	}

	checksum, size, locationRef, err := h.store.WriteObject(bkt.ID, objectID, body)
	if err != nil {
		h.log.Error("write object", "err", err, "bucket", bucket, "key", key)
		return h.writeError(StatusInternal, req.streamID, "failed to store object", "InternalError")
	}

	etag := hex.EncodeToString(md5Hash.Sum(nil))

	if contentType == "" {
		contentType = "application/octet-stream"
	}

	now := time.Now().UTC()
	obj := &meta.Object{
		BucketID:        bkt.ID,
		Key:             key,
		ObjectID:        objectID,
		State:           "active",
		SizeBytes:       size,
		ContentType:     contentType,
		ETag:            etag,
		ChecksumSHA256:  checksum,
		LocationRef:     locationRef,
		CreatedAt:       now,
		MetadataHeaders: metadata,
	}

	prev, err := h.db.PutObjectMeta(obj)
	if err != nil {
		h.store.Cleanup(locationRef)
		h.log.Error("put object meta", "err", err)
		return h.writeError(StatusInternal, req.streamID, "failed to store metadata", "InternalError")
	}

	if prev != nil && prev.LocationRef != locationRef {
		h.store.DeleteObject(prev.LocationRef)
	}

	return h.writeResponseCombined(StatusOK, req.streamID, EncodePutResponse(etag, checksum))
}

func (h *connHandler) handleGetObject(req *request) error {
	bucket, key, err := DecodeBucketKey(req.meta)
	if err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionObjectGet, bucket, key); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bkt, err := h.db.GetBucket(bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	obj, err := h.db.GetObjectMeta(bkt.ID, key)
	if err != nil {
		if errors.Is(err, meta.ErrObjectNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "object not found", "NoSuchKey")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	f, err := h.store.ReadObject(obj.LocationRef)
	if err != nil {
		h.log.Error("read object", "err", err, "location", obj.LocationRef)
		return h.writeError(StatusInternal, req.streamID, "failed to read object", "InternalError")
	}
	defer f.Close()

	resp := EncodeObjectInfo(
		obj.ContentType, obj.SizeBytes,
		obj.ETag, obj.ChecksumSHA256,
		obj.UpdatedAt.Format(time.RFC3339),
		obj.MetadataHeaders,
	)
	return h.writeResponse(StatusOK, req.streamID, resp, f, obj.SizeBytes)
}

func (h *connHandler) handleHeadObject(req *request) error {
	bucket, key, err := DecodeBucketKey(req.meta)
	if err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionObjectGet, bucket, key); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bkt, err := h.db.GetBucket(bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	obj, err := h.db.GetObjectMeta(bkt.ID, key)
	if err != nil {
		if errors.Is(err, meta.ErrObjectNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "object not found", "NoSuchKey")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	resp := EncodeObjectInfo(
		obj.ContentType, obj.SizeBytes,
		obj.ETag, obj.ChecksumSHA256,
		obj.UpdatedAt.Format(time.RFC3339),
		obj.MetadataHeaders,
	)
	return h.writeResponseCombined(StatusOK, req.streamID, resp)
}

func (h *connHandler) handleDeleteObject(req *request) error {
	bucket, key, err := DecodeBucketKey(req.meta)
	if err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionObjectDelete, bucket, key); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bkt, err := h.db.GetBucket(bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	obj, err := h.db.DeleteObjectMeta(bkt.ID, key)
	if err != nil {
		if errors.Is(err, meta.ErrObjectNotFound) {
			return h.writeResponse(StatusOK, req.streamID, nil, nil, 0)
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	if err := h.store.DeleteObject(obj.LocationRef); err != nil {
		h.log.Warn("gc deleted object", "err", err, "location", obj.LocationRef)
	}

	return h.writeResponse(StatusOK, req.streamID, nil, nil, 0)
}

// errDataTooLarge is returned by drainData when the remaining data exceeds
// MaxDrainSize, indicating the connection must be closed.
var errDataTooLarge = fmt.Errorf("data too large to drain, closing connection")

func drainData(req *request) error {
	if req.data == nil || req.dataLen == 0 {
		return nil
	}
	if req.dataLen > MaxDrainSize {
		return errDataTooLarge
	}
	_, err := io.CopyN(io.Discard, req.data, req.dataLen)
	return err
}

type emptyReader struct{}

func (e *emptyReader) Read(p []byte) (int, error) { return 0, io.EOF }
