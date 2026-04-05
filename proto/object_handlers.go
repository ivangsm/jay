package proto

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/meta"
)

type putObjectRequest struct {
	Bucket      string            `json:"bucket"`
	Key         string            `json:"key"`
	ContentType string            `json:"content_type,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type putObjectResponse struct {
	ETag           string `json:"etag"`
	ChecksumSHA256 string `json:"checksum_sha256"`
}

type objectInfoResponse struct {
	ContentType    string            `json:"content_type"`
	Size           int64             `json:"size"`
	ETag           string            `json:"etag"`
	ChecksumSHA256 string            `json:"checksum_sha256"`
	LastModified   string            `json:"last_modified"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type objectRequest struct {
	Bucket string `json:"bucket"`
	Key    string `json:"key"`
}

func (h *connHandler) handlePutObject(req *request) error {
	var params putObjectRequest
	if err := json.Unmarshal(req.meta, &params); err != nil {
		if derr := drainData(req); derr != nil {
			return derr
		}
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionObjectPut, params.Bucket, params.Key); err != nil {
		if derr := drainData(req); derr != nil {
			return derr
		}
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bucket, err := h.db.GetBucket(params.Bucket)
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

	// Stream data through MD5 hasher (store computes SHA-256)
	md5Hash := md5.New()
	var body io.Reader
	if req.data != nil {
		body = io.TeeReader(req.data, md5Hash)
	} else {
		body = &emptyReader{}
	}

	checksum, size, locationRef, err := h.store.WriteObject(bucket.ID, objectID, body)
	if err != nil {
		h.log.Error("write object", "err", err, "bucket", params.Bucket, "key", params.Key)
		return h.writeError(StatusInternal, req.streamID, "failed to store object", "InternalError")
	}

	etag := hex.EncodeToString(md5Hash.Sum(nil))

	contentType := params.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	obj := &meta.Object{
		BucketID:        bucket.ID,
		Key:             params.Key,
		ObjectID:        objectID,
		State:           "active",
		SizeBytes:       size,
		ContentType:     contentType,
		ETag:            etag,
		ChecksumSHA256:  checksum,
		LocationRef:     locationRef,
		CreatedAt:       time.Now().UTC(),
		MetadataHeaders: params.Metadata,
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

	resp, err := json.Marshal(putObjectResponse{
		ETag:           etag,
		ChecksumSHA256: checksum,
	})
	if err != nil {
		return h.writeError(StatusInternal, req.streamID, "failed to encode response", "InternalError")
	}
	return h.writeResponse(StatusOK, req.streamID, resp, nil, 0)
}

func (h *connHandler) handleGetObject(req *request) error {
	var params objectRequest
	if err := json.Unmarshal(req.meta, &params); err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionObjectGet, params.Bucket, params.Key); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bucket, err := h.db.GetBucket(params.Bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	obj, err := h.db.GetObjectMeta(bucket.ID, params.Key)
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

	resp, err := json.Marshal(objectInfoResponse{
		ContentType:    obj.ContentType,
		Size:           obj.SizeBytes,
		ETag:           obj.ETag,
		ChecksumSHA256: obj.ChecksumSHA256,
		LastModified:   obj.UpdatedAt.Format(time.RFC3339),
		Metadata:       obj.MetadataHeaders,
	})
	if err != nil {
		return h.writeError(StatusInternal, req.streamID, "failed to encode response", "InternalError")
	}

	return h.writeResponse(StatusOK, req.streamID, resp, f, obj.SizeBytes)
}

func (h *connHandler) handleHeadObject(req *request) error {
	var params objectRequest
	if err := json.Unmarshal(req.meta, &params); err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionObjectGet, params.Bucket, params.Key); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bucket, err := h.db.GetBucket(params.Bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	obj, err := h.db.GetObjectMeta(bucket.ID, params.Key)
	if err != nil {
		if errors.Is(err, meta.ErrObjectNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "object not found", "NoSuchKey")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	resp, err := json.Marshal(objectInfoResponse{
		ContentType:    obj.ContentType,
		Size:           obj.SizeBytes,
		ETag:           obj.ETag,
		ChecksumSHA256: obj.ChecksumSHA256,
		LastModified:   obj.UpdatedAt.Format(time.RFC3339),
		Metadata:       obj.MetadataHeaders,
	})
	if err != nil {
		return h.writeError(StatusInternal, req.streamID, "failed to encode response", "InternalError")
	}

	return h.writeResponse(StatusOK, req.streamID, resp, nil, 0)
}

func (h *connHandler) handleDeleteObject(req *request) error {
	var params objectRequest
	if err := json.Unmarshal(req.meta, &params); err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionObjectDelete, params.Bucket, params.Key); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bucket, err := h.db.GetBucket(params.Bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	obj, err := h.db.DeleteObjectMeta(bucket.ID, params.Key)
	if err != nil {
		if errors.Is(err, meta.ErrObjectNotFound) {
			// Return OK for deleting non-existent objects (like S3)
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

// drainData drains remaining data from a request's data reader.
// If dataLen exceeds MaxDrainSize, it returns errDataTooLarge to signal
// the caller that the connection is in a corrupt state and must be closed.
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
