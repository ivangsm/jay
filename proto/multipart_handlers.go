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

type createMultipartRequest struct {
	Bucket      string `json:"bucket"`
	Key         string `json:"key"`
	ContentType string `json:"content_type,omitempty"`
}

type createMultipartResponse struct {
	UploadID string `json:"upload_id"`
}

type uploadPartRequest struct {
	Bucket     string `json:"bucket"`
	Key        string `json:"key"`
	UploadID   string `json:"upload_id"`
	PartNumber int    `json:"part_number"`
}

type uploadPartResponse struct {
	ETag           string `json:"etag"`
	ChecksumSHA256 string `json:"checksum_sha256"`
}

type completeMultipartRequest struct {
	Bucket      string `json:"bucket"`
	Key         string `json:"key"`
	UploadID    string `json:"upload_id"`
	PartNumbers []int  `json:"part_numbers"`
}

type completeMultipartResponse struct {
	ETag           string `json:"etag"`
	ChecksumSHA256 string `json:"checksum_sha256"`
	Size           int64  `json:"size"`
}

type abortMultipartRequest struct {
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	UploadID string `json:"upload_id"`
}

type listPartsRequest struct {
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	UploadID string `json:"upload_id"`
}

type partEntry struct {
	PartNumber     int    `json:"part_number"`
	Size           int64  `json:"size"`
	ETag           string `json:"etag"`
	ChecksumSHA256 string `json:"checksum_sha256"`
}

type listPartsResponse struct {
	Parts []partEntry `json:"parts"`
}

func (h *connHandler) handleCreateMultipartUpload(req *request) error {
	var params createMultipartRequest
	if err := json.Unmarshal(req.meta, &params); err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionMultipartCreate, params.Bucket, params.Key); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bucket, err := h.db.GetBucket(params.Bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	contentType := params.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	upload := &meta.MultipartUpload{
		UploadID:    uuid.New().String(),
		BucketID:    bucket.ID,
		ObjectKey:   params.Key,
		ContentType: contentType,
		InitiatedBy: h.token.AccountID,
		CreatedAt:   time.Now().UTC(),
		State:       "initiated",
	}

	if err := h.db.CreateMultipartUpload(upload); err != nil {
		h.log.Error("create multipart", "err", err)
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	resp, err := json.Marshal(createMultipartResponse{UploadID: upload.UploadID})
	if err != nil {
		return h.writeError(StatusInternal, req.streamID, "failed to encode response", "InternalError")
	}
	return h.writeResponse(StatusOK, req.streamID, resp, nil, 0)
}

func (h *connHandler) handleUploadPart(req *request) error {
	var params uploadPartRequest
	if err := json.Unmarshal(req.meta, &params); err != nil {
		if derr := drainData(req); derr != nil {
			return derr
		}
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionMultipartUpload, params.Bucket, params.Key); err != nil {
		if derr := drainData(req); derr != nil {
			return derr
		}
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	upload, err := h.db.GetMultipartUpload(params.UploadID)
	if err != nil {
		if derr := drainData(req); derr != nil {
			return derr
		}
		if errors.Is(err, meta.ErrUploadNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "upload not found", "NoSuchUpload")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	if upload.State != "initiated" {
		if derr := drainData(req); derr != nil {
			return derr
		}
		return h.writeError(StatusBadRequest, req.streamID, "upload not active", "InvalidArgument")
	}

	if params.PartNumber < 1 || params.PartNumber > meta.MaxMultipartParts {
		if derr := drainData(req); derr != nil {
			return derr
		}
		return h.writeError(StatusBadRequest, req.streamID, "part number must be between 1 and 10000", "InvalidArgument")
	}

	md5Hash := md5.New()
	var body io.Reader
	if req.data != nil {
		body = io.TeeReader(req.data, md5Hash)
	} else {
		body = &emptyReader{}
	}

	checksum, size, locationRef, err := h.store.WritePart(params.UploadID, params.PartNumber, body)
	if err != nil {
		h.log.Error("write part", "err", err)
		return h.writeError(StatusInternal, req.streamID, "failed to write part", "InternalError")
	}

	etag := hex.EncodeToString(md5Hash.Sum(nil))

	part := meta.MultipartPart{
		PartNumber:     params.PartNumber,
		Size:           size,
		ETag:           etag,
		ChecksumSHA256: checksum,
		LocationRef:    locationRef,
		CreatedAt:      time.Now().UTC(),
	}

	if err := h.db.AddMultipartPart(params.UploadID, part); err != nil {
		h.store.Cleanup(locationRef)
		h.log.Error("add part meta", "err", err)
		return h.writeError(StatusInternal, req.streamID, "failed to register part", "InternalError")
	}

	resp, err := json.Marshal(uploadPartResponse{ETag: etag, ChecksumSHA256: checksum})
	if err != nil {
		return h.writeError(StatusInternal, req.streamID, "failed to encode response", "InternalError")
	}
	return h.writeResponse(StatusOK, req.streamID, resp, nil, 0)
}

func (h *connHandler) handleCompleteMultipart(req *request) error {
	var params completeMultipartRequest
	if err := json.Unmarshal(req.meta, &params); err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionMultipartComplete, params.Bucket, params.Key); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bucket, err := h.db.GetBucket(params.Bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	upload, err := h.db.CompleteMultipartUpload(params.UploadID, params.PartNumbers)
	if err != nil {
		if errors.Is(err, meta.ErrUploadNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "upload not found", "NoSuchUpload")
		}
		h.log.Error("complete multipart", "err", err)
		return h.writeError(StatusInternal, req.streamID, "failed to complete", "InternalError")
	}

	objectID := uuid.New().String()
	var partLocations []string
	for _, p := range upload.Parts {
		partLocations = append(partLocations, p.LocationRef)
	}

	checksum, size, locationRef, err := h.store.AssembleParts(bucket.ID, objectID, partLocations)
	if err != nil {
		h.log.Error("assemble parts", "err", err)
		return h.writeError(StatusInternal, req.streamID, "failed to assemble", "InternalError")
	}

	etag := computeMultipartETag(upload.Parts)

	obj := &meta.Object{
		BucketID:       bucket.ID,
		Key:            params.Key,
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
		return h.writeError(StatusInternal, req.streamID, "failed to store metadata", "InternalError")
	}

	if prev != nil && prev.LocationRef != locationRef {
		h.store.DeleteObject(prev.LocationRef)
	}

	if err := h.store.CleanupUploadParts(params.UploadID); err != nil {
		h.log.Warn("cleanup upload parts", "err", err, "upload_id", params.UploadID)
	}
	if err := h.db.DeleteMultipartUpload(params.UploadID); err != nil {
		h.log.Warn("delete multipart upload record", "err", err, "upload_id", params.UploadID)
	}

	resp, err := json.Marshal(completeMultipartResponse{
		ETag:           etag,
		ChecksumSHA256: checksum,
		Size:           size,
	})
	if err != nil {
		return h.writeError(StatusInternal, req.streamID, "failed to encode response", "InternalError")
	}
	return h.writeResponse(StatusOK, req.streamID, resp, nil, 0)
}

func (h *connHandler) handleAbortMultipart(req *request) error {
	var params abortMultipartRequest
	if err := json.Unmarshal(req.meta, &params); err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionMultipartAbort, params.Bucket, params.Key); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	upload, err := h.db.AbortMultipartUpload(params.UploadID)
	if err != nil {
		if errors.Is(err, meta.ErrUploadNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "upload not found", "NoSuchUpload")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	if err := h.store.CleanupUploadParts(upload.UploadID); err != nil {
		h.log.Warn("cleanup upload parts", "err", err, "upload_id", upload.UploadID)
	}
	if err := h.db.DeleteMultipartUpload(params.UploadID); err != nil {
		h.log.Warn("delete multipart upload record", "err", err, "upload_id", params.UploadID)
	}

	return h.writeResponse(StatusOK, req.streamID, nil, nil, 0)
}

func (h *connHandler) handleListParts(req *request) error {
	var params listPartsRequest
	if err := json.Unmarshal(req.meta, &params); err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionMultipartUpload, params.Bucket, params.Key); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	upload, err := h.db.GetMultipartUpload(params.UploadID)
	if err != nil {
		if errors.Is(err, meta.ErrUploadNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "upload not found", "NoSuchUpload")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	response := listPartsResponse{}
	for _, p := range upload.Parts {
		response.Parts = append(response.Parts, partEntry{
			PartNumber:     p.PartNumber,
			Size:           p.Size,
			ETag:           p.ETag,
			ChecksumSHA256: p.ChecksumSHA256,
		})
	}

	resp, err := json.Marshal(response)
	if err != nil {
		return h.writeError(StatusInternal, req.streamID, "failed to encode response", "InternalError")
	}
	return h.writeResponse(StatusOK, req.streamID, resp, nil, 0)
}

func computeMultipartETag(parts []meta.MultipartPart) string {
	h := md5.New()
	for _, p := range parts {
		partMD5, _ := hex.DecodeString(p.ETag)
		h.Write(partMD5)
	}
	return fmt.Sprintf("%s-%d", hex.EncodeToString(h.Sum(nil)), len(parts))
}
