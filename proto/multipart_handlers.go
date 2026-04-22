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

func (h *connHandler) handleCreateMultipartUpload(req *request) error {
	bucket, key, contentType, err := DecodeCreateMultipartRequest(req.meta)
	if err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionMultipartCreate, bucket, key); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bkt, err := h.db.GetBucket(bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	if contentType == "" {
		contentType = "application/octet-stream"
	}

	upload := &meta.MultipartUpload{
		UploadID:    uuid.New().String(),
		BucketID:    bkt.ID,
		ObjectKey:   key,
		ContentType: contentType,
		InitiatedBy: h.token.AccountID,
		CreatedAt:   time.Now().UTC(),
		State:       "initiated",
	}

	if err := h.db.CreateMultipartUpload(upload); err != nil {
		h.log.Error("create multipart", "err", err)
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	// Encode uploadID as a simple string
	return h.writeResponseCombined(StatusOK, req.streamID, EncodeBucket(upload.UploadID))
}

func (h *connHandler) handleUploadPart(req *request) error {
	bucket, key, uploadID, partNumber, err := DecodeUploadPartRequest(req.meta)
	if err != nil {
		if derr := drainData(req); derr != nil {
			return derr
		}
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionMultipartUpload, bucket, key); err != nil {
		if derr := drainData(req); derr != nil {
			return derr
		}
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	upload, err := h.db.GetMultipartUpload(uploadID)
	if err != nil {
		if derr := drainData(req); derr != nil {
			return derr
		}
		if errors.Is(err, meta.ErrUploadNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "upload not found", "NoSuchUpload")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	if upload.InitiatedBy != h.token.AccountID {
		if derr := drainData(req); derr != nil {
			return derr
		}
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	if upload.State != "initiated" {
		if derr := drainData(req); derr != nil {
			return derr
		}
		return h.writeError(StatusBadRequest, req.streamID, "upload not active", "InvalidArgument")
	}

	if partNumber < 1 || partNumber > meta.MaxMultipartParts {
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

	checksum, size, locationRef, err := h.store.WritePart(uploadID, partNumber, body)
	if err != nil {
		h.log.Error("write part", "err", err)
		return h.writeError(StatusInternal, req.streamID, "failed to write part", "InternalError")
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
		h.log.Error("add part meta", "err", err)
		return h.writeError(StatusInternal, req.streamID, "failed to register part", "InternalError")
	}

	return h.writeResponseCombined(StatusOK, req.streamID, EncodePutResponse(etag, checksum))
}

func (h *connHandler) handleCompleteMultipart(req *request) error {
	bucket, key, uploadID, partNumbers, err := DecodeCompleteMultipartRequest(req.meta)
	if err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionMultipartComplete, bucket, key); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bkt, err := h.db.GetBucket(bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	existing, err := h.db.GetMultipartUpload(uploadID)
	if err != nil {
		if errors.Is(err, meta.ErrUploadNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "upload not found", "NoSuchUpload")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}
	if existing.InitiatedBy != h.token.AccountID {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	upload, err := h.db.CompleteMultipartUpload(uploadID, partNumbers)
	if err != nil {
		if errors.Is(err, meta.ErrUploadNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "upload not found", "NoSuchUpload")
		}
		h.log.Error("complete multipart", "err", err)
		return h.writeError(StatusInternal, req.streamID, "failed to complete", "InternalError")
	}

	objectID := uuid.New().String()
	partLocations := make([]string, len(upload.Parts))
	for i, p := range upload.Parts {
		partLocations[i] = p.LocationRef
	}

	checksum, size, locationRef, err := h.store.AssembleParts(bkt.ID, objectID, partLocations)
	if err != nil {
		h.log.Error("assemble parts", "err", err)
		return h.writeError(StatusInternal, req.streamID, "failed to assemble", "InternalError")
	}

	etag := computeMultipartETag(upload.Parts)

	obj := &meta.Object{
		BucketID:       bkt.ID,
		Key:            key,
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
		if err := h.store.DeleteObject(prev.LocationRef); err != nil {
			h.log.Warn("delete previous object version", "err", err, "location", prev.LocationRef)
		}
	}

	if err := h.store.CleanupUploadParts(uploadID); err != nil {
		h.log.Warn("cleanup upload parts", "err", err, "upload_id", uploadID)
	}
	if err := h.db.DeleteMultipartUpload(uploadID); err != nil {
		h.log.Warn("delete multipart upload record", "err", err, "upload_id", uploadID)
	}

	return h.writeResponseCombined(StatusOK, req.streamID, EncodeCompleteMultipartResponse(etag, checksum, size))
}

func (h *connHandler) handleAbortMultipart(req *request) error {
	bucket, key, uploadID, err := DecodeBucketKeyUpload(req.meta)
	if err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionMultipartAbort, bucket, key); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	existing, err := h.db.GetMultipartUpload(uploadID)
	if err != nil {
		if errors.Is(err, meta.ErrUploadNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "upload not found", "NoSuchUpload")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}
	if existing.InitiatedBy != h.token.AccountID {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	upload, err := h.db.AbortMultipartUpload(uploadID)
	if err != nil {
		if errors.Is(err, meta.ErrUploadNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "upload not found", "NoSuchUpload")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	if err := h.store.CleanupUploadParts(upload.UploadID); err != nil {
		h.log.Warn("cleanup upload parts", "err", err, "upload_id", upload.UploadID)
	}
	if err := h.db.DeleteMultipartUpload(uploadID); err != nil {
		h.log.Warn("delete multipart upload record", "err", err, "upload_id", uploadID)
	}

	return h.writeResponse(StatusOK, req.streamID, nil, nil, 0)
}

func (h *connHandler) handleListParts(req *request) error {
	bucket, key, uploadID, err := DecodeBucketKeyUpload(req.meta)
	if err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionMultipartUpload, bucket, key); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	upload, err := h.db.GetMultipartUpload(uploadID)
	if err != nil {
		if errors.Is(err, meta.ErrUploadNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "upload not found", "NoSuchUpload")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}
	if upload.InitiatedBy != h.token.AccountID {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	entries := make([]PartInfoEntry, len(upload.Parts))
	for i, p := range upload.Parts {
		entries[i] = PartInfoEntry{
			PartNumber:     p.PartNumber,
			Size:           p.Size,
			ETag:           p.ETag,
			ChecksumSHA256: p.ChecksumSHA256,
		}
	}

	return h.writeResponseCombined(StatusOK, req.streamID, EncodeListPartsResponse(entries))
}

func computeMultipartETag(parts []meta.MultipartPart) string {
	h := md5.New()
	for _, p := range parts {
		partMD5, _ := hex.DecodeString(p.ETag)
		h.Write(partMD5)
	}
	return fmt.Sprintf("%s-%d", hex.EncodeToString(h.Sum(nil)), len(parts))
}
