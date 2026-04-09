package api

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/meta"
)

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
		UploadId: uploadID,
	})
}

// handleUploadPart handles PUT /<bucket>/<key>?uploadId=X&partNumber=N
func (h *Handler) handleUploadPart(w http.ResponseWriter, r *http.Request, bucketName, objectKey, uploadID string) {
	_, ok := h.requireAuth(r, w, meta.ActionMultipartUpload, bucketName, objectKey)
	if !ok {
		return
	}

	partNumberStr := r.URL.Query().Get("partNumber")
	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument, "Invalid part number", "/"+bucketName+"/"+objectKey)
		return
	}

	upload, err := h.db.GetMultipartUpload(uploadID)
	if err != nil {
		if errors.Is(err, meta.ErrUploadNotFound) {
			writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "Upload not found", "/"+bucketName+"/"+objectKey)
			return
		}
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Internal error", "/"+bucketName+"/"+objectKey)
		return
	}

	if upload.State != "initiated" {
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument, "Upload is not active", "/"+bucketName+"/"+objectKey)
		return
	}

	// Write part to disk
	md5Hash := md5.New()
	body := io.TeeReader(r.Body, md5Hash)

	checksum, size, locationRef, err := h.store.WritePart(uploadID, partNumber, body)
	if err != nil {
		h.log.Error("write part", "err", err, "upload", uploadID, "part", partNumber)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Failed to write part", "/"+bucketName+"/"+objectKey)
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
	w.WriteHeader(http.StatusOK)
}

// handleCompleteMultipartUpload handles POST /<bucket>/<key>?uploadId=X
func (h *Handler) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request, bucketName, objectKey, uploadID string) {
	_, ok := h.requireAuth(r, w, meta.ActionMultipartComplete, bucketName, objectKey)
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

	// Parse request body
	var input CompleteMultipartUploadInput
	if err := xml.NewDecoder(r.Body).Decode(&input); err != nil {
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument, "Invalid request body", "/"+bucketName+"/"+objectKey)
		return
	}

	partNumbers := make([]int, len(input.Parts))
	for i, p := range input.Parts {
		partNumbers[i] = p.PartNumber
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
	_, ok := h.requireAuth(r, w, meta.ActionMultipartAbort, bucketName, objectKey)
	if !ok {
		return
	}

	upload, err := h.db.AbortMultipartUpload(uploadID)
	if err != nil {
		if errors.Is(err, meta.ErrUploadNotFound) {
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
	_, ok := h.requireAuth(r, w, meta.ActionMultipartUpload, bucketName, objectKey)
	if !ok {
		return
	}

	upload, err := h.db.GetMultipartUpload(uploadID)
	if err != nil {
		if errors.Is(err, meta.ErrUploadNotFound) {
			writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "Upload not found", "/"+bucketName+"/"+objectKey)
			return
		}
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Internal error", "/"+bucketName+"/"+objectKey)
		return
	}

	result := ListPartsResult{
		XMLNS:    s3Namespace,
		Bucket:   bucketName,
		Key:      objectKey,
		UploadId: uploadID,
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
