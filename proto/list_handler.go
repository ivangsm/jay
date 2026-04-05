package proto

import (
	"errors"

	"github.com/ivangsm/jay/meta"
)

func (h *connHandler) handleListObjects(req *request) error {
	bucket, prefix, delimiter, startAfter, maxKeys, err := DecodeListObjectsRequest(req.meta)
	if err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionObjectList, bucket, ""); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bkt, err := h.db.GetBucket(bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	if maxKeys <= 0 {
		maxKeys = 1000
	}
	if maxKeys > 10000 {
		maxKeys = 10000
	}

	result, err := h.db.ListObjects(bkt.ID, prefix, delimiter, startAfter, maxKeys)
	if err != nil {
		h.log.Error("list objects", "err", err)
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	entries := make([]ListObjectEntry, len(result.Objects))
	for i, obj := range result.Objects {
		entries[i] = ListObjectEntry{
			Key:            obj.Key,
			Size:           obj.SizeBytes,
			ETag:           obj.ETag,
			ChecksumSHA256: obj.ChecksumSHA256,
			LastModified:   obj.UpdatedAt.Format("2006-01-02T15:04:05Z"),
			ContentType:    obj.ContentType,
		}
	}

	resp := EncodeListObjectsResponse(entries, result.CommonPrefixes, result.IsTruncated, result.NextStartAfter)
	return h.writeResponseCombined(StatusOK, req.streamID, resp)
}
