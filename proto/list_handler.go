package proto

import (
	"errors"
	"time"

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

	if err := h.authorizeBucketAccess(bkt, meta.ActionObjectList, ""); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
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
			// Same formatting as HeadObject and GetObject. This used to be the
			// literal layout "2006-01-02T15:04:05Z", which is not a timezone
			// specifier: it stamps a "Z" on whatever zone the value carries.
			// Identical output today because meta stores UTC, but it meant one
			// object reported its mtime two different ways depending on how it
			// was fetched, and the wrong one would have claimed UTC while
			// printing local time.
			LastModified: obj.UpdatedAt.UTC().Format(time.RFC3339),
			ContentType:  obj.ContentType,
		}
	}

	resp, encErr := EncodeListObjectsResponse(entries, result.CommonPrefixes, result.IsTruncated, result.NextStartAfter)

	if h.metrics != nil {
		h.metrics.ListObjectsTotal.Add(1)
	}

	return h.writeEncoded(StatusOK, req.streamID, resp, encErr)
}
