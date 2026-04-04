package proto

import (
	"encoding/json"
	"errors"

	"github.com/ivangsm/jay/meta"
)

type listObjectsRequest struct {
	Bucket     string `json:"bucket"`
	Prefix     string `json:"prefix,omitempty"`
	Delimiter  string `json:"delimiter,omitempty"`
	StartAfter string `json:"start_after,omitempty"`
	MaxKeys    int    `json:"max_keys,omitempty"`
}

type listObjectEntry struct {
	Key            string `json:"key"`
	Size           int64  `json:"size"`
	ETag           string `json:"etag"`
	ChecksumSHA256 string `json:"checksum_sha256"`
	LastModified   string `json:"last_modified"`
	ContentType    string `json:"content_type"`
}

type listObjectsResponse struct {
	Objects        []listObjectEntry `json:"objects"`
	CommonPrefixes []string          `json:"common_prefixes,omitempty"`
	IsTruncated    bool              `json:"is_truncated"`
	NextStartAfter string            `json:"next_start_after,omitempty"`
}

func (h *connHandler) handleListObjects(req *request) error {
	var params listObjectsRequest
	if err := json.Unmarshal(req.meta, &params); err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.auth.Authorize(h.token, meta.ActionObjectList, params.Bucket, ""); err != nil {
		return h.writeError(StatusForbidden, req.streamID, "access denied", "AccessDenied")
	}

	bucket, err := h.db.GetBucket(params.Bucket)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return h.writeError(StatusNotFound, req.streamID, "bucket not found", "NoSuchBucket")
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	maxKeys := params.MaxKeys
	if maxKeys <= 0 {
		maxKeys = 1000
	}

	result, err := h.db.ListObjects(bucket.ID, params.Prefix, params.Delimiter, params.StartAfter, maxKeys)
	if err != nil {
		h.log.Error("list objects", "err", err)
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	response := listObjectsResponse{
		CommonPrefixes: result.CommonPrefixes,
		IsTruncated:    result.IsTruncated,
		NextStartAfter: result.NextStartAfter,
	}

	for _, obj := range result.Objects {
		response.Objects = append(response.Objects, listObjectEntry{
			Key:            obj.Key,
			Size:           obj.SizeBytes,
			ETag:           obj.ETag,
			ChecksumSHA256: obj.ChecksumSHA256,
			LastModified:   obj.UpdatedAt.Format("2006-01-02T15:04:05Z"),
			ContentType:    obj.ContentType,
		})
	}

	resp, _ := json.Marshal(response)
	return h.writeResponse(StatusOK, req.streamID, resp, nil, 0)
}
