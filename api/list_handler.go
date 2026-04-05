package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ivangsm/jay/meta"
)

// handleListObjectsV2 handles GET /<bucket>?list-type=2
func (h *Handler) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucketName string) {
	_, ok := h.requireAuth(r, w, meta.ActionObjectList, bucketName, "")
	if !ok {
		return
	}

	bucket, err := h.db.GetBucket(bucketName)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchBucket,
				"Bucket not found", "/"+bucketName)
			return
		}
		h.log.Error("get bucket", "err", err)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", "/"+bucketName)
		return
	}

	q := r.URL.Query()
	prefix := q.Get("prefix")
	delimiter := q.Get("delimiter")
	startAfter := q.Get("start-after")
	contToken := q.Get("continuation-token")
	if contToken != "" && startAfter == "" {
		startAfter = contToken
	}

	maxKeys := 1000
	if mk := q.Get("max-keys"); mk != "" {
		if n, err := strconv.Atoi(mk); err == nil && n > 0 {
			maxKeys = n
		}
	}
	if maxKeys > 10000 {
		maxKeys = 10000
	}

	result, err := h.db.ListObjects(bucket.ID, prefix, delimiter, startAfter, maxKeys)
	if err != nil {
		h.log.Error("list objects", "err", err, "bucket", bucketName)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", "/"+bucketName)
		return
	}

	xmlResult := ListBucketResult{
		XMLNS:        s3Namespace,
		Name:         bucketName,
		Prefix:       prefix,
		Delimiter:    delimiter,
		MaxKeys:      maxKeys,
		IsTruncated:  result.IsTruncated,
		KeyCount:     len(result.Objects) + len(result.CommonPrefixes),
		EncodingType: q.Get("encoding-type"),
		StartAfter:   q.Get("start-after"),
		ContinuationToken: contToken,
	}

	if result.IsTruncated && result.NextStartAfter != "" {
		xmlResult.NextContinuationToken = result.NextStartAfter
	}

	for _, obj := range result.Objects {
		xmlResult.Contents = append(xmlResult.Contents, S3Content{
			Key:          obj.Key,
			LastModified: formatS3Time(obj.UpdatedAt),
			ETag:         formatETag(obj.ETag),
			Size:         obj.SizeBytes,
			StorageClass: "STANDARD",
		})
	}

	for _, cp := range result.CommonPrefixes {
		xmlResult.CommonPrefixes = append(xmlResult.CommonPrefixes, S3CommonPrefix{
			Prefix: cp,
		})
	}

	writeXML(w, r, http.StatusOK, xmlResult)
}
