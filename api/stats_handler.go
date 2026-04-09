package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/ivangsm/jay/meta"
)

// BucketStatsResponse is returned by GET /buckets/{name}/stats.
type BucketStatsResponse struct {
	Bucket         string `json:"bucket"`
	ObjectCount    int64  `json:"object_count"`
	TotalSizeBytes int64  `json:"total_size_bytes"`
}

// handleBucketStats handles GET /buckets/{name}/stats.
// Requires a regular token with the bucket:read-meta action.
func (h *Handler) handleBucketStats(w http.ResponseWriter, r *http.Request, bucketName string) {
	_, ok := h.requireAuth(r, w, meta.ActionBucketReadMeta, bucketName, "")
	if !ok {
		return
	}

	b, err := h.db.GetBucket(bucketName)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			http.Error(w, `{"error":"bucket not found"}`, http.StatusNotFound)
			return
		}
		h.log.Error("stats: get bucket", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	count, total, err := h.db.BucketStats(b.ID)
	if err != nil {
		h.log.Error("stats: compute", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(BucketStatsResponse{
		Bucket:         bucketName,
		ObjectCount:    count,
		TotalSizeBytes: total,
	})
}
