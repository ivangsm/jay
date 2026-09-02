package api

import (
	"cmp"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/ivangsm/jay/meta"
)

// defaultMaxUploads is the page size ListMultipartUploads uses when the client
// does not ask for one — the same 1000 S3 documents.
const defaultMaxUploads = 1000

// handleListMultipartUploads handles GET /<bucket>?uploads.
//
// Without it an S3 client cannot see, let alone abort, an upload that was
// started and never finished: the only thing that reclaims those is jay's own
// GC, 24 hours later. ListParts already exists, so this closes the bucket-level
// half of multipart.
//
// The listing is scoped twice. To the caller's account, because every other
// multipart operation authorizes against upload.InitiatedBy and an upload id
// from another account is unusable to this token anyway — listing it would only
// disclose object keys. And to the token's prefix scope, so a token that may not
// touch a key does not learn that an upload for it exists.
//
// The prefix half is deliberately stricter than handleListObjectsV2, which
// applies no prefix scope to its listing. That gap is older than this handler
// and is not widened by matching it here.
func (h *Handler) handleListMultipartUploads(w http.ResponseWriter, r *http.Request, bucketName string) {
	token, ok := h.requireAuth(r, w, meta.ActionObjectList, bucketName, "")
	if !ok {
		return
	}
	if token == nil {
		// requireAuth lets an anonymous caller list a public-read bucket. An
		// upload in flight is not published content — it has no object yet —
		// so public-read does not extend to it.
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied,
			"Authentication required", "/"+bucketName)
		return
	}

	bucket, err := h.db.GetBucket(bucketName)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchBucket,
				"Bucket not found", "/"+bucketName)
			return
		}
		h.log.Error("list multipart uploads: get bucket", "err", err, "bucket", bucketName)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", "/"+bucketName)
		return
	}

	if h.denyMultipartPolicy(w, r, bucket, meta.ActionObjectList, "") {
		return
	}

	uploads, err := h.db.ListMultipartUploads(bucket.ID)
	if err != nil {
		h.log.Error("list multipart uploads", "err", err, "bucket", bucketName)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", "/"+bucketName)
		return
	}

	if h.metrics != nil {
		h.metrics.ListObjectsTotal.Add(1)
	}

	writeXML(w, r, http.StatusOK, buildUploadsPage(bucketName, token, uploads, r.URL.Query()))
}

// buildUploadsPage applies prefix, delimiter, markers and max-uploads to the
// bucket's active uploads and returns one page of the S3 response.
//
// Uploads are ordered by (key, upload id) — the order the markers page through.
// bbolt stores them keyed by upload id, so the order has to be imposed here.
func buildUploadsPage(bucketName string, token *meta.Token, uploads []meta.MultipartUpload, q url.Values) ListMultipartUploadsResult {
	prefix := q.Get("prefix")
	delimiter := q.Get("delimiter")
	keyMarker := q.Get("key-marker")
	uploadIDMarker := q.Get("upload-id-marker")
	encodeURL := strings.EqualFold(q.Get("encoding-type"), "url")
	encodeKey := keyEncoder(rawKey)
	if encodeURL {
		encodeKey = urlEncodedKey
	}

	// Same reading as handleListObjectsV2: a max-uploads that is absent,
	// unparseable or non-positive falls back to the default rather than
	// producing an empty page the client cannot page past.
	maxUploads := defaultMaxUploads
	if raw := q.Get("max-uploads"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			maxUploads = min(n, defaultMaxUploads)
		}
	}

	candidates := make([]meta.MultipartUpload, 0, len(uploads))
	for _, u := range uploads {
		if u.InitiatedBy != token.AccountID {
			continue
		}
		if !withinPrefixScope(token.PrefixScope, u.ObjectKey) {
			continue
		}
		if prefix != "" && !strings.HasPrefix(u.ObjectKey, prefix) {
			continue
		}
		candidates = append(candidates, u)
	}
	slices.SortFunc(candidates, func(a, b meta.MultipartUpload) int {
		if c := cmp.Compare(a.ObjectKey, b.ObjectKey); c != 0 {
			return c
		}
		return cmp.Compare(a.UploadID, b.UploadID)
	})

	result := ListMultipartUploadsResult{
		XMLNS:          s3Namespace,
		Bucket:         bucketName,
		KeyMarker:      keyMarker,
		UploadIDMarker: uploadIDMarker,
		Prefix:         prefix,
		Delimiter:      delimiter,
		MaxUploads:     maxUploads,
	}

	seenPrefixes := make(map[string]struct{})
	var lastKey, lastUploadID string
	count := 0

	for _, u := range candidates {
		if !afterUploadMarker(u, keyMarker, uploadIDMarker) {
			continue
		}

		commonPrefix, rolled := rollUpPrefix(u.ObjectKey, prefix, delimiter)
		if rolled {
			// Members of a prefix are contiguous in this ordering, so every
			// upload behind an already-emitted prefix is consumed on the same
			// page it was emitted on. That is what makes lastKey below a resume
			// point that never repeats a common prefix across pages.
			if _, dup := seenPrefixes[commonPrefix]; dup {
				lastKey, lastUploadID = u.ObjectKey, u.UploadID
				continue
			}
			if count >= maxUploads {
				result.IsTruncated = true
				break
			}
			seenPrefixes[commonPrefix] = struct{}{}
			result.CommonPrefixes = append(result.CommonPrefixes, S3CommonPrefix{
				Prefix: encodeKey(commonPrefix),
			})
		} else {
			if count >= maxUploads {
				result.IsTruncated = true
				break
			}
			result.Uploads = append(result.Uploads, S3Upload{
				Key:          encodeKey(u.ObjectKey),
				UploadID:     u.UploadID,
				Initiator:    S3Owner{ID: u.InitiatedBy, DisplayName: u.InitiatedBy},
				Owner:        S3Owner{ID: u.InitiatedBy, DisplayName: u.InitiatedBy},
				StorageClass: "STANDARD",
				Initiated:    formatS3Time(u.CreatedAt),
			})
		}

		count++
		lastKey, lastUploadID = u.ObjectKey, u.UploadID
	}

	if result.IsTruncated {
		result.NextKeyMarker = encodeKey(lastKey)
		result.NextUploadIDMarker = lastUploadID
	}

	if encodeURL {
		// Only claim the encoding once every key-bearing field above has
		// actually been encoded: a client that reads EncodingType=url decodes
		// what it receives, so announcing it over raw keys corrupts them.
		result.EncodingType = "url"
		result.Prefix = encodeKey(result.Prefix)
		result.Delimiter = encodeKey(result.Delimiter)
		result.KeyMarker = encodeKey(result.KeyMarker)
	}

	return result
}

// withinPrefixScope reports whether a key is inside the token's prefix scope.
// An empty scope means the whole bucket, which is how meta.Token spells it
// everywhere else.
func withinPrefixScope(scope []string, key string) bool {
	if len(scope) == 0 {
		return true
	}
	return slices.ContainsFunc(scope, func(p string) bool {
		return strings.HasPrefix(key, p)
	})
}

// afterUploadMarker reports whether an upload falls after the (key-marker,
// upload-id-marker) pair. With no upload-id-marker only keys strictly greater
// than key-marker qualify, which is what S3 documents.
func afterUploadMarker(u meta.MultipartUpload, keyMarker, uploadIDMarker string) bool {
	if keyMarker == "" {
		return true
	}
	if u.ObjectKey > keyMarker {
		return true
	}
	if u.ObjectKey == keyMarker && uploadIDMarker != "" {
		return u.UploadID > uploadIDMarker
	}
	return false
}

// rollUpPrefix returns the common prefix a key collapses into for the given
// delimiter, and whether it collapses at all. The key is assumed to already
// carry prefix.
func rollUpPrefix(key, prefix, delimiter string) (string, bool) {
	if delimiter == "" {
		return "", false
	}
	rest := strings.TrimPrefix(key, prefix)
	i := strings.Index(rest, delimiter)
	if i < 0 {
		return "", false
	}
	return prefix + rest[:i+len(delimiter)], true
}

// keyEncoder renders a key into the response body. Which one is in play is
// decided once, from encoding-type, instead of being carried as a flag through
// every call site.
type keyEncoder func(string) string

// rawKey emits the key as stored — the default, and what every client that does
// not ask for encoding-type expects.
func rawKey(s string) string { return s }

// urlEncodedKey percent-encodes a key for encoding-type=url. url.QueryEscape
// spells a space as "+", which S3 does not; percent-encoding is what clients
// decode.
func urlEncodedKey(s string) string {
	if s == "" {
		return s
	}
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
