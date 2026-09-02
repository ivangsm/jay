package api

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/ivangsm/jay/internal/objops"
	"github.com/ivangsm/jay/meta"
)

// S3 error codes used only by DeleteObjects. Kept unexported here, next to the
// handler that emits them, for the same reason as s3ErrEntityTooLarge: the
// S3ErrXxx exported set is part of the package API and does not grow per
// operation.
const (
	s3ErrMalformedXML             = "MalformedXML"
	s3ErrBadDigest                = "BadDigest"
	s3ErrMaxMessageLengthExceeded = "MaxMessageLengthExceeded"
)

// maxDeleteKeys is S3's ceiling on one DeleteObjects request. A larger batch is
// refused whole: processing the first 1000 and dropping the rest would answer
// 200 for keys that were never even looked at.
const maxDeleteKeys = 1000

// maxDeleteRequestSize bounds the <Delete> document jay is willing to buffer.
// The XML has to be read end-to-end before a single key can be deleted, so
// without a ceiling an authenticated caller can make the server allocate as
// much memory as it can send — the same reasoning (and the same shape) as
// maxSignedPayloadSize in auth/sigv4.go.
//
// 4 MiB is far above any legitimate request: the largest S3 allows is 1000 keys
// of 1024 bytes, and even with every byte XML-escaped to `&amp;` that is ~5 MiB
// of pathological input against ~100 KB of a realistic one.
const maxDeleteRequestSize = 4 << 20

// handleDeleteObjects handles POST /<bucket>?delete — the batch delete behind
// `aws s3 rm --recursive`, `aws s3 sync --delete` and `aws s3 rb --force`.
//
// The contract that matters is the per-key one: every key of the request comes
// back in <Deleted> or in <Error>, never omitted. A caller that gets a 200 with
// a key silently missing concludes the object is gone, and for `rm --recursive`
// that is the difference between a deletion and a lie.
func (h *Handler) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucketName string) {
	// Bucket-level half of the authorization: action and bucket scope. The
	// per-key half — prefix scope and the bucket policy deny overlay — runs
	// inside objops for every key below, so a key outside the token's reach
	// becomes an <Error> instead of a delete.
	token, ok := h.requireAuth(r, w, meta.ActionObjectDelete, bucketName, "")
	if !ok {
		return
	}
	if token == nil {
		// requireAuth only lets a nil token through for public-read GET/LIST,
		// so this is unreachable today. It stays because objops treats a nil
		// token as "skip the token checks", and a batch delete is not where
		// that invariant should be discovered by trying.
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied,
			"Authentication required", "/"+bucketName)
		return
	}

	if _, err := h.db.GetBucket(bucketName); err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchBucket,
				"Bucket not found", "/"+bucketName)
			return
		}
		h.log.Error("delete objects: get bucket", "err", err, "bucket", bucketName)
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError,
			"Internal error", "/"+bucketName)
		return
	}

	body, ok := h.readDeleteBody(w, r, bucketName)
	if !ok {
		return
	}

	input, ok := h.parseDeleteInput(w, r, bucketName, body)
	if !ok {
		return
	}

	writeXML(w, r, http.StatusOK, h.deleteBatch(r, token, bucketName, input))
}

// readDeleteBody buffers the request body under maxDeleteRequestSize and, when
// the client sent one, verifies Content-MD5 against it.
//
// S3 documents Content-MD5 as required on DeleteObjects; jay does not require
// it. SigV4 already covers the body through x-amz-content-sha256, and the
// bearer and presigned paths have no way to produce the header, so demanding it
// would reject working clients over an integrity check that is already made.
// What jay does do is honour it when it arrives: acting on a body whose digest
// does not match the one the client computed would mean deleting keys the
// client did not send.
func (h *Handler) readDeleteBody(w http.ResponseWriter, r *http.Request, bucketName string) ([]byte, bool) {
	if r.ContentLength > maxDeleteRequestSize {
		writeS3Error(w, r, http.StatusBadRequest, s3ErrMaxMessageLengthExceeded,
			"Your request was too big", "/"+bucketName)
		return nil, false
	}

	var body []byte
	if r.Body != nil {
		// +1 so a body that lies about (or omits) Content-Length is detected
		// instead of being silently truncated into a document that parses.
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, maxDeleteRequestSize+1))
		if err != nil {
			writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument,
				"Could not read request body", "/"+bucketName)
			return nil, false
		}
		if len(body) > maxDeleteRequestSize {
			writeS3Error(w, r, http.StatusBadRequest, s3ErrMaxMessageLengthExceeded,
				"Your request was too big", "/"+bucketName)
			return nil, false
		}
	}

	if declared := strings.TrimSpace(r.Header.Get("Content-MD5")); declared != "" {
		// MD5 is not a security choice here: it is the digest S3 defines for
		// this header, and the comparison is against a value the client sent in
		// the clear anyway.
		sum := md5.Sum(body)
		if base64.StdEncoding.EncodeToString(sum[:]) != declared {
			writeS3Error(w, r, http.StatusBadRequest, s3ErrBadDigest,
				"The Content-MD5 you specified did not match what we received", "/"+bucketName)
			return nil, false
		}
	}

	return body, true
}

// parseDeleteInput decodes the <Delete> document and enforces the request-level
// limits. Anything wrong with the document as a whole fails the whole request:
// a batch that is half-applied and reported as 200 is the failure this
// operation exists to avoid.
func (h *Handler) parseDeleteInput(w http.ResponseWriter, r *http.Request, bucketName string, body []byte) (*DeleteObjectsInput, bool) {
	// encoding/xml refuses a document that declares its own DOCTYPE entities
	// instead of expanding them, so the buffered body cannot blow up in memory
	// past the ceiling readDeleteBody already applied.
	var input DeleteObjectsInput
	if err := xml.NewDecoder(bytes.NewReader(body)).Decode(&input); err != nil {
		writeS3Error(w, r, http.StatusBadRequest, s3ErrMalformedXML,
			"The XML you provided was not well-formed or did not validate against our published schema",
			"/"+bucketName)
		return nil, false
	}

	if len(input.Objects) == 0 {
		writeS3Error(w, r, http.StatusBadRequest, s3ErrMalformedXML,
			"The Delete request must contain at least one Object", "/"+bucketName)
		return nil, false
	}
	if len(input.Objects) > maxDeleteKeys {
		writeS3Error(w, r, http.StatusBadRequest, s3ErrMalformedXML,
			"The Delete request contains more than the maximum of 1000 objects", "/"+bucketName)
		return nil, false
	}

	return &input, true
}

// deleteBatch runs the per-key deletes and builds the response. Every entry of
// the request lands in exactly one of the two lists.
func (h *Handler) deleteBatch(r *http.Request, token *meta.Token, bucketName string, input *DeleteObjectsInput) DeleteResult {
	identity := h.buildIdentity(r, meta.ActionObjectDelete)
	result := DeleteResult{XMLNS: s3Namespace}

	deleted := 0
	for _, entry := range input.Objects {
		switch {
		case entry.Key == "":
			result.Errors = append(result.Errors, DeleteObjectError{
				Code:    S3ErrInvalidArgument,
				Message: "Object key must not be empty",
			})
			continue
		case entry.VersionID != "":
			// jay has no versioning. Deleting the current object because a
			// version was named would report work that was not the work asked
			// for — the same reason ?versionId answers 501 on a single object.
			result.Errors = append(result.Errors, DeleteObjectError{
				Key:     entry.Key,
				Code:    S3ErrNotImplemented,
				Message: "Versioned delete is not implemented",
			})
			continue
		}

		// objops owns the delete path for every transport. It is also where the
		// per-key authorization lives, so this loop cannot accidentally delete
		// past the token's prefix scope or past a bucket policy deny.
		if err := h.objops.DeleteObject(r.Context(), token, bucketName, entry.Key, identity); err != nil {
			code, message := deleteObjectsErrorFor(err)
			if code == S3ErrAccessDenied && h.metrics != nil {
				h.metrics.AuthFailures.Add(1)
			}
			if code == S3ErrInternalError {
				h.log.Error("delete objects: key failed",
					"err", err, "bucket", bucketName, "key", entry.Key)
			}
			result.Errors = append(result.Errors, DeleteObjectError{
				Key:     entry.Key,
				Code:    code,
				Message: message,
			})
			continue
		}

		deleted++
		// Quiet suppresses the successes only. The errors above are reported
		// either way: quiet means "do not list what worked", never "do not tell
		// me what failed".
		if !input.Quiet {
			result.Deleted = append(result.Deleted, DeletedObject{Key: entry.Key})
		}
	}

	if h.metrics != nil && deleted > 0 {
		h.metrics.DeleteObjectTotal.Add(int64(deleted))
	}
	return result
}

// deleteObjectsErrorFor maps an objops error to the per-key <Error> a client
// would have seen had it deleted that key on its own.
func deleteObjectsErrorFor(err error) (code, message string) {
	switch {
	case errors.Is(err, objops.ErrBucketNotFound):
		// The bucket was resolved before the loop, so reaching this means it
		// was deleted mid-batch.
		return S3ErrNoSuchBucket, "Bucket not found"
	case errors.Is(err, objops.ErrAccessDenied), errors.Is(err, objops.ErrPolicyDenied):
		return S3ErrAccessDenied, "Access denied"
	default:
		return S3ErrInternalError, "Internal error"
	}
}
