package api

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/ivangsm/jay/internal/objops"
	"github.com/ivangsm/jay/meta"
)

// handleCopyObject handles PUT /<bucket>/<key> with x-amz-copy-source header.
//
// The copy itself — both authorizations, the bucket-policy overlays on each
// side, the single-pass write and the metadata commit — is objops.CopyObject,
// shared with the native protocol and the embedded library. This handler only
// parses the S3 request and renders the S3 response.
func (h *Handler) handleCopyObject(w http.ResponseWriter, r *http.Request, dstBucket, dstKey string) {
	token, ok := h.requireAuth(r, w, meta.ActionObjectPut, dstBucket, dstKey)
	if !ok {
		return
	}
	dstResource := "/" + dstBucket + "/" + dstKey

	// What the client asked for is read before anything is copied: an algorithm
	// jay cannot compute has to be refused with nothing written, the same rule
	// PutObject follows. The AWS CLI only sends the header when someone passes
	// --checksum-algorithm, so this whole branch is dormant on the default path.
	checksumReq, cerr := copyChecksumRequest(r)
	if cerr != nil {
		h.writeChecksumError(w, r, cerr, dstResource)
		return
	}
	digester, cerr := objops.NewChecksumVerifier(checksumReq)
	if cerr != nil {
		h.writeChecksumError(w, r, cerr, dstResource)
		return
	}

	// Parse source: /bucket/key or bucket/key
	copySource := r.Header.Get("x-amz-copy-source")
	copySource = strings.TrimPrefix(copySource, "/")
	srcBucket, srcKey, found := strings.Cut(copySource, "/")
	if !found || srcKey == "" {
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument,
			"Invalid x-amz-copy-source", dstResource)
		return
	}
	srcResource := "/" + copySource

	// URL-decode source bucket and key
	srcBucket, err := url.PathUnescape(srcBucket)
	if err != nil {
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument,
			"Invalid copy source", copySource)
		return
	}
	srcKey, err = url.PathUnescape(srcKey)
	if err != nil {
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument,
			"Invalid copy source", copySource)
		return
	}

	// Token scope on the source. objops repeats the check with the bucket in
	// hand; this one answers before any lookup, like every other handler.
	if _, ok := h.requireAuth(r, w, meta.ActionObjectGet, srcBucket, srcKey); !ok {
		return
	}

	// The requested digest has to exist before the copy is committed. Answering
	// 200 without it is the defect PND-0194 names; answering 500 after the
	// metadata is in bbolt would report a failure for a copy that landed. The
	// hook runs between the write and the commit, so a refusal here removes one
	// temp file and nothing else.
	var checksumValue string
	beforeCommit := func(sha256Hex string) error {
		v, err := copyChecksumValue(digester, checksumReq.Algorithm, sha256Hex)
		if err != nil {
			return err
		}
		checksumValue = v
		return nil
	}

	newObj, err := h.objops.CopyObject(r.Context(), token,
		srcBucket, srcKey, dstBucket, dstKey,
		objops.CopyOptions{Digester: digester, BeforeCommit: beforeCommit},
		h.buildIdentity(r, meta.ActionObjectPut))
	if err != nil {
		h.writeCopyError(w, r, err, srcResource, dstResource, checksumReq.Algorithm)
		return
	}

	result := CopyObjectResult{
		XMLNS:        s3Namespace,
		LastModified: formatS3Time(newObj.CreatedAt),
		ETag:         formatETag(newObj.ETag),
	}
	if checksumValue != "" {
		// The copy is already committed, so this cannot refuse the request any
		// more. It can only fail if an algorithm exists that CopyObjectResult
		// has no element for, which the closed set in objops rules out — the
		// error is logged rather than swallowed so that day is not silent.
		if err := result.SetChecksum(checksumReq.Algorithm, checksumValue); err != nil {
			h.log.Error("copy: checksum has no response element", "err", err)
		}
	}
	writeXML(w, r, http.StatusOK, result)
}

// writeCopyError renders a CopyObject failure. Not-found and access errors name
// the side they happened on, because "NoSuchBucket" against the destination
// resource when it was the source that is missing sends the caller to fix the
// wrong thing.
func (h *Handler) writeCopyError(w http.ResponseWriter, r *http.Request, err error, srcResource, dstResource string, alg objops.ChecksumAlgorithm) {
	resource := dstResource
	prefix := "Destination"
	if objops.SideOfCopyError(err) == objops.CopySource {
		resource = srcResource
		prefix = "Source"
	}

	switch {
	case errors.Is(err, objops.ErrBucketNotFound):
		writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchBucket, prefix+" bucket not found", resource)
	case errors.Is(err, objops.ErrObjectNotFound):
		writeS3Error(w, r, http.StatusNotFound, S3ErrNoSuchKey, prefix+" object not found", resource)
	case errors.Is(err, objops.ErrPolicyDenied), errors.Is(err, objops.ErrAccessDenied):
		if h.metrics != nil {
			h.metrics.AuthFailures.Add(1)
		}
		writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Access denied", resource)
	default:
		// Includes the one refusal the BeforeCommit hook can raise — a digest
		// that was asked for and could not be produced — which is why the
		// algorithm is in the line.
		h.log.Error("copy: failed", "err", err,
			"source", srcResource, "destination", dstResource, "algorithm", string(alg))
		writeS3Error(w, r, http.StatusInternalServerError, S3ErrInternalError, "Failed to copy object", dstResource)
	}
}
