package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/ivangsm/jay/auth"
)

// S3 error codes for an aws-chunked body the decoder refused.
const (
	// s3ErrSignatureDoesNotMatch is the code S3 answers for a signature that
	// does not verify — here, a chunk or trailer signature.
	s3ErrSignatureDoesNotMatch = "SignatureDoesNotMatch"
	// s3ErrIncompleteBody is S3's code for a body that does not carry the
	// number of bytes its headers promised.
	s3ErrIncompleteBody = "IncompleteBody"
)

// withChunkedBodyGate decides, before authentication and before a byte of the
// body is read, whether an aws-chunked request may reach the decoder at all.
// The decoding itself happens in auth.AuthenticateSigV4, which is the only
// place holding the request signature the chunk chain is seeded with.
//
// What passes, and why nothing else does:
//
//   - A SigV4 Authorization header. A bearer token or a presigned URL (either
//     style) has no seed signature, so its chunks could not be verified; the
//     request answers 501 rather than being stored with its framing.
//   - PutObject or UploadPart. Those two commit only when the body reports its
//     end, and the decoder reports the end only once every chunk, the length
//     and the trailer have verified. A handler that acts on bytes as it parses
//     them (DeleteObjects, CompleteMultipartUpload) would act on data whose
//     chunk is not verified yet, so the framing is refused there; no client
//     frames those bodies anyway.
//   - A mode jay implements, with a well-formed announcement. SigV4a's ECDSA
//     variants answer 501; framing without a STREAMING-* literal, or without a
//     numeric x-amz-decoded-content-length, answers 400.
//
// It sits ahead of every middleware except request ID, logging, recovery and
// the IP rate limiter, so a refusal is cheap, is logged with its request ID, and
// writes nothing: no object, no metadata, no temp file. The same requests are
// refused a second time further in — by auth (verifyPayloadHash, the bearer
// branch of Authenticate) and by servePresigned for the X-Jay presigned form —
// so reordering this middleware cannot bring back the old behaviour of storing
// the framing as the object.
func (h *Handler) withChunkedBodyGate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := auth.ChunkedBodyIndicator(r)
		if hdr == "" {
			next(w, r)
			return
		}

		reason := ""
		switch {
		case !auth.UsesSigV4Header(r):
			reason = "aws-chunked request bodies are decoded only for requests signed with a SigV4 " +
				"Authorization header: a bearer token or a presigned URL has no signature to verify the chunks against"
		case !acceptsChunkedBody(r):
			reason = "only PutObject and UploadPart accept an aws-chunked request body"
		}
		if reason != "" {
			h.refuseChunkedBody(w, r, hdr, http.StatusNotImplemented, S3ErrNotImplemented, reason+
				". Re-send the request with the payload's SHA-256 in x-amz-content-sha256, or with UNSIGNED-PAYLOAD.")
			return
		}

		if _, err := auth.ParseStreamingPayload(r); err != nil {
			status, code := http.StatusBadRequest, s3ErrInvalidRequest
			if errors.Is(err, auth.ErrChunkedBodyUnsupported) {
				status, code = http.StatusNotImplemented, S3ErrNotImplemented
			}
			h.refuseChunkedBody(w, r, hdr, status, code, chunkedErrorDetail(err))
			return
		}

		next(w, r)
	}
}

// acceptsChunkedBody reports whether the request is one of the two operations
// that may carry an aws-chunked body: a PUT on an object key that is not a
// copy. dispatch sends such a request to PutObject, to UploadPart (with
// uploadId), or refuses it for an unsupported sub-resource before reading the
// body — it cannot reach any other handler.
func acceptsChunkedBody(r *http.Request) bool {
	if r.Method != http.MethodPut || r.Header.Get("x-amz-copy-source") != "" {
		return false
	}
	_, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	return key != ""
}

// refuseChunkedBody logs and answers a refused aws-chunked request.
//
// The ID comes from withRequestID, the outermost middleware, so the refusal
// reports the same one the client reads in x-amz-request-id and the same one
// the access log line carries.
func (h *Handler) refuseChunkedBody(w http.ResponseWriter, r *http.Request, indicator string, status int, code, message string) {
	h.log.Warn("rejected aws-chunked request body",
		"request_id", requestIDFromContext(r.Context()),
		"method", r.Method,
		"path", r.URL.Path,
		"indicator", indicator,
		"status", status,
		"reason", message,
	)
	writeS3Error(w, r, status, code, message, r.URL.Path)
}

// writeChunkedBodyError maps an error the aws-chunked decoder returned while a
// handler was reading the body. Returns true when it handled the error.
//
// By the time this runs nothing was committed: the decoder never reported the
// end of the body, so the store never renamed its temp file.
func (h *Handler) writeChunkedBodyError(w http.ResponseWriter, r *http.Request, err error, resource string) bool {
	var cerr *auth.ChunkedBodyError
	if !errors.As(err, &cerr) {
		return false
	}
	switch {
	case errors.Is(err, auth.ErrChunkSignatureMismatch):
		if h.metrics != nil {
			h.metrics.AuthFailures.Add(1)
		}
		writeS3Error(w, r, http.StatusForbidden, s3ErrSignatureDoesNotMatch,
			"The aws-chunked signature we calculated does not match the one you provided ("+cerr.Detail+")", resource)
	case errors.Is(err, auth.ErrDecodedLengthMismatch):
		writeS3Error(w, r, http.StatusBadRequest, s3ErrIncompleteBody,
			"The aws-chunked body does not match x-amz-decoded-content-length: "+cerr.Detail, resource)
	case errors.Is(err, auth.ErrChunkedBodyUnsupported):
		writeS3Error(w, r, http.StatusNotImplemented, S3ErrNotImplemented, cerr.Detail, resource)
	default:
		writeS3Error(w, r, http.StatusBadRequest, s3ErrInvalidRequest,
			"Malformed aws-chunked request body: "+cerr.Detail, resource)
	}
	return true
}

// chunkedErrorDetail returns the client-facing part of a decoder error.
func chunkedErrorDetail(err error) string {
	var cerr *auth.ChunkedBodyError
	if errors.As(err, &cerr) {
		return cerr.Detail
	}
	return err.Error()
}
