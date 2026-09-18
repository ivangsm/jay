package api

import (
	"net/http"

	"github.com/ivangsm/jay/auth"
)

// withUnframedBody refuses a request whose body carries AWS `aws-chunked`
// framing, before anything reads a byte of it: jay has no decoder for it, and
// storing the body verbatim would keep the chunk headers as the object.
//
// It sits ahead of every middleware except request ID, logging and the IP
// rate limiter: the refusal happens before authentication and before any
// handler opens a temp file, so nothing is written; one gate covers every
// entry point with a body and all three credential forms, which branch off
// later in withPresigned; and no signature is verified for a request that
// cannot be served. auth.verifyPayloadHash refuses the same requests a second
// time, so reordering this middleware cannot silently let them through.
func (h *Handler) withUnframedBody(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := auth.ChunkedBodyIndicator(r)
		if hdr == "" {
			next(w, r)
			return
		}

		// The ID comes from withRequestID, the outermost middleware, so this
		// refusal reports the same one the client reads in x-amz-request-id
		// and the same one the access log line carries.
		h.log.Warn("rejected aws-chunked request body",
			"request_id", requestIDFromContext(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"indicator", hdr,
		)

		writeS3Error(w, r, http.StatusNotImplemented, S3ErrNotImplemented,
			"Streaming aws-chunked request bodies are not implemented (announced by "+hdr+
				"). jay cannot decode the chunk framing and will not store it as the object. "+
				"Re-send the request with the payload's SHA-256 in x-amz-content-sha256, "+
				"or with UNSIGNED-PAYLOAD.",
			r.URL.Path)
	}
}
