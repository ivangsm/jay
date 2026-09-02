package api

import (
	"context"
	"net/http"

	"github.com/ivangsm/jay/auth"
)

// withUnframedBody refuses a request whose body carries AWS `aws-chunked`
// framing, before anything reads a byte of it.
//
// Why it exists: jay never had a decoder for that framing, but SigV4
// verification recognised the mode well enough to *skip* the payload check. The
// two together meant `mc cp` of a 15-byte file stored 187 bytes — the chunk
// headers and signatures kept as the object body — under a 200, with the ETag
// and the SHA-256 computed over the corrupted bytes. The scrubber then
// certified them healthy forever and recovery saw nothing inconsistent. A 200
// on work that did not happen is the failure this repo exists to avoid, so
// until there is a decoder the mode is refused.
//
// Why here, ahead of every other middleware except the IP rate limiter:
//
//   - Nothing is written. The refusal happens before authentication, before
//     dispatch and before any handler opens a temp file, so a rejected upload
//     leaves no object, no metadata and no orphan in JAY_DATA_DIR.
//   - One gate covers every entry point with a body. PutObject, UploadPart,
//     CompleteMultipartUpload, DeleteObjects and CreateBucket all pass through
//     here, and so do all three credential forms — Bearer, SigV4 header and
//     both presigned styles, which branch off later in withPresigned. A gate
//     per handler is a gate someone forgets on the next handler.
//   - No work is wasted verifying a signature for a request that cannot be
//     served. It still sits *inside* withIPRateLimit, so a flood of framed
//     requests is still rate limited.
//
// auth.verifyPayloadHash refuses the same requests a second time, so removing
// or reordering this middleware cannot silently restore the old behaviour.
func (h *Handler) withUnframedBody(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := auth.ChunkedBodyIndicator(r)
		if hdr == "" {
			next(w, r)
			return
		}

		// This middleware runs before withRequestIDAndAuth, so the error
		// response would otherwise carry an empty RequestId.
		reqID := generateRequestID()
		w.Header().Set("x-amz-request-id", reqID)
		r = r.WithContext(context.WithValue(r.Context(), ctxKeyRequestID, reqID))

		h.log.Warn("rejected aws-chunked request body",
			"request_id", reqID,
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
