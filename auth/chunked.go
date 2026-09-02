package auth

import (
	"errors"
	"net/http"
	"strings"
)

// ErrChunkedBodyUnsupported reports a request whose body carries AWS
// `aws-chunked` framing — the wire format SigV4 streaming signatures use, where
// the payload arrives as `<hex-size>;chunk-signature=<sig>\r\n<data>\r\n`
// repeated until a zero-length chunk.
//
// jay has no decoder for that framing. Recognising the mode and then reading
// the body verbatim is what stored the framing AS the object: a 15-byte file
// uploaded with `mc` became 187 bytes, the ETag and the SHA-256 were computed
// over the corrupted bytes, and the scrubber therefore certified them healthy
// forever. Until a decoder exists, the framing has to be refused — accepting it
// undecoded is the one option that must not stay.
var ErrChunkedBodyUnsupported = errors.New("aws-chunked request body is not supported")

// streamingPayloadPrefix is what a client writes in x-amz-content-sha256 to
// announce an aws-chunked body. It covers every variant AWS defines:
// STREAMING-AWS4-HMAC-SHA256-PAYLOAD, STREAMING-UNSIGNED-PAYLOAD-TRAILER and
// the -TRAILER form of the first.
const streamingPayloadPrefix = "STREAMING-"

// ChunkedBodyIndicator reports which request header shows the body carries
// aws-chunked framing, or "" when none does. The header name is returned rather
// than a bool so the rejection can name what it saw.
//
// Three independent signals are checked, because the declared payload hash is
// not the only one and not the most reliable:
//
//   - x-amz-content-sha256: STREAMING-* is what minio-go and the AWS SDKs
//     declare, and what the signature actually covers.
//   - x-amz-decoded-content-length exists ONLY in this mode: it carries the
//     real body length while Content-Length counts the framing. That makes its
//     presence proof of framing even from a client that never declares the
//     STREAMING-* literal.
//   - Content-Encoding: aws-chunked is what the SigV4 streaming spec tells
//     clients to send, and it may be combined with other codings
//     ("aws-chunked,gzip"), so the value is matched per token.
//
// None of the three has any other meaning in S3, so there is no request that
// legitimately carries one and is not framed.
func ChunkedBodyIndicator(r *http.Request) string {
	if strings.HasPrefix(
		strings.ToUpper(strings.TrimSpace(r.Header.Get("x-amz-content-sha256"))),
		streamingPayloadPrefix,
	) {
		return "x-amz-content-sha256"
	}
	if r.Header.Get("x-amz-decoded-content-length") != "" {
		return "x-amz-decoded-content-length"
	}
	for coding := range strings.SplitSeq(r.Header.Get("Content-Encoding"), ",") {
		if strings.EqualFold(strings.TrimSpace(coding), "aws-chunked") {
			return "content-encoding"
		}
	}
	return ""
}
