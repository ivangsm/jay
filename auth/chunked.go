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
// jay has no decoder for that framing, so it is refused: reading the body
// verbatim would store the framing AS the object, with the ETag and SHA-256
// computed over it and the scrubber certifying it healthy.
// TODO(PND-0188): implement the decoder and lift the refusal.
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
// not the only one: x-amz-content-sha256 STREAMING-* (what the signature
// covers), x-amz-decoded-content-length (exists only in this mode, even from
// a client that never declares the literal) and Content-Encoding: aws-chunked
// (matched per token, since it combines with other codings). None of the three
// has any other meaning in S3.
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
