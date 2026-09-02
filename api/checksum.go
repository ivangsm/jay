package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
)

// checksumHeader is the S3 header carrying the SHA-256 digest of an object.
const checksumHeader = "x-amz-checksum-sha256"

// setChecksumHeader emits x-amz-checksum-sha256 for a whole object.
//
// jay stores the digest hex-encoded (store.WriteObject), but S3 defines every
// x-amz-checksum-* header as the RAW digest in base64, and the AWS CLI verifies
// it on each download: a hex value aborts the transfer with "Expected checksum
// ... did not match calculated checksum" even though the bytes are intact.
//
// This is the single conversion point of the HTTP edge. The hex form is what
// the scrubber compares, what the native protocol carries and what `jay ls -l`
// prints, so it is never rewritten in place — only on the way out.
//
// A digest that is not a well-formed SHA-256 yields no header at all. An
// unverifiable checksum is worse than none: the client would reject bytes that
// are in fact correct.
//
// Only call this for a response whose body is the ENTIRE object. S3 scopes the
// header to the bytes it returns, so a 206 must not carry the full-object
// digest — see handleGetObject.
func setChecksumHeader(w http.ResponseWriter, hexDigest string) {
	if hexDigest == "" {
		return
	}
	raw, err := hex.DecodeString(hexDigest)
	if err != nil || len(raw) != sha256.Size {
		return
	}
	w.Header().Set(checksumHeader, base64.StdEncoding.EncodeToString(raw))
}
