package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/ivangsm/jay/internal/objops"
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

// ── Client-declared checksums (inbound) ───────────────────────────────────
//
// Everything above is about the digest jay reports. Everything below is about
// the digest the CLIENT reports, which is a different promise: sending
// Content-MD5 or x-amz-checksum-* on a PUT is the client asking "verify that
// what reached you is what I sent". Until PND-0189 jay read none of them and
// answered 200 regardless — an unconditional success to a request that was
// explicitly about integrity, in the one service whose selling point is
// integrity.

// The headers a client uses to declare a checksum. Two spellings for the
// algorithm because S3 uses both: the SDK header on PutObject/UploadPart, the
// plain one on CreateMultipartUpload. The AWS CLI sends the first on every
// upload it makes and the second on every multipart it starts.
const (
	sdkChecksumAlgorithmHeader = "x-amz-sdk-checksum-algorithm"
	checksumAlgorithmHeader    = "x-amz-checksum-algorithm"
	contentMD5Header           = "Content-MD5"
)

// S3 error codes for a checksum a client got wrong. InvalidDigest is the one S3
// reserves for a malformed Content-MD5; a malformed x-amz-checksum-* is an
// InvalidRequest, and a value that is well formed but does not describe the
// bytes is a BadDigest in both cases (s3ErrBadDigest, declared next to
// DeleteObjects, which had the only digest check jay used to have).
const (
	s3ErrInvalidDigest  = "InvalidDigest"
	s3ErrInvalidRequest = "InvalidRequest"
)

// checksumValueHeaders is every header that can carry a declared digest, paired
// with its algorithm. It is a slice and not a map so the scan order — and
// therefore the error message when a client sends two of them — is the same on
// every run. The list is closed on purpose: these five are all S3 defines for
// object payloads, and jay computes all five, so no declared digest is ignored.
var checksumValueHeaders = []struct {
	header string
	alg    objops.ChecksumAlgorithm
}{
	{"x-amz-checksum-crc32", objops.ChecksumCRC32},
	{"x-amz-checksum-crc32c", objops.ChecksumCRC32C},
	{"x-amz-checksum-crc64nvme", objops.ChecksumCRC64NVME},
	{"x-amz-checksum-sha1", objops.ChecksumSHA1},
	{"x-amz-checksum-sha256", objops.ChecksumSHA256},
}

// parseChecksumRequest reads what the client declared about the body it is
// about to send. It only reads headers — no digest is computed here — so it is
// safe (and required) to call before a single byte of the body is touched.
//
// Errors are *objops.ChecksumError, so writeChecksumError maps them without a
// second vocabulary.
func parseChecksumRequest(r *http.Request) (objops.ChecksumRequest, error) {
	req := objops.ChecksumRequest{
		ContentMD5: strings.TrimSpace(r.Header.Get(contentMD5Header)),
	}

	// Exactly one digest header, S3's rule. Two of them describe the same bytes
	// two ways, and honouring one while ignoring the other is the same silent
	// pass this whole file removes.
	var seen string
	for _, candidate := range checksumValueHeaders {
		value := strings.TrimSpace(r.Header.Get(candidate.header))
		if value == "" {
			continue
		}
		if seen != "" {
			return objops.ChecksumRequest{}, &objops.ChecksumError{
				Header: candidate.header,
				Kind:   objops.ErrUnknownChecksumAlgorithm,
				Detail: "expecting a single x-amz-checksum-* header, got " + seen + " and " + candidate.header,
			}
		}
		seen = candidate.header
		req.Algorithm = candidate.alg
		req.Digest = value
	}

	declared := strings.TrimSpace(r.Header.Get(sdkChecksumAlgorithmHeader))
	if declared == "" {
		declared = strings.TrimSpace(r.Header.Get(checksumAlgorithmHeader))
	}
	if declared == "" {
		return req, nil
	}

	alg, ok := objops.ParseChecksumAlgorithm(declared)
	if !ok {
		return objops.ChecksumRequest{}, &objops.ChecksumError{
			Header: sdkChecksumAlgorithmHeader,
			Kind:   objops.ErrUnknownChecksumAlgorithm,
			Detail: "unknown checksum algorithm " + declared,
		}
	}
	if req.Algorithm != "" && req.Algorithm != alg {
		// The client named one algorithm and sent another one's digest. Picking
		// either would be guessing at what it meant to verify.
		return objops.ChecksumRequest{}, &objops.ChecksumError{
			Header: sdkChecksumAlgorithmHeader,
			Kind:   objops.ErrUnknownChecksumAlgorithm,
			Detail: "declares " + declared + " but carries " + seen,
		}
	}
	req.Algorithm = alg
	return req, nil
}

// checksumVerifierFor parses the request's checksum headers and builds the
// verifier. On a bad declaration it writes the S3 error and returns false, and
// the caller must return without reading the body: refusing here is what makes
// a rejected upload leave nothing at all, not even a temp file.
func (h *Handler) checksumVerifierFor(w http.ResponseWriter, r *http.Request, resource string) (*objops.ChecksumVerifier, bool) {
	req, err := parseChecksumRequest(r)
	if err != nil {
		h.writeChecksumError(w, r, err, resource)
		return nil, false
	}
	v, err := objops.NewChecksumVerifier(req)
	if err != nil {
		h.writeChecksumError(w, r, err, resource)
		return nil, false
	}
	return v, true
}

// writeChecksumError maps a checksum failure to its S3 response. Returns true
// when it handled the error, so object handlers can chain it with mapObjopsErr.
func (h *Handler) writeChecksumError(w http.ResponseWriter, r *http.Request, err error, resource string) bool {
	var cerr *objops.ChecksumError
	if !errors.As(err, &cerr) {
		return false
	}
	switch {
	case errors.Is(err, objops.ErrBadDigest):
		writeS3Error(w, r, http.StatusBadRequest, s3ErrBadDigest,
			"The "+cerr.Header+" you specified did not match what we received", resource)
	case errors.Is(err, objops.ErrInvalidDigest):
		code := s3ErrInvalidRequest
		if cerr.Header == contentMD5Header {
			code = s3ErrInvalidDigest
		}
		writeS3Error(w, r, http.StatusBadRequest, code,
			"The "+cerr.Header+" you specified is not valid: "+cerr.Detail, resource)
	case errors.Is(err, objops.ErrUnknownChecksumAlgorithm):
		writeS3Error(w, r, http.StatusBadRequest, s3ErrInvalidRequest,
			"Invalid checksum declaration: "+cerr.Detail, resource)
	default:
		return false
	}
	return true
}

// setDeclaredChecksumHeader echoes the digest for the algorithm the client
// asked about. Without it a client that declared CRC32 would get back only a
// SHA-256 it never mentioned — true about the bytes, and an answer to a
// different question.
//
// Nothing is emitted for SHA-256: setChecksumHeader already ships it.
func setDeclaredChecksumHeader(w http.ResponseWriter, v *objops.ChecksumVerifier) {
	header, value := v.ResponseDigest()
	if header == "" {
		return
	}
	w.Header().Set(header, value)
}
