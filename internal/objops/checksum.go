package objops

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"strings"
)

// Errors a client-declared checksum can produce. They are sentinels so both
// transports can map them without importing the concrete error type.
var (
	// ErrBadDigest: the client declared a digest and the bytes that arrived
	// hash to a different one. S3 answers 400 BadDigest.
	ErrBadDigest = errors.New("objops: declared checksum does not match the bytes received")
	// ErrInvalidDigest: the declared value is not a well-formed digest for its
	// algorithm — bad base64, or the wrong number of bytes. S3 answers 400
	// InvalidDigest for Content-MD5 and 400 InvalidRequest for x-amz-checksum-*.
	ErrInvalidDigest = errors.New("objops: declared checksum is not a well-formed digest")
	// ErrUnknownChecksumAlgorithm: the algorithm header named something that is
	// not one of the five S3 defines for object payloads. S3 answers 400
	// InvalidRequest.
	ErrUnknownChecksumAlgorithm = errors.New("objops: unknown checksum algorithm")
)

// ChecksumError carries which header was wrong along with the sentinel, so the
// message the client reads names the header it has to fix. Unwrap is what makes
// errors.Is(err, ErrBadDigest) work.
type ChecksumError struct {
	// Header is the request header that carried the offending value.
	Header string
	// Kind is one of ErrBadDigest / ErrInvalidDigest / ErrUnknownChecksumAlgorithm.
	Kind error
	// Detail is a short human-readable reason, safe to echo back.
	Detail string
}

// Error implements error.
func (e *ChecksumError) Error() string {
	return fmt.Sprintf("objops: %s: %s", e.Header, e.Detail)
}

// Unwrap exposes the sentinel so callers compare with errors.Is.
func (e *ChecksumError) Unwrap() error { return e.Kind }

// ChecksumAlgorithm names one of the digests a client may declare on an upload.
//
// The set is closed and complete: these five are every algorithm S3 defines for
// object payloads, and jay computes all five. That is deliberate — the
// alternative (accepting an algorithm and answering with a SHA-256 nobody asked
// for) is the defect this file exists to remove, and answering 501 instead
// would break the reference client, which declares CRC64NVME on every single
// upload it makes.
type ChecksumAlgorithm string

// The algorithms S3 defines for object checksums.
const (
	ChecksumCRC32     ChecksumAlgorithm = "CRC32"
	ChecksumCRC32C    ChecksumAlgorithm = "CRC32C"
	ChecksumCRC64NVME ChecksumAlgorithm = "CRC64NVME"
	ChecksumSHA1      ChecksumAlgorithm = "SHA1"
	ChecksumSHA256    ChecksumAlgorithm = "SHA256"
)

// crc64NVMEPoly is the CRC-64/NVME polynomial in the bit-reversed form
// hash/crc64 expects (0xad93d23594c93659 reflected). Go's crc64 pre- and
// post-complements the register, which is exactly the init/xorout this
// algorithm specifies, so crc64.New(table) alone produces the AWS value.
// Pinned by a test against the standard check vector "123456789" →
// 0xae8b14860a799888, and measured against what the AWS CLI puts on the wire.
const crc64NVMEPoly = 0x9a6c9329ac4bc9b5

// crc32cTable and crc64NVMETable are built once: crc32.MakeTable picks the
// hardware-accelerated implementation on arm64 and amd64.
var (
	crc32cTable    = crc32.MakeTable(crc32.Castagnoli)
	crc64NVMETable = crc64.MakeTable(crc64NVMEPoly)
)

// digestSize returns the raw digest length of the algorithm in bytes, and
// whether the algorithm is one jay knows.
func (a ChecksumAlgorithm) digestSize() (int, bool) {
	switch a {
	case ChecksumCRC32, ChecksumCRC32C:
		return crc32.Size, true
	case ChecksumCRC64NVME:
		return crc64.Size, true
	case ChecksumSHA1:
		return sha1.Size, true
	case ChecksumSHA256:
		return sha256.Size, true
	default:
		return 0, false
	}
}

// Header returns the request/response header S3 defines for this algorithm's
// digest, e.g. "x-amz-checksum-crc64nvme".
func (a ChecksumAlgorithm) Header() string {
	return checksumHeaderPrefix + strings.ToLower(string(a))
}

// newHash builds the hasher for the algorithm. SHA-256 returns nil: the write
// path already computes it, and hashing the same bytes twice would be work
// nobody asked for.
//
// MD5 and SHA-1 are not a security choice here — they are the digests S3
// defines for these headers, compared against a value the client sent in the
// clear in the same request.
func (a ChecksumAlgorithm) newHash() hash.Hash {
	switch a {
	case ChecksumCRC32:
		return crc32.NewIEEE()
	case ChecksumCRC32C:
		return crc32.New(crc32cTable)
	case ChecksumCRC64NVME:
		return crc64.New(crc64NVMETable)
	case ChecksumSHA1:
		// Semgrep's weak-crypto rule flags this, and it is right about SHA-1 in
		// general and wrong about it here: S3 defines x-amz-checksum-sha1 as
		// SHA-1, so the only way to "fix" it would be to answer a different
		// algorithm than the client asked for. No nolint directive: gosec is
		// not in the lint gate, and a directive that suppresses nothing is
		// worse than the comment that explains why.
		return sha1.New()
	case ChecksumSHA256, "":
		return nil
	default:
		return nil
	}
}

// checksumHeaderPrefix is the common prefix of every S3 checksum value header.
const checksumHeaderPrefix = "x-amz-checksum-"

// contentMD5Header is the header S3 inherited from RFC 1864.
const contentMD5Header = "Content-MD5"

// ParseChecksumAlgorithm maps the literal a client puts in
// x-amz-sdk-checksum-algorithm (or x-amz-checksum-algorithm) to an algorithm.
// Matching is case-insensitive: the value is typed by clients, and S3 accepts
// it in any case.
func ParseChecksumAlgorithm(s string) (ChecksumAlgorithm, bool) {
	alg := ChecksumAlgorithm(strings.ToUpper(strings.TrimSpace(s)))
	if _, ok := alg.digestSize(); !ok {
		return "", false
	}
	return alg, true
}

// ChecksumRequest is what a client asked jay to verify about the bytes of one
// upload. A zero value asks for nothing, and asking for nothing is the only way
// an upload is accepted without its integrity being checked.
type ChecksumRequest struct {
	// ContentMD5 is the base64 MD5 from the Content-MD5 header, empty if absent.
	ContentMD5 string
	// Algorithm is the algorithm the client declared, empty if it declared none.
	Algorithm ChecksumAlgorithm
	// Digest is the base64 digest for Algorithm. It can be empty while
	// Algorithm is set: some clients name the algorithm and let the server
	// compute it, which jay honours by echoing the value back.
	Digest string
}

// Empty reports whether the request declared nothing at all.
func (c ChecksumRequest) Empty() bool {
	return c.ContentMD5 == "" && c.Algorithm == "" && c.Digest == ""
}

// ChecksumVerifier computes the digests a client asked jay to check, in the
// same single pass that writes the bytes to disk — the body is never buffered
// and never read twice.
//
// The lifecycle is: build it BEFORE reading a byte (so a malformed declaration
// is refused without opening a temp file), wrap the body with Wrap, and call
// Verify from the store's pre-rename hook, so a mismatch aborts the write while
// the bytes are still a temp file that nothing references.
//
// A nil *ChecksumVerifier is valid and verifies nothing: that is what the
// native protocol passes, since it carries no client-declared digest.
type ChecksumVerifier struct {
	req ChecksumRequest
	// extra is the hasher for req.Algorithm, nil when the algorithm is SHA-256
	// (the store already produces it) or when no algorithm was declared.
	extra hash.Hash
}

// NewChecksumVerifier validates the declaration itself and builds the hasher it
// needs. It returns a *ChecksumError wrapping ErrInvalidDigest or
// ErrUnknownChecksumAlgorithm when the client's own headers are malformed —
// which is why it must be called before any byte of the body is read.
func NewChecksumVerifier(req ChecksumRequest) (*ChecksumVerifier, error) {
	if req.ContentMD5 != "" {
		if err := checkDigestShape(contentMD5Header, req.ContentMD5, md5.Size); err != nil {
			return nil, err
		}
	}

	if req.Algorithm != "" {
		size, ok := req.Algorithm.digestSize()
		if !ok {
			return nil, &ChecksumError{
				Header: "x-amz-sdk-checksum-algorithm",
				Kind:   ErrUnknownChecksumAlgorithm,
				Detail: fmt.Sprintf("%q is not a checksum algorithm S3 defines for objects", string(req.Algorithm)),
			}
		}
		if req.Digest != "" {
			if err := checkDigestShape(req.Algorithm.Header(), req.Digest, size); err != nil {
				return nil, err
			}
		}
	} else if req.Digest != "" {
		// Unreachable through the HTTP parser, which always sets both. Guarded
		// anyway: a digest with no algorithm cannot be checked against
		// anything, and accepting it would be the silent pass this file removes.
		return nil, &ChecksumError{
			Header: checksumHeaderPrefix + "*",
			Kind:   ErrUnknownChecksumAlgorithm,
			Detail: "a checksum was declared without an algorithm",
		}
	}

	return &ChecksumVerifier{req: req, extra: req.Algorithm.newHash()}, nil
}

// checkDigestShape decodes a declared digest and checks its length.
func checkDigestShape(header, value string, want int) error {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return &ChecksumError{Header: header, Kind: ErrInvalidDigest, Detail: "value is not valid base64"}
	}
	if len(raw) != want {
		return &ChecksumError{
			Header: header,
			Kind:   ErrInvalidDigest,
			Detail: fmt.Sprintf("digest is %d bytes, expected %d", len(raw), want),
		}
	}
	return nil
}

// Wrap returns a reader that feeds everything read from r into the extra
// hasher. When there is nothing extra to compute it returns r untouched, so the
// common path pays nothing.
func (v *ChecksumVerifier) Wrap(r io.Reader) io.Reader {
	if v == nil || v.extra == nil {
		return r
	}
	return io.TeeReader(r, v.extra)
}

// Verify compares every digest the client declared against the ones computed
// over the bytes that actually arrived. sha256Hex and md5Hex are the digests
// the write path produces on its own (the object checksum and the ETag), passed
// in hex because that is how jay stores them.
//
// Returns a *ChecksumError wrapping ErrBadDigest on the first mismatch.
func (v *ChecksumVerifier) Verify(sha256Hex, md5Hex string) error {
	if v == nil || v.req.Empty() {
		return nil
	}

	if v.req.ContentMD5 != "" {
		if err := compareDigest(contentMD5Header, v.req.ContentMD5, hexToBase64(md5Hex)); err != nil {
			return err
		}
	}

	if v.req.Digest == "" {
		return nil
	}
	got := v.computed(sha256Hex)
	return compareDigest(v.req.Algorithm.Header(), v.req.Digest, got)
}

// computed returns the base64 digest for the declared algorithm.
func (v *ChecksumVerifier) computed(sha256Hex string) string {
	if v.extra == nil {
		// SHA-256: the store already hashed the bytes on the way to disk.
		return hexToBase64(sha256Hex)
	}
	return base64.StdEncoding.EncodeToString(v.extra.Sum(nil))
}

// ResponseDigest returns the header and value jay should echo so the client can
// see the digest for the algorithm IT asked about, rather than a SHA-256 it did
// not request. Both are empty when no algorithm was declared, or when the
// algorithm is SHA-256 — that one already ships as x-amz-checksum-sha256.
//
// Only valid once the body has been fully read.
func (v *ChecksumVerifier) ResponseDigest() (header, value string) {
	if v == nil || v.extra == nil {
		return "", ""
	}
	return v.req.Algorithm.Header(), base64.StdEncoding.EncodeToString(v.extra.Sum(nil))
}

// compareDigest reports a mismatch as a *ChecksumError. The comparison is on
// the base64 text, which is canonical for a fixed-length digest.
func compareDigest(header, declared, got string) error {
	if declared == got {
		return nil
	}
	return &ChecksumError{
		Header: header,
		Kind:   ErrBadDigest,
		Detail: fmt.Sprintf("declared %s, received %s", declared, got),
	}
}

// hexToBase64 re-encodes an internally stored hex digest as the base64 S3
// speaks. An unparsable input yields "", which can only ever fail a comparison.
func hexToBase64(hexDigest string) string {
	raw, err := hex.DecodeString(hexDigest)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}
