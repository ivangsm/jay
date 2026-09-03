package objops_test

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ivangsm/jay/internal/objops"
)

// The check vector every CRC specification publishes: the ASCII string
// "123456789". The expected digests below come from outside this process —
// openssl for MD5/SHA-1/SHA-256, zlib for CRC32, the reference bit-by-bit
// implementation for CRC32C, and the published CRC-64/NVME check value
// 0xae8b14860a799888 — so a wrong table here cannot agree with itself.
//
//	printf '123456789' | openssl dgst -sha256 -binary | openssl base64 -A
const checkVector = "123456789"

const (
	vecMD5       = "JfnnlDI7RTiF9RgfG2JNCw=="
	vecSHA1      = "98O8HYCOBHMq32eZZczDTKeuNEE="
	vecSHA256    = "FeKw08M4keuw8e9gnsQZQgwg4yDOlMZfvIwzEkSOsiU="
	vecCRC32     = "y/Q5Jg=="
	vecCRC32C    = "4waSgw=="
	vecCRC64NVME = "rosUhgp5mIg="
)

// vecSHA256Hex / vecMD5Hex are the same digests in the hex form jay stores and
// hands to Verify.
func vecSHA256Hex() string {
	sum := sha256.Sum256([]byte(checkVector))
	return hex.EncodeToString(sum[:])
}

func vecMD5Hex() string {
	sum := md5.Sum([]byte(checkVector))
	return hex.EncodeToString(sum[:])
}

// runVerifier feeds the check vector through a verifier the way a write path
// does: build it, wrap the body, read every byte, then verify.
func runVerifier(t *testing.T, req objops.ChecksumRequest) error {
	t.Helper()
	v, err := objops.NewChecksumVerifier(req)
	if err != nil {
		t.Fatalf("NewChecksumVerifier: %v", err)
	}
	if _, err := io.Copy(io.Discard, v.Wrap(strings.NewReader(checkVector))); err != nil {
		t.Fatalf("copy: %v", err)
	}
	return v.Verify(vecSHA256Hex(), vecMD5Hex())
}

func TestChecksumVerifier_AcceptsEveryAlgorithmS3Defines(t *testing.T) {
	cases := map[objops.ChecksumAlgorithm]string{
		objops.ChecksumCRC32:     vecCRC32,
		objops.ChecksumCRC32C:    vecCRC32C,
		objops.ChecksumCRC64NVME: vecCRC64NVME,
		objops.ChecksumSHA1:      vecSHA1,
		objops.ChecksumSHA256:    vecSHA256,
	}
	for alg, digest := range cases {
		t.Run(string(alg), func(t *testing.T) {
			if err := runVerifier(t, objops.ChecksumRequest{Algorithm: alg, Digest: digest}); err != nil {
				t.Fatalf("a correct %s digest was rejected: %v", alg, err)
			}
		})
	}
}

// A wrong digest for every algorithm has to fail. This is the assertion that
// would have caught PND-0189: before it, every one of these was a 200.
func TestChecksumVerifier_RejectsEveryWrongDigest(t *testing.T) {
	// The CRC64NVME digest, offered as if it were each algorithm's — well
	// formed base64, wrong bytes, and the right length only for its own.
	wrong := map[objops.ChecksumAlgorithm]string{
		objops.ChecksumCRC32:     "AAAAAA==",
		objops.ChecksumCRC32C:    "AAAAAA==",
		objops.ChecksumCRC64NVME: "AAAAAAAAAAA=",
		objops.ChecksumSHA1:      base64.StdEncoding.EncodeToString(make([]byte, 20)),
		objops.ChecksumSHA256:    base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	for alg, digest := range wrong {
		t.Run(string(alg), func(t *testing.T) {
			err := runVerifier(t, objops.ChecksumRequest{Algorithm: alg, Digest: digest})
			if !errors.Is(err, objops.ErrBadDigest) {
				t.Fatalf("%s: want ErrBadDigest, got %v", alg, err)
			}
		})
	}
}

func TestChecksumVerifier_ContentMD5(t *testing.T) {
	if err := runVerifier(t, objops.ChecksumRequest{ContentMD5: vecMD5}); err != nil {
		t.Fatalf("a correct Content-MD5 was rejected: %v", err)
	}

	err := runVerifier(t, objops.ChecksumRequest{ContentMD5: base64.StdEncoding.EncodeToString(make([]byte, 16))})
	if !errors.Is(err, objops.ErrBadDigest) {
		t.Fatalf("want ErrBadDigest for a wrong Content-MD5, got %v", err)
	}

	var cerr *objops.ChecksumError
	if !errors.As(err, &cerr) || cerr.Header != "Content-MD5" {
		t.Fatalf("the error must name the header the client got wrong, got %v", err)
	}
}

// Both digests are checked, not just the first one that happens to be present.
func TestChecksumVerifier_ChecksMD5AndAlgorithmTogether(t *testing.T) {
	err := runVerifier(t, objops.ChecksumRequest{
		ContentMD5: vecMD5, // correct
		Algorithm:  objops.ChecksumSHA256,
		Digest:     base64.StdEncoding.EncodeToString(make([]byte, 32)), // wrong
	})
	if !errors.Is(err, objops.ErrBadDigest) {
		t.Fatalf("a correct Content-MD5 must not excuse a wrong x-amz-checksum-sha256, got %v", err)
	}
}

func TestNewChecksumVerifier_RefusesMalformedDeclarations(t *testing.T) {
	cases := map[string]struct {
		req  objops.ChecksumRequest
		kind error
	}{
		"Content-MD5 is not base64": {
			objops.ChecksumRequest{ContentMD5: "not base64 at all!!"}, objops.ErrInvalidDigest,
		},
		"Content-MD5 is the wrong length": {
			objops.ChecksumRequest{ContentMD5: "AAAA"}, objops.ErrInvalidDigest,
		},
		"digest is hex instead of base64": {
			objops.ChecksumRequest{Algorithm: objops.ChecksumSHA256, Digest: vecSHA256Hex()},
			objops.ErrInvalidDigest,
		},
		"digest is the wrong length for its algorithm": {
			objops.ChecksumRequest{Algorithm: objops.ChecksumSHA256, Digest: vecCRC32},
			objops.ErrInvalidDigest,
		},
		"unknown algorithm": {
			objops.ChecksumRequest{Algorithm: "SHA512", Digest: vecSHA256},
			objops.ErrUnknownChecksumAlgorithm,
		},
		"digest without an algorithm": {
			objops.ChecksumRequest{Digest: vecSHA256}, objops.ErrUnknownChecksumAlgorithm,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			v, err := objops.NewChecksumVerifier(tc.req)
			if !errors.Is(err, tc.kind) {
				t.Fatalf("want %v, got %v", tc.kind, err)
			}
			if v != nil {
				t.Fatal("a refused declaration must not yield a verifier")
			}
		})
	}
}

func TestParseChecksumAlgorithm(t *testing.T) {
	// Case-insensitive: the value is a literal clients type.
	for _, in := range []string{"CRC64NVME", "crc64nvme", " Crc64Nvme "} {
		if alg, ok := objops.ParseChecksumAlgorithm(in); !ok || alg != objops.ChecksumCRC64NVME {
			t.Fatalf("ParseChecksumAlgorithm(%q) = %q, %v", in, alg, ok)
		}
	}
	for _, in := range []string{"", "SHA512", "MD5", "XXHASH64"} {
		if _, ok := objops.ParseChecksumAlgorithm(in); ok {
			t.Fatalf("ParseChecksumAlgorithm(%q) must not be accepted", in)
		}
	}
}

// The nil verifier is what the native protocol passes: it has no client-declared
// digest, and it must keep working without a nil check at every call site.
func TestChecksumVerifier_NilIsANoOp(t *testing.T) {
	var v *objops.ChecksumVerifier
	body := v.Wrap(strings.NewReader(checkVector))
	got, err := io.ReadAll(body)
	if err != nil || string(got) != checkVector {
		t.Fatalf("Wrap on a nil verifier changed the body: %q, %v", got, err)
	}
	if err := v.Verify(vecSHA256Hex(), vecMD5Hex()); err != nil {
		t.Fatalf("Verify on a nil verifier: %v", err)
	}
	if h, val := v.ResponseDigest(); h != "" || val != "" {
		t.Fatalf("ResponseDigest on a nil verifier = %q %q", h, val)
	}
}

// The point of ResponseDigest: a client that declared CRC32 gets its CRC32 back,
// not a SHA-256 it never mentioned.
func TestChecksumVerifier_ResponseDigestAnswersTheAlgorithmAsked(t *testing.T) {
	v, err := objops.NewChecksumVerifier(objops.ChecksumRequest{Algorithm: objops.ChecksumCRC32C})
	if err != nil {
		t.Fatalf("NewChecksumVerifier: %v", err)
	}
	if _, err := io.Copy(io.Discard, v.Wrap(strings.NewReader(checkVector))); err != nil {
		t.Fatalf("copy: %v", err)
	}
	header, value := v.ResponseDigest()
	if header != "x-amz-checksum-crc32c" || value != vecCRC32C {
		t.Fatalf("ResponseDigest = %q: %q, want x-amz-checksum-crc32c: %q", header, value, vecCRC32C)
	}

	// SHA-256 is the exception: setChecksumHeader already ships it, so this
	// must stay silent rather than emit the same header twice.
	v256, err := objops.NewChecksumVerifier(objops.ChecksumRequest{Algorithm: objops.ChecksumSHA256})
	if err != nil {
		t.Fatalf("NewChecksumVerifier: %v", err)
	}
	if header, _ := v256.ResponseDigest(); header != "" {
		t.Fatalf("ResponseDigest for SHA-256 = %q, want none", header)
	}
}

// An algorithm named with no digest cannot fail verification — there is nothing
// to compare — but it must still be computed so the response can carry it.
func TestChecksumVerifier_AlgorithmWithoutDigestVerifiesNothing(t *testing.T) {
	if err := runVerifier(t, objops.ChecksumRequest{Algorithm: objops.ChecksumCRC32}); err != nil {
		t.Fatalf("declaring an algorithm with no digest must not fail: %v", err)
	}
}
