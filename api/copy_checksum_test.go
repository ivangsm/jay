package api

// PND-0194: `aws s3api copy-object --checksum-algorithm CRC32` answered 200 and
// returned no checksum at all. The header reached the server, jay computed
// nothing, and the response said the request had been served.
//
// Nothing here asserts a status code on its own. The check is the VALUE of the
// digest in the response body, against numbers this file does not get from jay:
// the four CRC/SHA check values below are the published ones for the string
// "123456789", so a jay that hashed the wrong bytes — or hex where S3 wants
// base64 — fails even though it answered 200 with something checksum-shaped.

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ivangsm/jay/meta"
)

// checkVectorBody is the canonical CRC check string. Every expected digest
// below is its published value, not one jay produced.
const checkVectorBody = "123456789"

// base64BE renders an unsigned digest of n bytes the way S3 does: raw
// big-endian bytes, base64.
func base64BE(value uint64, size int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], value)
	return base64.StdEncoding.EncodeToString(buf[8-size:])
}

// base64Hex does the same for a digest published in hex. The conversion happens
// here rather than in the expectation so the literal below stays the number
// anyone can look up.
func base64Hex(hexDigest string) string {
	raw, err := hex.DecodeString(hexDigest)
	if err != nil {
		panic("test vector is not hex: " + hexDigest)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// Published check values for "123456789".
var (
	// CRC-32/ISO-HDLC (what S3 calls CRC32).
	wantCRC32 = base64BE(0xcbf43926, 4)
	// CRC-32/ISCSI, Castagnoli (CRC32C).
	wantCRC32C = base64BE(0xe3069283, 4)
	// CRC-64/NVME.
	wantCRC64NVME = base64BE(0xae8b14860a799888, 8)
	// SHA-1 and SHA-256 of "123456789".
	wantSHA1   = base64Hex("f7c3bc1d808e04732adf679965ccc34ca7ae3441")
	wantSHA256 = base64Hex("15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225")
)

// copyWithChecksum issues a CopyObject carrying the given algorithm header.
func copyWithChecksum(t *testing.T, h *Handler, tok *meta.Token, secret, header, algorithm, source, dstBucket, dstKey string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/"+dstBucket+"/"+dstKey, nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	req.Header.Set("x-amz-copy-source", source)
	if algorithm != "" {
		req.Header.Set(header, algorithm)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// decodeCopyResult parses <CopyObjectResult> or fails.
func decodeCopyResult(t *testing.T, body string) CopyObjectResult {
	t.Helper()
	var result CopyObjectResult
	if err := xml.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("response is not a CopyObjectResult: %v (%q)", err, body)
	}
	return result
}

// copyChecksumFixture is one source object holding the check vector, plus an
// empty destination bucket.
func copyChecksumFixture(t *testing.T) (*Handler, *meta.DB, *meta.Token, string) {
	t.Helper()
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "cks-src")
	createBucketForTest(t, db, tok.AccountID, "cks-dst")
	putObjectForTest(t, h, tok, secret, "cks-src", "vector.txt", checkVectorBody)
	return h, db, tok, secret
}

func TestCopyObject_ReturnsTheChecksumThatWasAskedFor(t *testing.T) {
	cases := []struct {
		algorithm string
		want      string
		element   func(CopyObjectResult) string
	}{
		{"CRC32", wantCRC32, func(r CopyObjectResult) string { return r.ChecksumCRC32 }},
		{"CRC32C", wantCRC32C, func(r CopyObjectResult) string { return r.ChecksumCRC32C }},
		{"CRC64NVME", wantCRC64NVME, func(r CopyObjectResult) string { return r.ChecksumCRC64NVME }},
		{"SHA1", wantSHA1, func(r CopyObjectResult) string { return r.ChecksumSHA1 }},
		{"SHA256", wantSHA256, func(r CopyObjectResult) string { return r.ChecksumSHA256 }},
	}

	for _, tc := range cases {
		t.Run(tc.algorithm, func(t *testing.T) {
			h, db, tok, secret := copyChecksumFixture(t)

			w := copyWithChecksum(t, h, tok, secret, checksumAlgorithmHeader, tc.algorithm,
				"/cks-src/vector.txt", "cks-dst", "copy.txt")
			if w.Code != http.StatusOK {
				t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
			}

			result := decodeCopyResult(t, w.Body.String())
			got := tc.element(result)
			if got == "" {
				t.Fatalf("%s was requested and the response carries no digest for it: %s",
					tc.algorithm, w.Body.String())
			}
			if got != tc.want {
				t.Fatalf("%s = %q, want %q (the published check value for %q)",
					tc.algorithm, got, tc.want, checkVectorBody)
			}

			// And the copy itself still happened, with the bytes it was given.
			dst, err := db.GetBucket("cks-dst")
			if err != nil {
				t.Fatalf("dst bucket: %v", err)
			}
			obj, err := db.GetObjectMeta(dst.ID, "copy.txt")
			if err != nil {
				t.Fatalf("the copy is missing: %v", err)
			}
			if obj.SizeBytes != int64(len(checkVectorBody)) {
				t.Fatalf("copied size = %d, want %d", obj.SizeBytes, len(checkVectorBody))
			}
			code, body := getObjectBody(t, h, authHeader(tok, secret), "cks-dst", "copy.txt")
			if code != http.StatusOK || body != checkVectorBody {
				t.Fatalf("reading the copy gave (%d, %q), want (200, %q)", code, body, checkVectorBody)
			}
		})
	}
}

// The SDK spelling is what boto3 and the Go SDK send; the plain one is what the
// AWS CLI puts on a copy-object. Both have to reach the same code.
func TestCopyObject_SdkAlgorithmHeaderIsHonouredToo(t *testing.T) {
	h, _, tok, secret := copyChecksumFixture(t)

	w := copyWithChecksum(t, h, tok, secret, sdkChecksumAlgorithmHeader, "CRC32",
		"/cks-src/vector.txt", "cks-dst", "copy.txt")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := decodeCopyResult(t, w.Body.String()).ChecksumCRC32; got != wantCRC32 {
		t.Fatalf("ChecksumCRC32 = %q, want %q", got, wantCRC32)
	}
}

// Case-insensitive, because the value is typed by hand and S3 accepts any case.
func TestCopyObject_AlgorithmIsCaseInsensitive(t *testing.T) {
	h, _, tok, secret := copyChecksumFixture(t)

	w := copyWithChecksum(t, h, tok, secret, checksumAlgorithmHeader, "crc32c",
		"/cks-src/vector.txt", "cks-dst", "copy.txt")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := decodeCopyResult(t, w.Body.String()).ChecksumCRC32C; got != wantCRC32C {
		t.Fatalf("ChecksumCRC32C = %q, want %q", got, wantCRC32C)
	}
}

func TestCopyObject_UnknownAlgorithmIsRefusedAndNothingIsWritten(t *testing.T) {
	h, db, tok, secret := copyChecksumFixture(t)

	w := copyWithChecksum(t, h, tok, secret, checksumAlgorithmHeader, "SHA512",
		"/cks-src/vector.txt", "cks-dst", "copy.txt")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), s3ErrInvalidRequest) {
		t.Fatalf("want %s in the error document, got %s", s3ErrInvalidRequest, w.Body.String())
	}

	// Refused before a byte is copied: the destination key must not exist.
	dst, err := db.GetBucket("cks-dst")
	if err != nil {
		t.Fatalf("dst bucket: %v", err)
	}
	if _, err := db.GetObjectMeta(dst.ID, "copy.txt"); err == nil {
		t.Fatal("the copy was written even though the checksum declaration was refused")
	}
}

func TestCopyObject_WithoutTheHeaderReturnsNoChecksum(t *testing.T) {
	h, _, tok, secret := copyChecksumFixture(t)

	w := copyRequest(t, h, tok, secret, "/cks-src/vector.txt", "cks-dst", "copy.txt")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	result := decodeCopyResult(t, w.Body.String())
	if result.ChecksumCRC32 != "" || result.ChecksumCRC32C != "" || result.ChecksumCRC64NVME != "" ||
		result.ChecksumSHA1 != "" || result.ChecksumSHA256 != "" {
		t.Fatalf("a copy that asked for no checksum came back with one: %s", w.Body.String())
	}
	if result.ETag == "" {
		t.Fatalf("the default path lost its ETag: %s", w.Body.String())
	}
}
