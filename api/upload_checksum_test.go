package api

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivangsm/jay/meta"
)

// These tests assert the two halves of PND-0189 together, and the second half
// is the one that is easy to get wrong: the status code AND the absence of
// bytes. A test that only checked for 400 would have stayed green with the
// object already written and metadata already committed.

// helloWorldCRC64NVMEBase64 is the CRC-64/NVME of "hello world" as the AWS CLI
// computes it — the algorithm it declares on every upload it makes.
const helloWorldCRC64NVMEBase64 = "jSnVw/bqjr4="

// storedFiles lists every regular file under the store's bucket tree. The
// comparison is before/after, so a leftover temp or a renamed object shows up
// as a difference rather than having to be predicted by name.
func storedFiles(t *testing.T, h *Handler) []string {
	t.Helper()
	root := h.store.DataDir()
	var out []string
	for _, sub := range []string{"buckets", "tmp", "multipart"} {
		dir := filepath.Join(root, sub)
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if !info.IsDir() {
				rel, rerr := filepath.Rel(root, path)
				if rerr != nil {
					return rerr
				}
				out = append(out, rel)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return out
}

// assertNothingWritten fails if the store gained a file, and says which.
func assertNothingWritten(t *testing.T, h *Handler, before []string) {
	t.Helper()
	after := storedFiles(t, h)
	if len(after) == len(before) {
		return
	}
	seen := make(map[string]bool, len(before))
	for _, f := range before {
		seen[f] = true
	}
	var added []string
	for _, f := range after {
		if !seen[f] {
			added = append(added, f)
		}
	}
	t.Fatalf("a refused upload left %d file(s) behind: %v", len(added), added)
}

// putWithHeaders issues a PUT with arbitrary extra headers.
func putWithHeaders(t *testing.T, h *Handler, tok *meta.Token, secret, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
	req.Header.Set("Authorization", authHeader(tok, secret))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// objectAbsent asserts the key is not readable — the second half of the check.
func objectAbsent(t *testing.T, h *Handler, tok *meta.Token, secret, bucket, key string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("the object was refused but GET answers %d: %s", w.Code, w.Body.String())
	}
}

// wrongDigests are well-formed base64 of the right length for each algorithm,
// and describe bytes nobody sent.
var wrongDigests = map[string]string{
	"x-amz-checksum-crc32":     "AAAAAA==",
	"x-amz-checksum-crc32c":    "AAAAAA==",
	"x-amz-checksum-crc64nvme": "AAAAAAAAAAA=",
	"x-amz-checksum-sha1":      base64.StdEncoding.EncodeToString(make([]byte, 20)),
	"x-amz-checksum-sha256":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
	"Content-MD5":              base64.StdEncoding.EncodeToString(make([]byte, 16)),
}

func TestPutObject_WrongChecksumIsRefusedAndWritesNothing(t *testing.T) {
	for header, digest := range wrongDigests {
		t.Run(header, func(t *testing.T) {
			h, db, tok, secret := fullSetupTestHandler(t)
			createBucketForTest(t, db, tok.AccountID, "digest-bucket")
			before := storedFiles(t, h)

			w := putWithHeaders(t, h, tok, secret, "/digest-bucket/k.txt", "hello world",
				map[string]string{header: digest})

			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), s3ErrBadDigest) {
				t.Fatalf("want %s in the body, got %s", s3ErrBadDigest, w.Body.String())
			}
			objectAbsent(t, h, tok, secret, "digest-bucket", "k.txt")
			assertNothingWritten(t, h, before)
		})
	}
}

func TestPutObject_CorrectChecksumIsAccepted(t *testing.T) {
	// The digests of "hello world", every one of them read off the wire from
	// the AWS CLI (aws s3api put-object --checksum-algorithm X --debug), not
	// produced by the code under test. That is what makes this an
	// interoperability assertion rather than jay agreeing with itself.
	cases := map[string]string{
		"x-amz-checksum-crc32":     "DUoRhQ==",
		"x-amz-checksum-crc32c":    "yZRlqg==",
		"x-amz-checksum-crc64nvme": helloWorldCRC64NVMEBase64,
		"x-amz-checksum-sha1":      "Kq5sNclPz7QV2+lfQIuc6R7oRu0=",
		"x-amz-checksum-sha256":    helloWorldSHA256Base64,
	}
	for header, digest := range cases {
		t.Run(header, func(t *testing.T) {
			h, db, tok, secret := fullSetupTestHandler(t)
			createBucketForTest(t, db, tok.AccountID, "ok-bucket")

			w := putWithHeaders(t, h, tok, secret, "/ok-bucket/k.txt", "hello world",
				map[string]string{header: digest})
			if w.Code != http.StatusOK {
				t.Fatalf("a correct %s was refused: %d %s", header, w.Code, w.Body.String())
			}
			// The response answers the algorithm that was asked about.
			if header != "x-amz-checksum-sha256" {
				if got := w.Header().Get(header); got != digest {
					t.Fatalf("response %s = %q, want %q", header, got, digest)
				}
			}
		})
	}
}

func TestPutObject_CorrectContentMD5IsAccepted(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "md5-bucket")

	sum := md5.Sum([]byte("hello world"))
	w := putWithHeaders(t, h, tok, secret, "/md5-bucket/k.txt", "hello world",
		map[string]string{"Content-MD5": base64.StdEncoding.EncodeToString(sum[:])})
	if w.Code != http.StatusOK {
		t.Fatalf("a correct Content-MD5 was refused: %d %s", w.Code, w.Body.String())
	}
}

func TestPutObject_MalformedDeclarationIsRefusedBeforeTheBody(t *testing.T) {
	cases := map[string]struct {
		headers map[string]string
		code    string
	}{
		"Content-MD5 is not base64": {
			map[string]string{"Content-MD5": "!!!not base64!!!"}, s3ErrInvalidDigest,
		},
		"checksum is hex instead of base64": {
			map[string]string{"x-amz-checksum-sha256": helloWorldSHA256Hex}, s3ErrInvalidRequest,
		},
		"unknown algorithm": {
			map[string]string{"x-amz-sdk-checksum-algorithm": "SHA512"}, s3ErrInvalidRequest,
		},
		"two digest headers": {
			map[string]string{
				"x-amz-checksum-crc32":  "DUoRhQ==",
				"x-amz-checksum-sha256": helloWorldSHA256Base64,
			}, s3ErrInvalidRequest,
		},
		"algorithm disagrees with the digest sent": {
			map[string]string{
				"x-amz-sdk-checksum-algorithm": "CRC32",
				"x-amz-checksum-sha256":        helloWorldSHA256Base64,
			}, s3ErrInvalidRequest,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h, db, tok, secret := fullSetupTestHandler(t)
			createBucketForTest(t, db, tok.AccountID, "bad-decl-bucket")
			before := storedFiles(t, h)

			w := putWithHeaders(t, h, tok, secret, "/bad-decl-bucket/k.txt", "hello world", tc.headers)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.code) {
				t.Fatalf("want %s, got %s", tc.code, w.Body.String())
			}
			objectAbsent(t, h, tok, secret, "bad-decl-bucket", "k.txt")
			assertNothingWritten(t, h, before)
		})
	}
}

// ── multipart ─────────────────────────────────────────────────────────────

// beginUpload creates a multipart upload with arbitrary extra headers and
// returns its id. (list_uploads_handler_test.go has a headerless startUpload.)
func beginUpload(t *testing.T, h *Handler, tok *meta.Token, secret, bucket, key string, headers map[string]string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/"+bucket+"/"+key+"?uploads", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create multipart upload: %d %s", w.Code, w.Body.String())
	}
	var res InitiateMultipartUploadResult
	if err := xml.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode InitiateMultipartUploadResult: %v", err)
	}
	return res.UploadID
}

func TestUploadPart_WrongChecksumIsRefusedAndWritesNothing(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "mp-bucket")
	uploadID := beginUpload(t, h, tok, secret, "mp-bucket", "big.bin", nil)

	before := storedFiles(t, h)
	path := fmt.Sprintf("/mp-bucket/big.bin?uploadId=%s&partNumber=1", uploadID)
	w := putWithHeaders(t, h, tok, secret, path, "hello world",
		map[string]string{"x-amz-checksum-crc64nvme": "AAAAAAAAAAA="})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), s3ErrBadDigest) {
		t.Fatalf("want %s, got %s", s3ErrBadDigest, w.Body.String())
	}
	assertNothingWritten(t, h, before)

	upload, err := h.db.GetMultipartUpload(uploadID)
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	if len(upload.Parts) != 0 {
		t.Fatalf("a refused part was registered anyway: %+v", upload.Parts)
	}
}

// A retry of a part that was already accepted must not destroy it when the
// retry is refused: the part path is derived from the part number, so a
// post-rename cleanup would have unlinked the good bytes while the metadata
// still pointed at them.
func TestUploadPart_RefusedRetryLeavesTheAcceptedPartIntact(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "mp-retry")
	uploadID := beginUpload(t, h, tok, secret, "mp-retry", "big.bin", nil)
	path := fmt.Sprintf("/mp-retry/big.bin?uploadId=%s&partNumber=1", uploadID)

	if w := putWithHeaders(t, h, tok, secret, path, "hello world", nil); w.Code != http.StatusOK {
		t.Fatalf("first part: %d %s", w.Code, w.Body.String())
	}
	upload, err := h.db.GetMultipartUpload(uploadID)
	if err != nil || len(upload.Parts) != 1 {
		t.Fatalf("part 1 should be registered: %v %+v", err, upload)
	}
	partPath := filepath.Join(h.store.DataDir(), upload.Parts[0].LocationRef)
	original, err := os.ReadFile(partPath)
	if err != nil {
		t.Fatalf("read part: %v", err)
	}

	w := putWithHeaders(t, h, tok, secret, path, "corrupted bytes",
		map[string]string{"x-amz-checksum-crc32": "AAAAAA=="})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for the retry, got %d: %s", w.Code, w.Body.String())
	}

	after, err := os.ReadFile(partPath)
	if err != nil {
		t.Fatalf("the accepted part was destroyed by a refused retry: %v", err)
	}
	if string(after) != string(original) {
		t.Fatalf("the accepted part was overwritten: %q, want %q", after, original)
	}
}

func TestUploadPart_CorrectChecksumIsAccepted(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "mp-ok")
	uploadID := beginUpload(t, h, tok, secret, "mp-ok", "big.bin",
		map[string]string{"x-amz-checksum-algorithm": "CRC64NVME"})

	path := fmt.Sprintf("/mp-ok/big.bin?uploadId=%s&partNumber=1", uploadID)
	w := putWithHeaders(t, h, tok, secret, path, "hello world",
		map[string]string{"x-amz-checksum-crc64nvme": helloWorldCRC64NVMEBase64})
	if w.Code != http.StatusOK {
		t.Fatalf("a correct part checksum was refused: %d %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("x-amz-checksum-crc64nvme"); got != helloWorldCRC64NVMEBase64 {
		t.Fatalf("part response checksum = %q", got)
	}
}

func TestCreateMultipartUpload_RefusesAnAlgorithmJayCannotCompute(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "mp-alg")

	req := httptest.NewRequest(http.MethodPost, "/mp-alg/k.bin?uploads", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	req.Header.Set("x-amz-checksum-algorithm", "SHA512")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), s3ErrInvalidRequest) {
		t.Fatalf("want %s, got %s", s3ErrInvalidRequest, w.Body.String())
	}
}

// A whole-object checksum on Complete is not verified, so it is refused rather
// than accepted and ignored.
func TestCompleteMultipartUpload_RefusesADeclaredObjectChecksum(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "mp-complete")
	uploadID := beginUpload(t, h, tok, secret, "mp-complete", "k.bin", nil)

	partPath := fmt.Sprintf("/mp-complete/k.bin?uploadId=%s&partNumber=1", uploadID)
	if w := putWithHeaders(t, h, tok, secret, partPath, "hello world", nil); w.Code != http.StatusOK {
		t.Fatalf("upload part: %d %s", w.Code, w.Body.String())
	}

	body := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>`
	req := httptest.NewRequest(http.MethodPost, "/mp-complete/k.bin?uploadId="+uploadID, strings.NewReader(body))
	req.Header.Set("Authorization", authHeader(tok, secret))
	req.Header.Set("x-amz-checksum-crc64nvme", helloWorldCRC64NVMEBase64)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("want 501, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), S3ErrNotImplemented) {
		t.Fatalf("want %s, got %s", S3ErrNotImplemented, w.Body.String())
	}
}
