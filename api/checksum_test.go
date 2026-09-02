package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ivangsm/jay/meta"
)

// helloWorldSHA256Base64 is the SHA-256 of "hello world" (11 bytes), raw digest
// in base64 — the encoding S3 defines for x-amz-checksum-*.
//
// It is written out as a literal on purpose. A test that put an object and then
// read the header back through jay's own code would stay green with the digest
// hex-encoded, because both ends would share the mistake. This value comes from
// outside the process:
//
//	printf 'hello world' | openssl dgst -sha256 -binary | base64
const helloWorldSHA256Base64 = "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="

// helloWorldSHA256Hex is the same digest hex-encoded — what bbolt stores and
// what the scrubber, the native protocol and `jay ls -l` keep reading:
//
//	printf 'hello world' | shasum -a 256
const helloWorldSHA256Hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

// putHelloWorld stores "hello world" at bucket/key and returns the PUT response.
func putHelloWorld(t *testing.T, h *Handler, tok *meta.Token, secret, bucket, key string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/"+bucket+"/"+key, strings.NewReader("hello world"))
	req.Header.Set("Authorization", authHeader(tok, secret))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("put: want 200, got %d: %s", w.Code, w.Body.String())
	}
	return w
}

func TestChecksumHeader_PutGetHeadAreBase64(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	bucket := createBucketForTest(t, db, tok.AccountID, "sum-bucket")

	putResp := putHelloWorld(t, h, tok, secret, bucket.Name, "k.txt")
	if got := putResp.Header().Get(checksumHeader); got != helloWorldSHA256Base64 {
		t.Fatalf("PUT %s = %q, want %q", checksumHeader, got, helloWorldSHA256Base64)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/sum-bucket/k.txt", nil)
	getReq.Header.Set("Authorization", authHeader(tok, secret))
	getW := httptest.NewRecorder()
	h.ServeHTTP(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("get: want 200, got %d: %s", getW.Code, getW.Body.String())
	}
	if got := getW.Header().Get(checksumHeader); got != helloWorldSHA256Base64 {
		t.Fatalf("GET %s = %q, want %q", checksumHeader, got, helloWorldSHA256Base64)
	}

	headReq := httptest.NewRequest(http.MethodHead, "/sum-bucket/k.txt", nil)
	headReq.Header.Set("Authorization", authHeader(tok, secret))
	headW := httptest.NewRecorder()
	h.ServeHTTP(headW, headReq)
	if headW.Code != http.StatusOK {
		t.Fatalf("head: want 200, got %d", headW.Code)
	}
	if got := headW.Header().Get(checksumHeader); got != helloWorldSHA256Base64 {
		t.Fatalf("HEAD %s = %q, want %q", checksumHeader, got, helloWorldSHA256Base64)
	}

	// The stored form stays hex: the scrubber, the native protocol and the CLI
	// all read it from there, so the conversion lives at the HTTP edge only.
	obj, err := db.GetObjectMeta(bucket.ID, "k.txt")
	if err != nil {
		t.Fatalf("get object meta: %v", err)
	}
	if obj.ChecksumSHA256 != helloWorldSHA256Hex {
		t.Fatalf("stored checksum = %q, want the hex form %q", obj.ChecksumSHA256, helloWorldSHA256Hex)
	}
}

func TestChecksumHeader_AbsentOnRangeResponse(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "sum-range-bucket")
	putHelloWorld(t, h, tok, secret, "sum-range-bucket", "k.txt")

	req := httptest.NewRequest(http.MethodGet, "/sum-range-bucket/k.txt", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	req.Header.Set("Range", "bytes=0-4")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusPartialContent {
		t.Fatalf("want 206, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "hello" {
		t.Fatalf("body = %q, want %q", w.Body.String(), "hello")
	}
	// The digest covers the whole object. Emitting it next to five bytes makes
	// a correct transfer look corrupt to any client that verifies it — which is
	// every ranged download the AWS CLI does above its 8 MiB threshold.
	if got := w.Header().Get(checksumHeader); got != "" {
		t.Fatalf("206 carried %s = %q, want no header", checksumHeader, got)
	}
}

func TestSetChecksumHeader_RefusesMalformedDigest(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"not hex":        strings.Repeat("z", 64),
		"too short":      "b94d27b9",
		"base64 already": helloWorldSHA256Base64,
	}
	for name, digest := range cases {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			setChecksumHeader(w, digest)
			if got := w.Header().Get(checksumHeader); got != "" {
				t.Fatalf("emitted %s = %q for %q, want no header", checksumHeader, got, digest)
			}
		})
	}
}
