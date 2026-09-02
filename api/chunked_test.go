package api

import (
	"encoding/xml"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ivangsm/jay/meta"
	"uuid"
)

// walkDataDir returns every regular file under the store's data directory,
// relative to it, sorted. Used to prove a rejected upload wrote nothing: not
// the object, not a temp file, not an orphan a later recovery pass would have
// to quarantine.
func walkDataDir(t *testing.T, h *Handler) []string {
	t.Helper()
	root := h.store.DataDir()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		out = append(out, rel)
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walk data dir: %v", err)
	}
	sort.Strings(out)
	return out
}

// chunkedTestBucket creates a bucket owned by the token's account.
func chunkedTestBucket(t *testing.T, db *meta.DB, tok *meta.Token, name string) {
	t.Helper()
	b := &meta.Bucket{
		ID: uuid.New().String(), Name: name,
		OwnerAccountID: tok.AccountID, Visibility: "private", Status: "active",
	}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
}

// The framed body, exactly as minio-go puts it on the wire for a 15-byte file.
var awsChunkedBody = "f;chunk-signature=" + strings.Repeat("a", 64) + "\r\n" +
	"hola desde jay\n" + "\r\n" +
	"0;chunk-signature=" + strings.Repeat("b", 64) + "\r\n\r\n"

// Every entry point that accepts a body must refuse aws-chunked framing. One
// closed door is worth nothing while the one next to it is open: PutObject was
// how the corruption was found, but UploadPart frames its parts exactly the
// same way, and that is where a 20 MiB upload gained 29 KiB of chunk headers.
func TestChunkedBodyRejected_AllBodyEntryPoints(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		target  string
		body    string
		headers map[string]string
	}{
		{
			name: "PutObject", method: http.MethodPut, target: "/chunk-bkt/obj.txt",
			body:    awsChunkedBody,
			headers: map[string]string{"x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"},
		},
		{
			name: "UploadPart", method: http.MethodPut, target: "/chunk-bkt/obj.txt?uploadId=nope&partNumber=1",
			body:    awsChunkedBody,
			headers: map[string]string{"x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"},
		},
		{
			name: "CompleteMultipartUpload", method: http.MethodPost, target: "/chunk-bkt/obj.txt?uploadId=nope",
			body:    awsChunkedBody,
			headers: map[string]string{"x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"},
		},
		{
			name: "DeleteObjects", method: http.MethodPost, target: "/chunk-bkt?delete",
			body:    awsChunkedBody,
			headers: map[string]string{"x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER"},
		},
		{
			name: "CreateBucket", method: http.MethodPut, target: "/another-bkt",
			body:    awsChunkedBody,
			headers: map[string]string{"x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"},
		},
		{
			// Announced only by the decoded length: the payload hash is an
			// ordinary UNSIGNED-PAYLOAD and would have been waved through.
			name: "PutObject announced by decoded length", method: http.MethodPut, target: "/chunk-bkt/obj.txt",
			body: awsChunkedBody,
			headers: map[string]string{
				"x-amz-content-sha256":         "UNSIGNED-PAYLOAD",
				"x-amz-decoded-content-length": "15",
			},
		},
		{
			name: "PutObject announced by content-encoding", method: http.MethodPut, target: "/chunk-bkt/obj.txt",
			body:    awsChunkedBody,
			headers: map[string]string{"Content-Encoding": "aws-chunked"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, db, tok, secret := fullSetupTestHandler(t)
			chunkedTestBucket(t, db, tok, "chunk-bkt")
			before := walkDataDir(t, h)

			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			req.Header.Set("Authorization", authHeader(tok, secret))
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusNotImplemented {
				t.Fatalf("want 501, got %d: %s", w.Code, w.Body.String())
			}

			var errResp S3Error
			if err := xml.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("response is not an S3 error document: %v (%s)", err, w.Body.String())
			}
			if errResp.Code != S3ErrNotImplemented {
				t.Errorf("Code = %q, want %q", errResp.Code, S3ErrNotImplemented)
			}
			// The message has to say what to do, not just that it failed.
			for _, want := range []string{"aws-chunked", "x-amz-content-sha256", "UNSIGNED-PAYLOAD"} {
				if !strings.Contains(errResp.Message, want) {
					t.Errorf("message %q does not mention %q", errResp.Message, want)
				}
			}
			if errResp.RequestID == "" {
				t.Error("RequestId is empty")
			}

			// Nothing may have been written: no object, no metadata, no temp
			// file left behind for recovery to quarantine.
			if after := walkDataDir(t, h); len(after) != len(before) {
				t.Errorf("data dir changed after a rejected request:\nbefore %v\nafter  %v", before, after)
			}
			if _, _, err := db.GetBucketAndObject("chunk-bkt", "obj.txt"); err == nil {
				t.Error("object metadata was committed for a rejected request")
			}
		})
	}
}

// The refusal must not depend on holding a valid credential — and, just as
// importantly, must not be reachable in a way that stores anything.
func TestChunkedBodyRejected_BeforeAuthentication(t *testing.T) {
	h, _, _, _ := fullSetupTestHandler(t)

	req := httptest.NewRequest(http.MethodPut, "/chunk-bkt/obj.txt", strings.NewReader(awsChunkedBody))
	req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("want 501 with no credentials, got %d: %s", w.Code, w.Body.String())
	}
}

// A body with no framing is untouched by the gate. This is the aws-cli path:
// a real payload hash, no x-amz-decoded-content-length, no aws-chunked coding.
func TestUnframedBodyStillAccepted(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	chunkedTestBucket(t, db, tok, "chunk-bkt")

	body := "hola desde jay\n"
	req := httptest.NewRequest(http.MethodPut, "/chunk-bkt/plain.txt", strings.NewReader(body))
	req.Header.Set("Authorization", authHeader(tok, secret))
	req.Header.Set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	_, obj, err := db.GetBucketAndObject("chunk-bkt", "plain.txt")
	if err != nil {
		t.Fatalf("object should exist: %v", err)
	}
	if obj.SizeBytes != int64(len(body)) {
		t.Errorf("stored size = %d, want %d", obj.SizeBytes, len(body))
	}
}
