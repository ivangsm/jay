package api

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"uuid"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/meta"
)

// fullSetupTestHandler extends setupTestHandler with a full-actions token so
// object tests can exercise GET, DELETE, and LIST.
func fullSetupTestHandler(t *testing.T) (*Handler, *meta.DB, *meta.Token, string) {
	t.Helper()
	h, db, tok, _ := setupTestHandler(t)

	fullSecret := "full-secret-value-xyz"
	hash, _ := auth.HashSecret(fullSecret)
	fullTok := &meta.Token{
		TokenID:        "full-token",
		AccountID:      tok.AccountID,
		Name:           "full",
		SecretHash:     hash,
		SecretKey:      fullSecret,
		AllowedActions: meta.AllActions,
		Status:         "active",
	}
	if err := db.CreateToken(fullTok); err != nil {
		t.Fatalf("create full token: %v", err)
	}
	return h, db, fullTok, fullSecret
}

// authHeader returns the Bearer Authorization header value.
func authHeader(tok *meta.Token, secret string) string {
	return "Bearer " + tok.TokenID + ":" + secret
}

// ── Bucket handlers ────────────────────────────────────────────────────────

func TestCreateBucket_Success(t *testing.T) {
	h, db, tok, secret := setupTestHandler(t)

	req := httptest.NewRequest(http.MethodPut, "/test-bucket", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify bucket exists in DB
	b, err := db.GetBucket("test-bucket")
	if err != nil {
		t.Fatalf("bucket should exist: %v", err)
	}
	if b.Name != "test-bucket" {
		t.Fatalf("unexpected bucket name: %s", b.Name)
	}
}

func TestCreateBucket_InvalidName(t *testing.T) {
	h, _, tok, secret := setupTestHandler(t)

	// "ab" is only 2 chars — ValidBucketName requires min 3
	req := httptest.NewRequest(http.MethodPut, "/ab", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateBucket_Duplicate(t *testing.T) {
	h, _, tok, secret := setupTestHandler(t)

	for i := range 2 {
		req := httptest.NewRequest(http.MethodPut, "/dup-bucket", nil)
		req.Header.Set("Authorization", authHeader(tok, secret))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if i == 0 && w.Code != http.StatusOK {
			t.Fatalf("first create: want 200, got %d", w.Code)
		}
		if i == 1 && w.Code != http.StatusConflict {
			t.Fatalf("second create: want 409, got %d: %s", w.Code, w.Body.String())
		}
	}
}

func TestCreateBucket_Unauthorized(t *testing.T) {
	h, _, _, _ := setupTestHandler(t)

	req := httptest.NewRequest(http.MethodPut, "/some-bucket", nil)
	// No Authorization header
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401/403, got %d", w.Code)
	}
}

func TestHeadBucket_Exists(t *testing.T) {
	h, db, tok, secret := setupTestHandler(t)

	b := &meta.Bucket{
		ID:             uuid.New().String(),
		Name:           "head-bucket",
		OwnerAccountID: tok.AccountID,
		Visibility:     "private",
		Status:         "active",
	}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	req := httptest.NewRequest(http.MethodHead, "/head-bucket", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestHeadBucket_NotFound(t *testing.T) {
	h, _, tok, secret := setupTestHandler(t)

	req := httptest.NewRequest(http.MethodHead, "/nonexistent-bucket", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestDeleteBucket_Empty(t *testing.T) {
	h, db, tok, secret := setupTestHandler(t)

	b := &meta.Bucket{
		ID:             uuid.New().String(),
		Name:           "del-bucket",
		OwnerAccountID: tok.AccountID,
		Visibility:     "private",
		Status:         "active",
	}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/del-bucket", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteBucket_NotFound(t *testing.T) {
	h, _, tok, secret := setupTestHandler(t)

	req := httptest.NewRequest(http.MethodDelete, "/no-such-bucket", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListBuckets_Empty(t *testing.T) {
	h, _, tok, secret := fullSetupTestHandler(t)
	// Use the full token (has bucket:list)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var result ListAllMyBucketsResult
	body := w.Body.Bytes()
	// Strip XML header if present
	if idx := strings.Index(string(body), "<ListAllMyBucketsResult"); idx >= 0 {
		body = body[idx:]
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, w.Body.String())
	}
	if len(result.Buckets.Bucket) != 0 {
		t.Fatalf("want 0 buckets, got %d", len(result.Buckets.Bucket))
	}
}

func TestListBuckets_WithBuckets(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)

	names := []string{"list-bucket-one", "list-bucket-two"}
	for _, name := range names {
		b := &meta.Bucket{
			ID:             uuid.New().String(),
			Name:           name,
			OwnerAccountID: tok.AccountID,
			Visibility:     "private",
			Status:         "active",
		}
		if err := db.CreateBucket(b); err != nil {
			t.Fatalf("create bucket %s: %v", name, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var result ListAllMyBucketsResult
	body := w.Body.Bytes()
	if idx := strings.Index(string(body), "<ListAllMyBucketsResult"); idx >= 0 {
		body = body[idx:]
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, w.Body.String())
	}
	if len(result.Buckets.Bucket) != 2 {
		t.Fatalf("want 2 buckets, got %d", len(result.Buckets.Bucket))
	}

	got := make(map[string]bool)
	for _, b := range result.Buckets.Bucket {
		got[b.Name] = true
	}
	for _, name := range names {
		if !got[name] {
			t.Fatalf("bucket %q not found in list response", name)
		}
	}
}

// ── Object handlers ────────────────────────────────────────────────────────

// createBucketForTest creates a bucket directly in DB and returns it.
func createBucketForTest(t *testing.T, db *meta.DB, accountID, name string) *meta.Bucket {
	t.Helper()
	b := &meta.Bucket{
		ID:             uuid.New().String(),
		Name:           name,
		OwnerAccountID: accountID,
		Visibility:     "private",
		Status:         "active",
	}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("create bucket %s: %v", name, err)
	}
	return b
}

func TestPutObject_Success(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "put-bucket")

	body := strings.NewReader("hello world")
	req := httptest.NewRequest(http.MethodPut, "/put-bucket/mykey", body)
	req.Header.Set("Authorization", authHeader(tok, secret))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("ETag") == "" {
		t.Fatal("want non-empty ETag header")
	}
}

func TestPutObject_Unauthorized(t *testing.T) {
	h, db, tok, _ := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "put-unauth-bucket")

	body := strings.NewReader("hello")
	req := httptest.NewRequest(http.MethodPut, "/put-unauth-bucket/key", body)
	// No Authorization header
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401/403, got %d", w.Code)
	}
}

func TestGetObject_Success(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "get-bucket")

	// Put first
	putBody := strings.NewReader("hello world")
	putReq := httptest.NewRequest(http.MethodPut, "/get-bucket/getkey", putBody)
	putReq.Header.Set("Authorization", authHeader(tok, secret))
	putReq.Header.Set("Content-Type", "text/plain")
	putW := httptest.NewRecorder()
	h.ServeHTTP(putW, putReq)
	if putW.Code != http.StatusOK {
		t.Fatalf("put failed: %d %s", putW.Code, putW.Body.String())
	}

	// Now get
	req := httptest.NewRequest(http.MethodGet, "/get-bucket/getkey", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if cl := w.Header().Get("Content-Length"); cl == "" {
		t.Fatal("want Content-Length header")
	}
	if got := w.Body.String(); got != "hello world" {
		t.Fatalf("want body %q, got %q", "hello world", got)
	}
}

func TestGetObject_NotFound(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "get-notfound-bucket")

	req := httptest.NewRequest(http.MethodGet, "/get-notfound-bucket/nosuchkey", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetObject_BucketNotFound(t *testing.T) {
	h, _, tok, secret := fullSetupTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/no-such-bucket-xyz/key", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHeadObject_Success(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "head-obj-bucket")

	// Put first
	putBody := strings.NewReader("head content")
	putReq := httptest.NewRequest(http.MethodPut, "/head-obj-bucket/headkey", putBody)
	putReq.Header.Set("Authorization", authHeader(tok, secret))
	putReq.Header.Set("Content-Type", "text/plain")
	putW := httptest.NewRecorder()
	h.ServeHTTP(putW, putReq)
	if putW.Code != http.StatusOK {
		t.Fatalf("put failed: %d %s", putW.Code, putW.Body.String())
	}

	// Head
	req := httptest.NewRequest(http.MethodHead, "/head-obj-bucket/headkey", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("HEAD response must have no body, got %q", w.Body.String())
	}
	if w.Header().Get("Content-Length") == "" {
		t.Fatal("want Content-Length header")
	}
	if w.Header().Get("ETag") == "" {
		t.Fatal("want ETag header")
	}
}

func TestHeadObject_NotFound(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "head-notfound-bucket")

	req := httptest.NewRequest(http.MethodHead, "/head-notfound-bucket/nosuchkey", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", w.Code)
	}
}

func TestDeleteObject_Success(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "del-obj-bucket")

	// Put first
	putBody := strings.NewReader("to be deleted")
	putReq := httptest.NewRequest(http.MethodPut, "/del-obj-bucket/delkey", putBody)
	putReq.Header.Set("Authorization", authHeader(tok, secret))
	putReq.Header.Set("Content-Type", "text/plain")
	putW := httptest.NewRecorder()
	h.ServeHTTP(putW, putReq)
	if putW.Code != http.StatusOK {
		t.Fatalf("put failed: %d %s", putW.Code, putW.Body.String())
	}

	// Delete
	req := httptest.NewRequest(http.MethodDelete, "/del-obj-bucket/delkey", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteObject_NotFound(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "del-notfound-bucket")

	req := httptest.NewRequest(http.MethodDelete, "/del-notfound-bucket/nosuchkey", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// S3 DELETE is idempotent → 204, but some implementations return 404.
	// Accept either to match the actual handler behavior.
	if w.Code != http.StatusNoContent && w.Code != http.StatusNotFound {
		t.Fatalf("want 204 or 404, got %d: %s", w.Code, w.Body.String())
	}
}

// ── List objects ───────────────────────────────────────────────────────────

func TestListObjects_Empty(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "list-empty-bucket")

	req := httptest.NewRequest(http.MethodGet, "/list-empty-bucket", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var result ListBucketResult
	body := w.Body.Bytes()
	if idx := strings.Index(string(body), "<ListBucketResult"); idx >= 0 {
		body = body[idx:]
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, w.Body.String())
	}
	if len(result.Contents) != 0 {
		t.Fatalf("want 0 objects, got %d", len(result.Contents))
	}
	if result.Name != "list-empty-bucket" {
		t.Fatalf("unexpected bucket name in response: %s", result.Name)
	}
}

func TestListObjects_WithObjects(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "list-objs-bucket")

	keys := []string{"alpha", "beta", "gamma"}
	for _, key := range keys {
		putBody := strings.NewReader("content of " + key)
		putReq := httptest.NewRequest(http.MethodPut, "/list-objs-bucket/"+key, putBody)
		putReq.Header.Set("Authorization", authHeader(tok, secret))
		putReq.Header.Set("Content-Type", "text/plain")
		putW := httptest.NewRecorder()
		h.ServeHTTP(putW, putReq)
		if putW.Code != http.StatusOK {
			t.Fatalf("put %s failed: %d %s", key, putW.Code, putW.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/list-objs-bucket", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var result ListBucketResult
	body := w.Body.Bytes()
	if idx := strings.Index(string(body), "<ListBucketResult"); idx >= 0 {
		body = body[idx:]
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, w.Body.String())
	}
	if len(result.Contents) != 3 {
		t.Fatalf("want 3 objects, got %d", len(result.Contents))
	}

	got := make(map[string]bool)
	for _, c := range result.Contents {
		got[c.Key] = true
	}
	for _, key := range keys {
		if !got[key] {
			t.Fatalf("key %q not found in list response", key)
		}
	}
}

// ── CopyObject ─────────────────────────────────────────────────────────────

// putObjectForTest stores an object through the S3 handler.
func putObjectForTest(t *testing.T, h *Handler, tok *meta.Token, secret, bucket, key, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/"+bucket+"/"+key, strings.NewReader(body))
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("put %s/%s: want 200, got %d: %s", bucket, key, w.Code, w.Body.String())
	}
}

// copyRequest issues PUT /<dst>/<key> with x-amz-copy-source.
func copyRequest(t *testing.T, h *Handler, tok *meta.Token, secret, source, dstBucket, dstKey string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/"+dstBucket+"/"+dstKey, nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	req.Header.Set("x-amz-copy-source", source)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// denyPolicy builds a bucket policy that denies `action` for every subject.
func denyPolicy(action string) json.RawMessage {
	return json.RawMessage(`{"version":"1","statements":[{"effect":"deny","actions":["` +
		action + `"],"subjects":["*"]}]}`)
}

func TestCopyObject_NoPolicy_Success(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "copy-src")
	dst := createBucketForTest(t, db, tok.AccountID, "copy-dst")
	putObjectForTest(t, h, tok, secret, "copy-src", "a.txt", "hello copy")

	w := copyRequest(t, h, tok, secret, "/copy-src/a.txt", "copy-dst", "b.txt")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	obj, err := db.GetObjectMeta(dst.ID, "b.txt")
	if err != nil {
		t.Fatalf("copied object should exist: %v", err)
	}
	if obj.SizeBytes != int64(len("hello copy")) {
		t.Fatalf("want size %d, got %d", len("hello copy"), obj.SizeBytes)
	}
}

func TestCopyObject_SourcePolicyDeniesGet(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "copy-src")
	dst := createBucketForTest(t, db, tok.AccountID, "copy-dst")
	putObjectForTest(t, h, tok, secret, "copy-src", "a.txt", "secret data")

	if err := db.UpdateBucketPolicy("copy-src", denyPolicy(meta.ActionObjectGet)); err != nil {
		t.Fatalf("update policy: %v", err)
	}

	w := copyRequest(t, h, tok, secret, "/copy-src/a.txt", "copy-dst", "b.txt")
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := db.GetObjectMeta(dst.ID, "b.txt"); !errors.Is(err, meta.ErrObjectNotFound) {
		t.Fatalf("denied copy must not create the destination object, got err=%v", err)
	}
}

func TestCopyObject_DestPolicyDeniesPut(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "copy-src")
	dst := createBucketForTest(t, db, tok.AccountID, "copy-dst")
	putObjectForTest(t, h, tok, secret, "copy-src", "a.txt", "payload")

	if err := db.UpdateBucketPolicy("copy-dst", denyPolicy(meta.ActionObjectPut)); err != nil {
		t.Fatalf("update policy: %v", err)
	}

	w := copyRequest(t, h, tok, secret, "/copy-src/a.txt", "copy-dst", "b.txt")
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := db.GetObjectMeta(dst.ID, "b.txt"); !errors.Is(err, meta.ErrObjectNotFound) {
		t.Fatalf("denied copy must not create the destination object, got err=%v", err)
	}
}

func TestCopyObject_MalformedPolicyFailsClosed(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "copy-src")
	createBucketForTest(t, db, tok.AccountID, "copy-dst")
	putObjectForTest(t, h, tok, secret, "copy-src", "a.txt", "payload")

	// Syntactically valid JSON (so it can be persisted) but not a BucketPolicy:
	// unmarshalling into the policy struct fails, which must fail closed.
	if err := db.UpdateBucketPolicy("copy-src", json.RawMessage(`{"statements":"nope"}`)); err != nil {
		t.Fatalf("update policy: %v", err)
	}

	w := copyRequest(t, h, tok, secret, "/copy-src/a.txt", "copy-dst", "b.txt")
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 for malformed policy, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCopyObject_SourceFileMissing_404(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	src := createBucketForTest(t, db, tok.AccountID, "copy-src")
	createBucketForTest(t, db, tok.AccountID, "copy-dst")
	putObjectForTest(t, h, tok, secret, "copy-src", "a.txt", "will vanish")

	// Drop the physical file, keep the metadata: metadata/disk skew must map to
	// NoSuchKey (404), not InternalError (500).
	obj, err := db.GetObjectMeta(src.ID, "a.txt")
	if err != nil {
		t.Fatalf("get object meta: %v", err)
	}
	if err := h.store.DeleteObject(obj.LocationRef); err != nil {
		t.Fatalf("delete physical file: %v", err)
	}

	w := copyRequest(t, h, tok, secret, "/copy-src/a.txt", "copy-dst", "b.txt")
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body.String())
	}
}

// ── Cross-account bucket ownership ─────────────────────────────────────────

// foreignToken creates a token belonging to a DIFFERENT account than the one
// setupTestHandler seeds, with full permissions and no bucket scope.
func foreignToken(t *testing.T, db *meta.DB, bucketScope []string) (*meta.Token, string) {
	t.Helper()
	acc := &meta.Account{AccountID: uuid.New().String(), Name: "attacker", Status: "active"}
	if err := db.CreateAccount(acc); err != nil {
		t.Fatalf("create foreign account: %v", err)
	}
	secret := "foreign-secret-value"
	hash, _ := auth.HashSecret(secret)
	tok := &meta.Token{
		TokenID:        "foreign-token",
		AccountID:      acc.AccountID,
		Name:           "foreign",
		SecretHash:     hash,
		SecretKey:      secret,
		AllowedActions: meta.AllActions,
		BucketScope:    bucketScope,
		Status:         "active",
	}
	if err := db.CreateToken(tok); err != nil {
		t.Fatalf("create foreign token: %v", err)
	}
	return tok, secret
}

// seedBucket inserts a bucket owned by ownerAccountID directly in meta.
func seedBucket(t *testing.T, db *meta.DB, name, ownerAccountID string) {
	t.Helper()
	if err := db.CreateBucket(&meta.Bucket{
		ID:             uuid.New().String(),
		Name:           name,
		OwnerAccountID: ownerAccountID,
		Visibility:     "private",
		Status:         "active",
	}); err != nil {
		t.Fatalf("create bucket %s: %v", name, err)
	}
}

func TestDeleteBucket_CrossAccountDenied(t *testing.T) {
	h, db, owner, _ := setupTestHandler(t)
	seedBucket(t, db, "victim-bucket", owner.AccountID)

	attacker, attackerSecret := foreignToken(t, db, nil)

	req := httptest.NewRequest(http.MethodDelete, "/victim-bucket", nil)
	req.Header.Set("Authorization", authHeader(attacker, attackerSecret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 for cross-account delete, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := db.GetBucket("victim-bucket"); err != nil {
		t.Fatalf("bucket must still exist after denied delete: %v", err)
	}
}

func TestDeleteBucket_OwnerAllowed(t *testing.T) {
	h, db, owner, secret := setupTestHandler(t)
	seedBucket(t, db, "own-bucket", owner.AccountID)

	req := httptest.NewRequest(http.MethodDelete, "/own-bucket", nil)
	req.Header.Set("Authorization", authHeader(owner, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204 for owner delete, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := db.GetBucket("own-bucket"); !errors.Is(err, meta.ErrBucketNotFound) {
		t.Fatalf("bucket should be gone, got %v", err)
	}
}

func TestDeleteBucket_ExplicitBucketScopeAllowed(t *testing.T) {
	h, db, owner, _ := setupTestHandler(t)
	seedBucket(t, db, "shared-bucket", owner.AccountID)

	// Operator delegated this exact bucket to another account's token.
	delegate, delegateSecret := foreignToken(t, db, []string{"shared-bucket"})

	req := httptest.NewRequest(http.MethodDelete, "/shared-bucket", nil)
	req.Header.Set("Authorization", authHeader(delegate, delegateSecret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204 for delegated delete, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteBucket_LegacyOwnerlessAllowed(t *testing.T) {
	h, db, _, _ := setupTestHandler(t)
	seedBucket(t, db, "legacy-bucket", "")

	attacker, attackerSecret := foreignToken(t, db, nil)

	req := httptest.NewRequest(http.MethodDelete, "/legacy-bucket", nil)
	req.Header.Set("Authorization", authHeader(attacker, attackerSecret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204 for ownerless bucket, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHeadBucket_CrossAccountDenied(t *testing.T) {
	h, db, owner, _ := setupTestHandler(t)
	seedBucket(t, db, "private-bucket", owner.AccountID)

	attacker, attackerSecret := foreignToken(t, db, nil)

	req := httptest.NewRequest(http.MethodHead, "/private-bucket", nil)
	req.Header.Set("Authorization", authHeader(attacker, attackerSecret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 for cross-account head, got %d", w.Code)
	}
}

func TestHeadBucket_OwnerAllowed(t *testing.T) {
	h, db, owner, secret := setupTestHandler(t)
	seedBucket(t, db, "owned-head-bucket", owner.AccountID)

	req := httptest.NewRequest(http.MethodHead, "/owned-head-bucket", nil)
	req.Header.Set("Authorization", authHeader(owner, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200 for owner head, got %d", w.Code)
	}
}

// ── Pre-auth rate limiting ─────────────────────────────────────────────────

// Requests with bogus credentials must be throttled by IP BEFORE authentication
// runs, so bcrypt is never reached by an attacker without valid credentials.
func TestIPRateLimit_ThrottlesUnauthenticatedRequests(t *testing.T) {
	h, _, _, _ := setupTestHandler(t)
	h.rateLimiter = newRateLimiter(RateLimiterConfig{Rate: 1, Burst: 2})
	h.ipRateLimiter = newRateLimiter(RateLimiterConfig{Rate: 1, Burst: 2})

	var last int
	for i := range 5 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.7:1234"
		req.Header.Set("Authorization", "Bearer bogus:credentials")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		last = w.Code
		if i < 2 && last == http.StatusTooManyRequests {
			t.Fatalf("request %d throttled before burst was exhausted", i)
		}
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("want 429 once the IP burst is exhausted, got %d", last)
	}
}

// Authenticated traffic is limited per token; the IP bucket must not throttle a
// legitimate client below its configured rate.
func TestIPRateLimit_AuthenticatedRequestsPassWithinBudget(t *testing.T) {
	h, _, tok, secret := setupTestHandler(t)
	h.rateLimiter = newRateLimiter(RateLimiterConfig{Rate: 100, Burst: 200})
	h.ipRateLimiter = newRateLimiter(RateLimiterConfig{Rate: 100, Burst: 200})

	for i := range 10 {
		req := httptest.NewRequest(http.MethodHead, "/no-such-bucket", nil)
		req.RemoteAddr = "203.0.113.8:1234"
		req.Header.Set("Authorization", authHeader(tok, secret))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d unexpectedly rate limited", i)
		}
	}
}

// --- parseRange -------------------------------------------------------------

// A zero-byte object has no satisfiable range: every form must be rejected so
// the caller answers 416 instead of emitting a bogus Content-Range / length.
func TestParseRange_EmptyObject(t *testing.T) {
	for _, hdr := range []string{"bytes=0-", "bytes=0-0", "bytes=-1", "bytes=-500", "bytes=1-2"} {
		start, end, ok := parseRange(hdr, 0)
		if ok {
			t.Errorf("parseRange(%q, 0) = (%d, %d, true), want not-satisfiable", hdr, start, end)
		}
		if length := end - start + 1; ok && length <= 0 {
			t.Errorf("parseRange(%q, 0) produced non-positive length %d", hdr, length)
		}
	}
}

func TestParseRange_NonEmptyObject(t *testing.T) {
	tests := []struct {
		hdr        string
		total      int64
		start, end int64
		ok         bool
	}{
		{"bytes=0-", 10, 0, 9, true},
		{"bytes=0-0", 10, 0, 0, true},
		{"bytes=5-", 10, 5, 9, true},
		{"bytes=-3", 10, 7, 9, true},
		{"bytes=-99", 10, 0, 9, true},
		{"bytes=2-99", 10, 2, 9, true},
		{"bytes=10-", 10, 0, 0, false}, // start == totalSize
		{"bytes=5-4", 10, 0, 0, false}, // end < start
		{"bytes=0-1,3-4", 10, 0, 0, false},
		{"chars=0-1", 10, 0, 0, false},
	}
	for _, tc := range tests {
		start, end, ok := parseRange(tc.hdr, tc.total)
		if ok != tc.ok || start != tc.start || end != tc.end {
			t.Errorf("parseRange(%q, %d) = (%d, %d, %v), want (%d, %d, %v)",
				tc.hdr, tc.total, start, end, ok, tc.start, tc.end, tc.ok)
		}
	}
}
