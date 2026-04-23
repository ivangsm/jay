package api

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
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

	for i := 0; i < 2; i++ {
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
