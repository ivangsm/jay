package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

func setupTestHandler(t *testing.T) (*Handler, *meta.DB, *meta.Token, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := meta.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetSigningSecret("test-secret")
	t.Cleanup(func() { _ = db.Close() })

	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	acc := &meta.Account{AccountID: uuid.New().String(), Name: "test", Status: "active"}
	if err := db.CreateAccount(acc); err != nil {
		t.Fatalf("create account: %v", err)
	}

	secret := "test-secret-value"
	hash, _ := auth.HashSecret(secret)
	tok := &meta.Token{
		TokenID:        "test-token",
		AccountID:      acc.AccountID,
		Name:           "test",
		SecretHash:     hash,
		SecretKey:      secret,
		AllowedActions: []string{meta.ActionBucketReadMeta, meta.ActionBucketWriteMeta, meta.ActionObjectPut},
		Status:         "active",
	}
	if err := db.CreateToken(tok); err != nil {
		t.Fatalf("create token: %v", err)
	}

	au := auth.New(db)
	log := testLogger()
	metrics := maintenance.NewMetrics()
	h := NewHandler(db, st, au, log, metrics, "", nil)
	return h, db, tok, secret
}

func TestBucketStatsHandler_Empty(t *testing.T) {
	h, db, tok, secret := setupTestHandler(t)

	b := &meta.Bucket{ID: uuid.New().String(), Name: "bk1", OwnerAccountID: tok.AccountID, Visibility: "private", Status: "active"}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/_stats/bk1", nil)
	req.Header.Set("Authorization", "Bearer "+tok.TokenID+":"+secret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Bucket         string `json:"bucket"`
		ObjectCount    int64  `json:"object_count"`
		TotalSizeBytes int64  `json:"total_size_bytes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, w.Body.String())
	}
	if resp.Bucket != "bk1" || resp.ObjectCount != 0 || resp.TotalSizeBytes != 0 {
		t.Fatalf("bad body: %+v", resp)
	}
}

func TestBucketStatsHandler_WithObjects(t *testing.T) {
	h, db, tok, secret := setupTestHandler(t)

	b := &meta.Bucket{ID: uuid.New().String(), Name: "bk2", OwnerAccountID: tok.AccountID, Visibility: "private", Status: "active"}
	_ = db.CreateBucket(b)

	for _, size := range []int64{100, 200, 300} {
		_, _ = db.PutObjectMeta(&meta.Object{
			BucketID: b.ID, Key: uuid.New().String(), ObjectID: uuid.New().String(),
			SizeBytes: size, State: "active",
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/_stats/bk2", nil)
	req.Header.Set("Authorization", "Bearer "+tok.TokenID+":"+secret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		ObjectCount    int64 `json:"object_count"`
		TotalSizeBytes int64 `json:"total_size_bytes"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.ObjectCount != 3 || resp.TotalSizeBytes != 600 {
		t.Fatalf("bad body: %+v", resp)
	}
}

func TestBucketStatsHandler_Unauthorized(t *testing.T) {
	h, db, tok, _ := setupTestHandler(t)
	b := &meta.Bucket{ID: uuid.New().String(), Name: "bk3", OwnerAccountID: tok.AccountID, Visibility: "private", Status: "active"}
	_ = db.CreateBucket(b)

	req := httptest.NewRequest(http.MethodGet, "/_stats/bk3", nil)
	// No Authorization header
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401/403, got %d", w.Code)
	}
}

func TestBucketStatsHandler_NonexistentBucket(t *testing.T) {
	h, _, tok, secret := setupTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/_stats/doesnotexist", nil)
	req.Header.Set("Authorization", "Bearer "+tok.TokenID+":"+secret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
