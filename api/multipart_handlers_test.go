package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

type multipartHTTPEnv struct {
	handler *Handler
	db      *meta.DB
	store   *store.Store
	token   *meta.Token
	secret  string
}

func setupMultipartHTTPEnv(t *testing.T) *multipartHTTPEnv {
	t.Helper()
	dir := t.TempDir()
	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetSigningSecret("test-secret-at-least-32-bytes-long")
	t.Cleanup(func() { _ = db.Close() })

	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	account := &meta.Account{AccountID: uuid.New().String(), Name: "test", Status: "active"}
	if err := db.CreateAccount(account); err != nil {
		t.Fatalf("create account: %v", err)
	}

	secret := "test-secret-value"
	hash, err := auth.HashSecret(secret)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	token := &meta.Token{
		TokenID:        "test-token",
		AccountID:      account.AccountID,
		Name:           "test",
		SecretHash:     hash,
		SecretKey:      secret,
		AllowedActions: meta.AllActions,
		Status:         "active",
	}
	if err := db.CreateToken(token); err != nil {
		t.Fatalf("create token: %v", err)
	}

	h := NewHandler(
		db,
		st,
		auth.New(db),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		maintenance.NewMetrics(),
		"",
		nil,
	)
	return &multipartHTTPEnv{handler: h, db: db, store: st, token: token, secret: secret}
}

func (env *multipartHTTPEnv) createBucket(t *testing.T, name string) *meta.Bucket {
	t.Helper()
	b := &meta.Bucket{
		ID:             uuid.New().String(),
		Name:           name,
		OwnerAccountID: env.token.AccountID,
		Visibility:     "private",
		Status:         "active",
	}
	if err := env.db.CreateBucket(b); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	if err := env.store.EnsureBucketDir(b.ID); err != nil {
		t.Fatalf("ensure bucket dir: %v", err)
	}
	return b
}

func (env *multipartHTTPEnv) createUpload(t *testing.T, bucket *meta.Bucket, key string) *meta.MultipartUpload {
	t.Helper()
	upload := &meta.MultipartUpload{
		UploadID:    uuid.New().String(),
		BucketID:    bucket.ID,
		ObjectKey:   key,
		ContentType: "application/octet-stream",
		InitiatedBy: env.token.AccountID,
		CreatedAt:   time.Now().UTC(),
		State:       "initiated",
	}
	if err := env.db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("create upload: %v", err)
	}
	return upload
}

func (env *multipartHTTPEnv) serve(method, path string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+env.token.TokenID+":"+env.secret)
	w := httptest.NewRecorder()
	env.handler.ServeHTTP(w, req)
	return w
}

func TestMultipartUploadPartRejectsWrongBucketOrKey(t *testing.T) {
	env := setupMultipartHTTPEnv(t)
	env.createBucket(t, "other")
	bucket := env.createBucket(t, "owner")
	upload := env.createUpload(t, bucket, "image.bin")

	w := env.serve(http.MethodPut, "/other/image.bin?uploadId="+upload.UploadID+"&partNumber=1", []byte("part-data"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("wrong bucket: want 404, got %d: %s", w.Code, w.Body.String())
	}

	w = env.serve(http.MethodPut, "/owner/other.bin?uploadId="+upload.UploadID+"&partNumber=1", []byte("part-data"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("wrong key: want 404, got %d: %s", w.Code, w.Body.String())
	}

	got, err := env.db.GetMultipartUpload(upload.UploadID)
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	if len(got.Parts) != 0 {
		t.Fatalf("wrong bucket/key must not register parts, got %d", len(got.Parts))
	}
}

func TestMultipartCompleteAbortAndListRejectWrongBucketOrKey(t *testing.T) {
	env := setupMultipartHTTPEnv(t)
	env.createBucket(t, "other")
	bucket := env.createBucket(t, "owner")
	upload := env.createUpload(t, bucket, "image.bin")

	completeXML := []byte(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>`)
	cases := []struct {
		method string
		path   string
		body   []byte
	}{
		{http.MethodPost, "/other/image.bin?uploadId=" + upload.UploadID, completeXML},
		{http.MethodPost, "/owner/other.bin?uploadId=" + upload.UploadID, completeXML},
		{http.MethodDelete, "/other/image.bin?uploadId=" + upload.UploadID, nil},
		{http.MethodGet, "/owner/other.bin?uploadId=" + upload.UploadID, nil},
	}

	for _, tc := range cases {
		w := env.serve(tc.method, tc.path, tc.body)
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s %s: want 404, got %d: %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}

	got, err := env.db.GetMultipartUpload(upload.UploadID)
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	if got.State != "initiated" {
		t.Fatalf("upload state changed: %s", got.State)
	}
}

func TestMultipartUploadPartHonorsBucketPolicyDeny(t *testing.T) {
	env := setupMultipartHTTPEnv(t)
	bucket := env.createBucket(t, "owner")
	policy := auth.BucketPolicy{
		Version: "1",
		Statements: []auth.PolicyStatement{{
			Effect:   "deny",
			Actions:  []string{meta.ActionMultipartUpload},
			Prefixes: []string{"private/"},
			Subjects: []string{env.token.TokenID},
		}},
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	if err := env.db.UpdateBucketPolicy(bucket.Name, raw); err != nil {
		t.Fatalf("update policy: %v", err)
	}
	upload := env.createUpload(t, bucket, "private/image.bin")

	w := env.serve(http.MethodPut, "/owner/private/image.bin?uploadId="+upload.UploadID+"&partNumber=1", []byte("part-data"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}

	got, err := env.db.GetMultipartUpload(upload.UploadID)
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	if len(got.Parts) != 0 {
		t.Fatalf("policy-denied upload must not register parts, got %d", len(got.Parts))
	}
}

func TestMultipartCompleteFailureLeavesUploadRetryable(t *testing.T) {
	env := setupMultipartHTTPEnv(t)
	bucket := env.createBucket(t, "owner")
	upload := env.createUpload(t, bucket, "image.bin")
	if err := env.db.AddMultipartPart(upload.UploadID, meta.MultipartPart{
		PartNumber:     1,
		Size:           4,
		ETag:           "8d777f385d3dfec8815d20f7496026dc",
		ChecksumSHA256: "missing",
		LocationRef:    "multipart/" + upload.UploadID + "/part-00001",
		CreatedAt:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("add part: %v", err)
	}

	body := []byte(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>`)
	w := env.serve(http.MethodPost, "/owner/image.bin?uploadId="+upload.UploadID, body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d: %s", w.Code, w.Body.String())
	}

	got, err := env.db.GetMultipartUpload(upload.UploadID)
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	if got.State != "initiated" {
		t.Fatalf("failed complete should remain retryable, got state %s", got.State)
	}
	if _, err := env.db.GetObjectMeta(bucket.ID, "image.bin"); !errors.Is(err, meta.ErrObjectNotFound) {
		t.Fatalf("object should not be committed, got %v", err)
	}
}

func TestMultipartCompleteSuccessDeletesUploadRecord(t *testing.T) {
	env := setupMultipartHTTPEnv(t)
	bucket := env.createBucket(t, "owner")
	upload := env.createUpload(t, bucket, "image.bin")

	w := env.serve(http.MethodPut, "/owner/image.bin?uploadId="+upload.UploadID+"&partNumber=1", []byte("data"))
	if w.Code != http.StatusOK {
		t.Fatalf("upload part: got %d: %s", w.Code, w.Body.String())
	}

	body := []byte(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>`)
	w = env.serve(http.MethodPost, "/owner/image.bin?uploadId="+upload.UploadID, body)
	if w.Code != http.StatusOK {
		t.Fatalf("complete: got %d: %s", w.Code, w.Body.String())
	}
	if _, err := env.db.GetMultipartUpload(upload.UploadID); !errors.Is(err, meta.ErrUploadNotFound) {
		t.Fatalf("upload record should be deleted, got %v", err)
	}
	if _, err := env.db.GetObjectMeta(bucket.ID, "image.bin"); err != nil {
		t.Fatalf("object should be committed: %v", err)
	}
}
