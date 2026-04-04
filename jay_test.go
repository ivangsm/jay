package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"log/slog"

	"github.com/ivangsm/jay/admin"
	jayapi "github.com/ivangsm/jay/api"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/recovery"
	"github.com/ivangsm/jay/store"
)

type testEnv struct {
	db         *meta.DB
	store      *store.Store
	s3Server   *httptest.Server
	adminServer *httptest.Server
	auth       string // Authorization header value
}

func setup(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	log := slog.Default()

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := recovery.Run(db, st, log); err != nil {
		t.Fatal(err)
	}

	au := auth.New(db)
	metrics := maintenance.NewMetrics()
	s3Handler := jayapi.NewHandler(db, st, au, log, metrics)
	s3Srv := httptest.NewServer(s3Handler)
	t.Cleanup(s3Srv.Close)

	adminHandler := admin.NewHandler(db, "test-admin", log, metrics)
	adminSrv := httptest.NewServer(adminHandler)
	t.Cleanup(adminSrv.Close)

	// Create account and token
	account := createTestAccount(t, adminSrv.URL)
	tokenID, secret := createTestToken(t, adminSrv.URL, account)

	return &testEnv{
		db:          db,
		store:       st,
		s3Server:    s3Srv,
		adminServer: adminSrv,
		auth:        "Bearer " + tokenID + ":" + secret,
	}
}

func createTestAccount(t *testing.T, adminURL string) string {
	t.Helper()
	body := `{"name":"testaccount"}`
	req, _ := http.NewRequest("POST", adminURL+"/_jay/accounts", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-admin")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result struct {
		AccountID string `json:"account_id"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.AccountID
}

func createTestToken(t *testing.T, adminURL, accountID string) (string, string) {
	t.Helper()
	body := `{"account_id":"` + accountID + `","name":"test"}`
	req, _ := http.NewRequest("POST", adminURL+"/_jay/tokens", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-admin")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result struct {
		TokenID string `json:"token_id"`
		Secret  string `json:"secret"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	return result.TokenID, result.Secret
}

func (e *testEnv) s3Request(t *testing.T, method, path string, body io.Reader) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, e.s3Server.URL+path, body)
	req.Header.Set("Authorization", e.auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestBucketLifecycle(t *testing.T) {
	env := setup(t)

	// Create bucket
	resp := env.s3Request(t, "PUT", "/test-bucket", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("create bucket: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Head bucket
	resp = env.s3Request(t, "HEAD", "/test-bucket", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("head bucket: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Create duplicate bucket
	resp = env.s3Request(t, "PUT", "/test-bucket", nil)
	if resp.StatusCode != 409 {
		t.Fatalf("duplicate bucket: expected 409, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Delete bucket
	resp = env.s3Request(t, "DELETE", "/test-bucket", nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete bucket: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Head deleted bucket
	resp = env.s3Request(t, "HEAD", "/test-bucket", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("head deleted bucket: expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestObjectLifecycle(t *testing.T) {
	env := setup(t)

	// Create bucket
	resp := env.s3Request(t, "PUT", "/mybucket", nil)
	resp.Body.Close()

	// Put object
	content := "hello, jay!"
	resp = env.s3Request(t, "PUT", "/mybucket/greeting.txt",
		strings.NewReader(content))
	if resp.StatusCode != 200 {
		t.Fatalf("put object: got %d", resp.StatusCode)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("put object: missing ETag")
	}
	resp.Body.Close()

	// Get object
	resp = env.s3Request(t, "GET", "/mybucket/greeting.txt", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("get object: got %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != content {
		t.Fatalf("get object: got %q, want %q", got, content)
	}

	// Head object
	resp = env.s3Request(t, "HEAD", "/mybucket/greeting.txt", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("head object: got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Length") != "11" {
		t.Fatalf("head object: wrong content-length: %s", resp.Header.Get("Content-Length"))
	}
	resp.Body.Close()

	// Delete object
	resp = env.s3Request(t, "DELETE", "/mybucket/greeting.txt", nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete object: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Get deleted object
	resp = env.s3Request(t, "GET", "/mybucket/greeting.txt", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("get deleted: expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Delete non-existent returns 204 (S3 behavior)
	resp = env.s3Request(t, "DELETE", "/mybucket/nonexistent.txt", nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete non-existent: expected 204, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestObjectOverwrite(t *testing.T) {
	env := setup(t)

	resp := env.s3Request(t, "PUT", "/mybucket", nil)
	resp.Body.Close()

	// Put v1
	resp = env.s3Request(t, "PUT", "/mybucket/data.bin", strings.NewReader("version1"))
	resp.Body.Close()

	// Put v2 (overwrite)
	resp = env.s3Request(t, "PUT", "/mybucket/data.bin", strings.NewReader("version2"))
	resp.Body.Close()

	// Get should return v2
	resp = env.s3Request(t, "GET", "/mybucket/data.bin", nil)
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != "version2" {
		t.Fatalf("overwrite: got %q, want %q", got, "version2")
	}
}

func TestListObjectsV2(t *testing.T) {
	env := setup(t)

	resp := env.s3Request(t, "PUT", "/listbucket", nil)
	resp.Body.Close()

	// Put several objects
	for _, key := range []string{"photos/a.jpg", "photos/b.jpg", "docs/readme.md", "root.txt"} {
		resp = env.s3Request(t, "PUT", "/listbucket/"+key, strings.NewReader("data"))
		resp.Body.Close()
	}

	// List all
	resp = env.s3Request(t, "GET", "/listbucket?list-type=2", nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result jayapi.ListBucketResult
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(result.Contents) != 4 {
		t.Fatalf("list all: got %d objects, want 4", len(result.Contents))
	}

	// List with prefix
	resp = env.s3Request(t, "GET", "/listbucket?list-type=2&prefix=photos/", nil)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	result = jayapi.ListBucketResult{}
	xml.Unmarshal(body, &result)
	if len(result.Contents) != 2 {
		t.Fatalf("list prefix: got %d, want 2", len(result.Contents))
	}

	// List with delimiter
	resp = env.s3Request(t, "GET", "/listbucket?list-type=2&delimiter=/", nil)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	result = jayapi.ListBucketResult{}
	xml.Unmarshal(body, &result)
	if len(result.Contents) != 1 {
		t.Fatalf("list delimiter objects: got %d, want 1 (root.txt)", len(result.Contents))
	}
	if len(result.CommonPrefixes) != 2 {
		t.Fatalf("list delimiter prefixes: got %d, want 2 (docs/, photos/)", len(result.CommonPrefixes))
	}
}

func TestDeleteBucketNotEmpty(t *testing.T) {
	env := setup(t)

	resp := env.s3Request(t, "PUT", "/notempty", nil)
	resp.Body.Close()

	resp = env.s3Request(t, "PUT", "/notempty/file.txt", strings.NewReader("data"))
	resp.Body.Close()

	resp = env.s3Request(t, "DELETE", "/notempty", nil)
	if resp.StatusCode != 409 {
		t.Fatalf("delete non-empty bucket: expected 409, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestUnauthorized(t *testing.T) {
	env := setup(t)

	// Request without auth
	req, _ := http.NewRequest("PUT", env.s3Server.URL+"/anybucket", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("no auth: expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Request with bad token
	req, _ = http.NewRequest("PUT", env.s3Server.URL+"/anybucket", nil)
	req.Header.Set("Authorization", "Bearer bad:creds")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("bad auth: expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestListBuckets(t *testing.T) {
	env := setup(t)

	// Create two buckets
	resp := env.s3Request(t, "PUT", "/alpha-bucket", nil)
	resp.Body.Close()
	resp = env.s3Request(t, "PUT", "/beta-bucket", nil)
	resp.Body.Close()

	resp = env.s3Request(t, "GET", "/", nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result jayapi.ListAllMyBucketsResult
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(result.Buckets.Bucket) != 2 {
		t.Fatalf("list buckets: got %d, want 2", len(result.Buckets.Bucket))
	}
}

func TestUserMetadata(t *testing.T) {
	env := setup(t)

	resp := env.s3Request(t, "PUT", "/metabucket", nil)
	resp.Body.Close()

	// Put with custom metadata
	req, _ := http.NewRequest("PUT", env.s3Server.URL+"/metabucket/file.txt",
		strings.NewReader("data"))
	req.Header.Set("Authorization", env.auth)
	req.Header.Set("x-amz-meta-custom", "myvalue")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()

	// Head should return custom metadata
	resp = env.s3Request(t, "HEAD", "/metabucket/file.txt", nil)
	if resp.Header.Get("x-amz-meta-custom") != "myvalue" {
		t.Fatalf("metadata: got %q, want %q",
			resp.Header.Get("x-amz-meta-custom"), "myvalue")
	}
	resp.Body.Close()
}

func TestRecoveryOrphanedFiles(t *testing.T) {
	dir := t.TempDir()
	log := slog.Default()

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Write an orphaned temp file
	tmpContent := []byte("orphaned temp")
	tmpPath := filepath.Join(dir, "tmp", "orphan-123")
	if err := writeFile(tmpPath, tmpContent); err != nil {
		t.Fatal(err)
	}

	// Run recovery
	if err := recovery.Run(db, st, log); err != nil {
		t.Fatal(err)
	}

	// Temp file should be cleaned
	if fileExists(tmpPath) {
		t.Fatal("orphaned temp file not cleaned")
	}
}

func TestChecksumOnWrite(t *testing.T) {
	env := setup(t)

	resp := env.s3Request(t, "PUT", "/checkbucket", nil)
	resp.Body.Close()

	content := "checksum test content"
	resp = env.s3Request(t, "PUT", "/checkbucket/file.bin",
		bytes.NewReader([]byte(content)))
	checksum := resp.Header.Get("x-amz-checksum-sha256")
	resp.Body.Close()

	if checksum == "" {
		t.Fatal("missing checksum in response")
	}

	// Verify via head
	resp = env.s3Request(t, "HEAD", "/checkbucket/file.bin", nil)
	if resp.Header.Get("x-amz-checksum-sha256") != checksum {
		t.Fatal("checksum mismatch between put and head")
	}
	resp.Body.Close()
}

// helpers

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
