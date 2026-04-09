package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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
	db          *meta.DB
	store       *store.Store
	s3Server    *httptest.Server
	adminServer *httptest.Server
	auth        string // Authorization header value
	tokenID     string
	secret      string
	accountID   string
}

func setup(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	log := slog.Default()

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := recovery.Run(db, st, log); err != nil {
		t.Fatal(err)
	}

	au := auth.New(db)
	metrics := maintenance.NewMetrics()
	s3Handler := jayapi.NewHandler(db, st, au, log, metrics, "", nil)
	s3Srv := httptest.NewServer(s3Handler)
	t.Cleanup(s3Srv.Close)

	adminHandler := admin.NewHandler(db, "test-admin", log, metrics, st, "", "", false, au)
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
		tokenID:     tokenID,
		secret:      secret,
		accountID:   account,
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
	defer func() { _ = resp.Body.Close() }()
	var result struct {
		AccountID string `json:"account_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode account: %v", err)
	}
	return result.AccountID
}

func createTestToken(t *testing.T, adminURL, accountID string) (string, string) {
	t.Helper()
	body := `{"account_id":"` + accountID + `","name":"test","allowed_actions":["bucket:list","bucket:read-meta","bucket:write-meta","object:get","object:put","object:delete","object:list","multipart:create","multipart:upload-part","multipart:complete","multipart:abort"]}`
	req, _ := http.NewRequest("POST", adminURL+"/_jay/tokens", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-admin")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var result struct {
		TokenID string `json:"token_id"`
		Secret  string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode token: %v", err)
	}
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
	_ = resp.Body.Close()

	// Head bucket
	resp = env.s3Request(t, "HEAD", "/test-bucket", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("head bucket: got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Create duplicate bucket
	resp = env.s3Request(t, "PUT", "/test-bucket", nil)
	if resp.StatusCode != 409 {
		t.Fatalf("duplicate bucket: expected 409, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Delete bucket
	resp = env.s3Request(t, "DELETE", "/test-bucket", nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete bucket: got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Head deleted bucket
	resp = env.s3Request(t, "HEAD", "/test-bucket", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("head deleted bucket: expected 404, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestObjectLifecycle(t *testing.T) {
	env := setup(t)

	// Create bucket
	resp := env.s3Request(t, "PUT", "/mybucket", nil)
	_ = resp.Body.Close()

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
	_ = resp.Body.Close()

	// Get object
	resp = env.s3Request(t, "GET", "/mybucket/greeting.txt", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("get object: got %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
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
	_ = resp.Body.Close()

	// Delete object
	resp = env.s3Request(t, "DELETE", "/mybucket/greeting.txt", nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete object: got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Get deleted object
	resp = env.s3Request(t, "GET", "/mybucket/greeting.txt", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("get deleted: expected 404, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Delete non-existent returns 204 (S3 behavior)
	resp = env.s3Request(t, "DELETE", "/mybucket/nonexistent.txt", nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete non-existent: expected 204, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestObjectOverwrite(t *testing.T) {
	env := setup(t)

	resp := env.s3Request(t, "PUT", "/mybucket", nil)
	_ = resp.Body.Close()

	// Put v1
	resp = env.s3Request(t, "PUT", "/mybucket/data.bin", strings.NewReader("version1"))
	_ = resp.Body.Close()

	// Put v2 (overwrite)
	resp = env.s3Request(t, "PUT", "/mybucket/data.bin", strings.NewReader("version2"))
	_ = resp.Body.Close()

	// Get should return v2
	resp = env.s3Request(t, "GET", "/mybucket/data.bin", nil)
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(got) != "version2" {
		t.Fatalf("overwrite: got %q, want %q", got, "version2")
	}
}

func TestListObjectsV2(t *testing.T) {
	env := setup(t)

	resp := env.s3Request(t, "PUT", "/listbucket", nil)
	_ = resp.Body.Close()

	// Put several objects
	for _, key := range []string{"photos/a.jpg", "photos/b.jpg", "docs/readme.md", "root.txt"} {
		resp = env.s3Request(t, "PUT", "/listbucket/"+key, strings.NewReader("data"))
		_ = resp.Body.Close()
	}

	// List all
	resp = env.s3Request(t, "GET", "/listbucket?list-type=2", nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

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
	_ = resp.Body.Close()
	result = jayapi.ListBucketResult{}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal prefix list: %v", err)
	}
	if len(result.Contents) != 2 {
		t.Fatalf("list prefix: got %d, want 2", len(result.Contents))
	}

	// List with delimiter
	resp = env.s3Request(t, "GET", "/listbucket?list-type=2&delimiter=/", nil)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	result = jayapi.ListBucketResult{}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal delimiter list: %v", err)
	}
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
	_ = resp.Body.Close()

	resp = env.s3Request(t, "PUT", "/notempty/file.txt", strings.NewReader("data"))
	_ = resp.Body.Close()

	resp = env.s3Request(t, "DELETE", "/notempty", nil)
	if resp.StatusCode != 409 {
		t.Fatalf("delete non-empty bucket: expected 409, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestUnauthorized(t *testing.T) {
	env := setup(t)

	// Request without auth
	req, _ := http.NewRequest("PUT", env.s3Server.URL+"/anybucket", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("no auth: expected 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Request with bad token
	req, _ = http.NewRequest("PUT", env.s3Server.URL+"/anybucket", nil)
	req.Header.Set("Authorization", "Bearer bad:creds")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("bad auth: expected 403, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestListBuckets(t *testing.T) {
	env := setup(t)

	// Create two buckets
	resp := env.s3Request(t, "PUT", "/alpha-bucket", nil)
	_ = resp.Body.Close()
	resp = env.s3Request(t, "PUT", "/beta-bucket", nil)
	_ = resp.Body.Close()

	resp = env.s3Request(t, "GET", "/", nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

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
	_ = resp.Body.Close()

	// Put with custom metadata
	req, _ := http.NewRequest("PUT", env.s3Server.URL+"/metabucket/file.txt",
		strings.NewReader("data"))
	req.Header.Set("Authorization", env.auth)
	req.Header.Set("x-amz-meta-custom", "myvalue")
	resp, _ = http.DefaultClient.Do(req)
	_ = resp.Body.Close()

	// Head should return custom metadata
	resp = env.s3Request(t, "HEAD", "/metabucket/file.txt", nil)
	if resp.Header.Get("x-amz-meta-custom") != "myvalue" {
		t.Fatalf("metadata: got %q, want %q",
			resp.Header.Get("x-amz-meta-custom"), "myvalue")
	}
	_ = resp.Body.Close()
}

func TestRecoveryOrphanedFiles(t *testing.T) {
	dir := t.TempDir()
	log := slog.Default()

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

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
	_ = resp.Body.Close()

	content := "checksum test content"
	resp = env.s3Request(t, "PUT", "/checkbucket/file.bin",
		bytes.NewReader([]byte(content)))
	checksum := resp.Header.Get("x-amz-checksum-sha256")
	_ = resp.Body.Close()

	if checksum == "" {
		t.Fatal("missing checksum in response")
	}

	// Verify via head
	resp = env.s3Request(t, "HEAD", "/checkbucket/file.bin", nil)
	if resp.Header.Get("x-amz-checksum-sha256") != checksum {
		t.Fatal("checksum mismatch between put and head")
	}
	_ = resp.Body.Close()
}

// setupWithSigning creates a test env with a signing secret configured.
func setupWithSigning(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	log := slog.Default()

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := recovery.Run(db, st, log); err != nil {
		t.Fatal(err)
	}

	au := auth.New(db)
	metrics := maintenance.NewMetrics()
	signingSecret := "test-signing-secret"
	s3Handler := jayapi.NewHandler(db, st, au, log, metrics, signingSecret, nil)
	s3Srv := httptest.NewServer(s3Handler)
	t.Cleanup(s3Srv.Close)

	adminHandler := admin.NewHandler(db, "test-admin", log, metrics, st, signingSecret, s3Srv.Listener.Addr().String(), false, au)
	adminSrv := httptest.NewServer(adminHandler)
	t.Cleanup(adminSrv.Close)

	account := createTestAccount(t, adminSrv.URL)
	tokenID, secret := createTestToken(t, adminSrv.URL, account)

	return &testEnv{
		db:          db,
		store:       st,
		s3Server:    s3Srv,
		adminServer: adminSrv,
		auth:        "Bearer " + tokenID + ":" + secret,
		tokenID:     tokenID,
		secret:      secret,
		accountID:   account,
	}
}

// === Presigned URL Tests ===

func computeTestSignature(signingSecret, tokenID, method, path, expires string) string {
	mac := hmac.New(sha256.New, []byte(signingSecret))
	// Include empty canonical query string to match updated signature format.
	mac.Write([]byte(tokenID + "\n" + method + "\n" + path + "\n" + "\n" + expires))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestPresignedURLGet(t *testing.T) {
	env := setupWithSigning(t)
	signingSecret := "test-signing-secret"

	// Create bucket and object
	resp := env.s3Request(t, "PUT", "/presign-bucket", nil)
	_ = resp.Body.Close()
	resp = env.s3Request(t, "PUT", "/presign-bucket/secret.txt", strings.NewReader("presigned content"))
	_ = resp.Body.Close()

	// Generate presigned URL
	expiresAt := time.Now().Add(5 * time.Minute).Unix()
	expiresStr := strconv.FormatInt(expiresAt, 10)
	path := "/presign-bucket/secret.txt"
	sig := computeTestSignature(signingSecret, env.tokenID, "GET", path, expiresStr)

	url := fmt.Sprintf("%s%s?X-Jay-Token=%s&X-Jay-Expires=%s&X-Jay-Signature=%s",
		env.s3Server.URL, path, env.tokenID, expiresStr, sig)

	// GET without auth header — presigned URL provides auth
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("presigned GET: expected 200, got %d: %s", resp.StatusCode, body)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "presigned content" {
		t.Fatalf("presigned GET: got %q, want %q", got, "presigned content")
	}
}

func TestPresignedURLExpired(t *testing.T) {
	env := setupWithSigning(t)
	signingSecret := "test-signing-secret"

	resp := env.s3Request(t, "PUT", "/presign-bucket2", nil)
	_ = resp.Body.Close()
	resp = env.s3Request(t, "PUT", "/presign-bucket2/file.txt", strings.NewReader("data"))
	_ = resp.Body.Close()

	// Expired 1 minute ago
	expiresAt := time.Now().Add(-1 * time.Minute).Unix()
	expiresStr := strconv.FormatInt(expiresAt, 10)
	path := "/presign-bucket2/file.txt"
	sig := computeTestSignature(signingSecret, env.tokenID, "GET", path, expiresStr)

	url := fmt.Sprintf("%s%s?X-Jay-Token=%s&X-Jay-Expires=%s&X-Jay-Signature=%s",
		env.s3Server.URL, path, env.tokenID, expiresStr, sig)

	req, _ := http.NewRequest("GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("expired presigned request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 403 {
		t.Fatalf("expired presigned: expected 403, got %d", resp.StatusCode)
	}
}

func TestPresignedURLBadSignature(t *testing.T) {
	env := setupWithSigning(t)

	resp := env.s3Request(t, "PUT", "/presign-bucket3", nil)
	_ = resp.Body.Close()
	resp = env.s3Request(t, "PUT", "/presign-bucket3/file.txt", strings.NewReader("data"))
	_ = resp.Body.Close()

	expiresAt := time.Now().Add(5 * time.Minute).Unix()
	expiresStr := strconv.FormatInt(expiresAt, 10)
	path := "/presign-bucket3/file.txt"

	url := fmt.Sprintf("%s%s?X-Jay-Token=%s&X-Jay-Expires=%s&X-Jay-Signature=%s",
		env.s3Server.URL, path, env.tokenID, expiresStr, "badsignature")

	req, _ := http.NewRequest("GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("bad signature request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 403 {
		t.Fatalf("bad signature: expected 403, got %d", resp.StatusCode)
	}
}

// === CopyObject Tests ===

func TestCopyObject(t *testing.T) {
	env := setup(t)

	// Create source bucket and object
	resp := env.s3Request(t, "PUT", "/src-bucket", nil)
	_ = resp.Body.Close()
	resp = env.s3Request(t, "PUT", "/dst-bucket", nil)
	_ = resp.Body.Close()

	content := "copy me!"
	req, _ := http.NewRequest("PUT", env.s3Server.URL+"/src-bucket/original.txt",
		strings.NewReader(content))
	req.Header.Set("Authorization", env.auth)
	req.Header.Set("x-amz-meta-author", "test")
	resp, _ = http.DefaultClient.Do(req)
	_ = resp.Body.Close()

	// Copy to different bucket
	req, _ = http.NewRequest("PUT", env.s3Server.URL+"/dst-bucket/copied.txt", nil)
	req.Header.Set("Authorization", env.auth)
	req.Header.Set("x-amz-copy-source", "/src-bucket/original.txt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("copy object: expected 200, got %d: %s", resp.StatusCode, body)
	}

	// Verify copy result XML has xmlns
	var copyResult jayapi.CopyObjectResult
	if err := xml.Unmarshal(body, &copyResult); err != nil {
		t.Fatalf("unmarshal copy result: %v", err)
	}
	if copyResult.ETag == "" {
		t.Fatal("copy result missing ETag")
	}

	// Get copied object
	resp = env.s3Request(t, "GET", "/dst-bucket/copied.txt", nil)
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(got) != content {
		t.Fatalf("copied content: got %q, want %q", got, content)
	}

	// Verify metadata preserved
	resp = env.s3Request(t, "HEAD", "/dst-bucket/copied.txt", nil)
	if resp.Header.Get("x-amz-meta-author") != "test" {
		t.Fatalf("copy metadata not preserved: got %q", resp.Header.Get("x-amz-meta-author"))
	}
	_ = resp.Body.Close()
}

func TestCopyObjectSameBucket(t *testing.T) {
	env := setup(t)

	resp := env.s3Request(t, "PUT", "/copybucket", nil)
	_ = resp.Body.Close()
	resp = env.s3Request(t, "PUT", "/copybucket/a.txt", strings.NewReader("hello"))
	_ = resp.Body.Close()

	req, _ := http.NewRequest("PUT", env.s3Server.URL+"/copybucket/b.txt", nil)
	req.Header.Set("Authorization", env.auth)
	req.Header.Set("x-amz-copy-source", "/copybucket/a.txt")
	resp, _ = http.DefaultClient.Do(req)
	_ = resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("copy same bucket: expected 200, got %d", resp.StatusCode)
	}

	resp = env.s3Request(t, "GET", "/copybucket/b.txt", nil)
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(got) != "hello" {
		t.Fatalf("copy same bucket content: got %q", got)
	}
}

func TestCopyObjectNonExistentSource(t *testing.T) {
	env := setup(t)

	resp := env.s3Request(t, "PUT", "/copybucket2", nil)
	_ = resp.Body.Close()

	req, _ := http.NewRequest("PUT", env.s3Server.URL+"/copybucket2/dest.txt", nil)
	req.Header.Set("Authorization", env.auth)
	req.Header.Set("x-amz-copy-source", "/copybucket2/nonexistent.txt")
	resp, _ = http.DefaultClient.Do(req)
	_ = resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Fatalf("copy non-existent: expected 404, got %d", resp.StatusCode)
	}
}

// === Range Request Tests ===

func TestRangeRequests(t *testing.T) {
	env := setup(t)

	resp := env.s3Request(t, "PUT", "/rangebucket", nil)
	_ = resp.Body.Close()

	// Upload a known content
	content := "0123456789abcdefghij" // 20 bytes
	resp = env.s3Request(t, "PUT", "/rangebucket/data.txt", strings.NewReader(content))
	_ = resp.Body.Close()

	tests := []struct {
		name       string
		rangeHdr   string
		wantStatus int
		wantBody   string
	}{
		{"first 5 bytes", "bytes=0-4", 206, "01234"},
		{"middle range", "bytes=5-9", 206, "56789"},
		{"suffix range", "bytes=-5", 206, "fghij"},
		{"open-ended", "bytes=15-", 206, "fghij"},
		{"single byte", "bytes=0-0", 206, "0"},
		{"entire file", "bytes=0-19", 206, content},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", env.s3Server.URL+"/rangebucket/data.txt", nil)
			req.Header.Set("Authorization", env.auth)
			req.Header.Set("Range", tt.rangeHdr)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status: got %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			got, _ := io.ReadAll(resp.Body)
			if string(got) != tt.wantBody {
				t.Fatalf("body: got %q, want %q", got, tt.wantBody)
			}
			if tt.wantStatus == 206 {
				if resp.Header.Get("Content-Range") == "" {
					t.Fatal("missing Content-Range header")
				}
			}
		})
	}
}

func TestRangeRequestInvalid(t *testing.T) {
	env := setup(t)

	resp := env.s3Request(t, "PUT", "/rangebucket2", nil)
	_ = resp.Body.Close()
	resp = env.s3Request(t, "PUT", "/rangebucket2/small.txt", strings.NewReader("tiny"))
	_ = resp.Body.Close()

	// Range beyond file size
	req, _ := http.NewRequest("GET", env.s3Server.URL+"/rangebucket2/small.txt", nil)
	req.Header.Set("Authorization", env.auth)
	req.Header.Set("Range", "bytes=100-200")
	resp, _ = http.DefaultClient.Do(req)
	_ = resp.Body.Close()

	if resp.StatusCode != 416 {
		t.Fatalf("invalid range: expected 416, got %d", resp.StatusCode)
	}
}

// === Multipart Upload Extended Tests ===

func TestMultipartUploadComplete(t *testing.T) {
	env := setup(t)

	resp := env.s3Request(t, "PUT", "/mpbucket", nil)
	_ = resp.Body.Close()

	// Create multipart upload
	resp = env.s3Request(t, "POST", "/mpbucket/bigfile.bin?uploads", nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var initResult jayapi.InitiateMultipartUploadResult
	if err := xml.Unmarshal(body, &initResult); err != nil {
		t.Fatalf("unmarshal multipart init: %v", err)
	}
	uploadID := initResult.UploadId
	if uploadID == "" {
		t.Fatal("missing upload ID")
	}

	// Upload two parts
	part1 := strings.Repeat("A", 1024)
	part2 := strings.Repeat("B", 1024)

	resp = env.s3Request(t, "PUT",
		fmt.Sprintf("/mpbucket/bigfile.bin?uploadId=%s&partNumber=1", uploadID),
		strings.NewReader(part1))
	etag1 := resp.Header.Get("ETag")
	_ = resp.Body.Close()

	resp = env.s3Request(t, "PUT",
		fmt.Sprintf("/mpbucket/bigfile.bin?uploadId=%s&partNumber=2", uploadID),
		strings.NewReader(part2))
	etag2 := resp.Header.Get("ETag")
	_ = resp.Body.Close()

	// List parts
	resp = env.s3Request(t, "GET",
		fmt.Sprintf("/mpbucket/bigfile.bin?uploadId=%s", uploadID), nil)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var listParts jayapi.ListPartsResult
	if err := xml.Unmarshal(body, &listParts); err != nil {
		t.Fatalf("unmarshal list parts: %v", err)
	}
	if len(listParts.Parts) != 2 {
		t.Fatalf("list parts: got %d, want 2", len(listParts.Parts))
	}

	// Complete
	completeXML := fmt.Sprintf(`<CompleteMultipartUpload>
		<Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part>
		<Part><PartNumber>2</PartNumber><ETag>%s</ETag></Part>
	</CompleteMultipartUpload>`, etag1, etag2)

	resp = env.s3Request(t, "POST",
		fmt.Sprintf("/mpbucket/bigfile.bin?uploadId=%s", uploadID),
		strings.NewReader(completeXML))
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("complete: expected 200, got %d: %s", resp.StatusCode, body)
	}
	_ = resp.Body.Close()

	// Verify assembled object
	resp = env.s3Request(t, "GET", "/mpbucket/bigfile.bin", nil)
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	expected := part1 + part2
	if string(got) != expected {
		t.Fatalf("assembled object: got %d bytes, want %d", len(got), len(expected))
	}
}

func TestMultipartUploadAbort(t *testing.T) {
	env := setup(t)

	resp := env.s3Request(t, "PUT", "/mpabortbucket", nil)
	_ = resp.Body.Close()

	// Create multipart upload
	resp = env.s3Request(t, "POST", "/mpabortbucket/file.bin?uploads", nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var initResult jayapi.InitiateMultipartUploadResult
	if err := xml.Unmarshal(body, &initResult); err != nil {
		t.Fatalf("unmarshal multipart init: %v", err)
	}
	uploadID := initResult.UploadId

	// Upload a part
	resp = env.s3Request(t, "PUT",
		fmt.Sprintf("/mpabortbucket/file.bin?uploadId=%s&partNumber=1", uploadID),
		strings.NewReader("partial data"))
	_ = resp.Body.Close()

	// Abort
	resp = env.s3Request(t, "DELETE",
		fmt.Sprintf("/mpabortbucket/file.bin?uploadId=%s", uploadID), nil)
	if resp.StatusCode != 204 {
		t.Fatalf("abort: expected 204, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Object should not exist
	resp = env.s3Request(t, "GET", "/mpabortbucket/file.bin", nil)
	if resp.StatusCode != 404 {
		t.Fatalf("after abort: expected 404, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// === Bucket Policy Tests ===

func TestBucketPolicyDenyOverridesAllow(t *testing.T) {
	policy := &auth.BucketPolicy{
		Version: "2024-01-01",
		Statements: []auth.PolicyStatement{
			{Effect: "allow", Actions: []string{"*"}, Subjects: []string{"*"}},
			{Effect: "deny", Actions: []string{"object:put"}, Subjects: []string{"*"}, Prefixes: []string{"readonly/"}},
		},
	}

	allowed, denied := auth.EvaluatePolicy(policy, "any-token", "object:put", "readonly/file.txt", "127.0.0.1")
	if allowed {
		t.Fatal("expected not allowed (deny should override)")
	}
	if !denied {
		t.Fatal("expected denied")
	}
}

func TestBucketPolicyPrefixMatch(t *testing.T) {
	policy := &auth.BucketPolicy{
		Version: "2024-01-01",
		Statements: []auth.PolicyStatement{
			{Effect: "allow", Actions: []string{"object:get"}, Subjects: []string{"*"}, Prefixes: []string{"public/"}},
		},
	}

	allowed, _ := auth.EvaluatePolicy(policy, "any", "object:get", "public/file.txt", "")
	if !allowed {
		t.Fatal("expected allowed for matching prefix")
	}

	allowed, _ = auth.EvaluatePolicy(policy, "any", "object:get", "private/file.txt", "")
	if allowed {
		t.Fatal("expected not allowed for non-matching prefix")
	}
}

func TestBucketPolicyIPCondition(t *testing.T) {
	policy := &auth.BucketPolicy{
		Version: "2024-01-01",
		Statements: []auth.PolicyStatement{
			{
				Effect:   "allow",
				Actions:  []string{"*"},
				Subjects: []string{"*"},
				Conditions: &auth.PolicyConditions{
					IPWhitelist: []string{"10.0.0.0/8"},
				},
			},
		},
	}

	allowed, _ := auth.EvaluatePolicy(policy, "any", "object:get", "file.txt", "10.1.2.3")
	if !allowed {
		t.Fatal("expected allowed from whitelisted IP")
	}

	allowed, _ = auth.EvaluatePolicy(policy, "any", "object:get", "file.txt", "192.168.1.1")
	if allowed {
		t.Fatal("expected not allowed from non-whitelisted IP")
	}
}

func TestBucketPolicyWildcardSubjects(t *testing.T) {
	policy := &auth.BucketPolicy{
		Version: "2024-01-01",
		Statements: []auth.PolicyStatement{
			{Effect: "allow", Actions: []string{"object:get"}, Subjects: []string{"*"}},
		},
	}

	allowed, _ := auth.EvaluatePolicy(policy, "random-token-id", "object:get", "any/key", "")
	if !allowed {
		t.Fatal("expected allowed for wildcard subject")
	}
}

func TestBucketPolicySpecificSubject(t *testing.T) {
	policy := &auth.BucketPolicy{
		Version: "2024-01-01",
		Statements: []auth.PolicyStatement{
			{Effect: "allow", Actions: []string{"object:get"}, Subjects: []string{"token-abc"}},
		},
	}

	allowed, _ := auth.EvaluatePolicy(policy, "token-abc", "object:get", "file.txt", "")
	if !allowed {
		t.Fatal("expected allowed for matching subject")
	}

	allowed, _ = auth.EvaluatePolicy(policy, "token-xyz", "object:get", "file.txt", "")
	if allowed {
		t.Fatal("expected not allowed for non-matching subject")
	}
}

func TestBucketPolicyNilPolicy(t *testing.T) {
	allowed, denied := auth.EvaluatePolicy(nil, "any", "object:get", "file.txt", "")
	if allowed || denied {
		t.Fatal("nil policy should return false, false")
	}
}

// === Quarantine Tests ===

func TestQuarantineListAndPurge(t *testing.T) {
	dir := t.TempDir()
	log := slog.Default()

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := recovery.Run(db, st, log); err != nil {
		t.Fatal(err)
	}

	au := auth.New(db)
	metrics := maintenance.NewMetrics()
	s3Handler := jayapi.NewHandler(db, st, au, log, metrics, "", nil)
	s3Srv := httptest.NewServer(s3Handler)
	defer s3Srv.Close()

	adminHandler := admin.NewHandler(db, "test-admin", log, metrics, st, "", "", false, au)
	adminSrv := httptest.NewServer(adminHandler)
	defer adminSrv.Close()

	account := createTestAccount(t, adminSrv.URL)
	tokenID, secret := createTestToken(t, adminSrv.URL, account)
	authHdr := "Bearer " + tokenID + ":" + secret

	// Create bucket and object
	req, _ := http.NewRequest("PUT", s3Srv.URL+"/qbucket", nil)
	req.Header.Set("Authorization", authHdr)
	resp, _ := http.DefaultClient.Do(req)
	_ = resp.Body.Close()

	req, _ = http.NewRequest("PUT", s3Srv.URL+"/qbucket/file.txt", strings.NewReader("quarantine test"))
	req.Header.Set("Authorization", authHdr)
	resp, _ = http.DefaultClient.Do(req)
	_ = resp.Body.Close()

	// Get bucket ID
	bucket, _ := db.GetBucket("qbucket")

	// Quarantine the object
	if err := db.QuarantineObject(bucket.ID, "file.txt"); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	// List quarantined via QuarantineManager
	qm := maintenance.NewQuarantineManager(db, st, log)
	quarantined, err := qm.ListQuarantined()
	if err != nil {
		t.Fatal(err)
	}
	if len(quarantined) != 1 {
		t.Fatalf("expected 1 quarantined, got %d", len(quarantined))
	}
	if quarantined[0].Key != "file.txt" {
		t.Fatalf("quarantined key: got %q", quarantined[0].Key)
	}

	// Inspect — file should exist with matching checksum
	inspection, err := qm.Inspect(bucket.ID, "file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.FileExists {
		t.Fatal("quarantined file should exist")
	}
	if !inspection.ChecksumMatch {
		t.Fatal("checksum should match (file is not actually corrupted)")
	}

	// Revalidate — should restore since checksum matches
	restored, err := qm.Revalidate(bucket.ID, "file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !restored {
		t.Fatal("expected object to be restored")
	}

	// Should be accessible again
	req, _ = http.NewRequest("GET", s3Srv.URL+"/qbucket/file.txt", nil)
	req.Header.Set("Authorization", authHdr)
	resp, _ = http.DefaultClient.Do(req)
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(got) != "quarantine test" {
		t.Fatalf("after revalidation: got %q", got)
	}

	// Quarantine again and purge
	if err := db.QuarantineObject(bucket.ID, "file.txt"); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	purged, err := qm.PurgeAll()
	if err != nil {
		t.Fatal(err)
	}
	if purged != 1 {
		t.Fatalf("expected 1 purged, got %d", purged)
	}

	// Should be gone
	quarantined, _ = qm.ListQuarantined()
	if len(quarantined) != 0 {
		t.Fatalf("expected 0 quarantined after purge, got %d", len(quarantined))
	}
}

// === Rate Limiting Tests ===

func TestRateLimiting(t *testing.T) {
	dir := t.TempDir()
	log := slog.Default()

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := recovery.Run(db, st, log); err != nil {
		t.Fatal(err)
	}

	au := auth.New(db)
	metrics := maintenance.NewMetrics()

	// Very low rate limit: 2 req/sec, burst 3
	rlCfg := &jayapi.RateLimiterConfig{Rate: 2, Burst: 3}
	s3Handler := jayapi.NewHandler(db, st, au, log, metrics, "", rlCfg)
	s3Srv := httptest.NewServer(s3Handler)
	defer s3Srv.Close()

	adminHandler := admin.NewHandler(db, "test-admin", log, metrics, st, "", "", false, au)
	adminSrv := httptest.NewServer(adminHandler)
	defer adminSrv.Close()

	account := createTestAccount(t, adminSrv.URL)
	tokenID, secret := createTestToken(t, adminSrv.URL, account)
	authHdr := "Bearer " + tokenID + ":" + secret

	// Create bucket
	req, _ := http.NewRequest("PUT", s3Srv.URL+"/rl-bucket", nil)
	req.Header.Set("Authorization", authHdr)
	resp, _ := http.DefaultClient.Do(req)
	_ = resp.Body.Close()

	// Exhaust burst (3 requests should pass, then fail)
	var got429 bool
	for range 10 {
		req, _ := http.NewRequest("HEAD", s3Srv.URL+"/rl-bucket", nil)
		req.Header.Set("Authorization", authHdr)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == 429 {
			got429 = true
			if resp.Header.Get("Retry-After") == "" {
				t.Fatal("429 response missing Retry-After header")
			}
			break
		}
	}
	if !got429 {
		t.Fatal("expected 429 after exceeding rate limit")
	}
}

// helpers

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
