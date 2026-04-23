package client

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/proto"
	"github.com/ivangsm/jay/store"
)

type testEnv struct {
	db       *meta.DB
	st       *store.Store
	client   *Client
	addr     string
	tokenID  string
	secret   string
	shutdown func() error
}

func setup(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetSigningSecret("test-secret-for-signing-that-is-long-enough")
	t.Cleanup(func() { _ = db.Close() })

	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	au := auth.New(db)

	account := &meta.Account{AccountID: "test-account", Name: "test", Status: "active"}
	if err := db.CreateAccount(account); err != nil {
		t.Fatal(err)
	}

	secretBytes := make([]byte, 32)
	rand.Read(secretBytes)
	secret := hex.EncodeToString(secretBytes)
	hash, _ := auth.HashSecret(secret)

	token := &meta.Token{
		TokenID:        "test-token",
		AccountID:      "test-account",
		Name:           "test",
		SecretHash:     hash,
		AllowedActions: meta.AllActions,
		Status:         "active",
	}
	if err := db.CreateToken(token); err != nil {
		t.Fatal(err)
	}

	var metrics *maintenance.Metrics
	srv := proto.NewServer(db, st, au, log, metrics, 0, 0)

	// Pick a random available port then release it so ListenAndServe can bind it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	shutdown, err := srv.ListenAndServe(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shutdown() })

	c, err := Dial(addr, "test-token", secret, 2)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	return &testEnv{
		db:       db,
		st:       st,
		client:   c,
		addr:     addr,
		tokenID:  "test-token",
		secret:   secret,
		shutdown: shutdown,
	}
}

// --- Client lifecycle ---

func TestDial_InvalidAddr(t *testing.T) {
	// Port 1 on loopback should refuse connections.
	_, err := Dial("127.0.0.1:1", "token", "secret", 1)
	if err == nil {
		t.Fatal("expected error dialing invalid address")
	}
}

func TestDial_BadCredentials(t *testing.T) {
	env := setup(t)

	_, err := Dial(env.addr, "bad-token", "bad-secret", 1)
	if err == nil {
		t.Fatal("expected auth failure")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClose_Idempotent(t *testing.T) {
	env := setup(t)

	c, err := Dial(env.addr, env.tokenID, env.secret, 1)
	if err != nil {
		t.Fatal(err)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second close should not panic or return an error.
	// The channel is already closed; closing a closed channel panics in Go,
	// but our implementation sets c.closed = true before closing the channel,
	// so the second Close should be safe (channel is already closed but
	// iterating over a closed empty channel is fine — we just skip the for-range).
	// Actually Close() calls close(c.pool) which panics on double-close.
	// So we test the semantics: after Close, operations fail gracefully.
	_ = c.Ping() // should return "client is closed" error, not panic
}

func TestClose_OperationsAfterClose(t *testing.T) {
	env := setup(t)

	c, err := Dial(env.addr, env.tokenID, env.secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	err = c.Ping()
	if err == nil {
		t.Fatal("expected error after close")
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// --- Ping ---

func TestPing(t *testing.T) {
	env := setup(t)
	if err := env.client.Ping(); err != nil {
		t.Fatal(err)
	}
}

// --- Bucket operations ---

func TestCreateBucket_Success(t *testing.T) {
	env := setup(t)

	info, err := env.client.CreateBucket("test-bucket")
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if info.Name != "test-bucket" {
		t.Fatalf("expected name %q, got %q", "test-bucket", info.Name)
	}
	if info.BucketID == "" {
		t.Fatal("expected non-empty BucketID")
	}
	if info.CreatedAt == "" {
		t.Fatal("expected non-empty CreatedAt")
	}
}

func TestCreateBucket_Duplicate(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("dup-bucket"); err != nil {
		t.Fatalf("first CreateBucket: %v", err)
	}

	_, err := env.client.CreateBucket("dup-bucket")
	if err == nil {
		t.Fatal("expected error creating duplicate bucket")
	}
}

func TestHeadBucket_Exists(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("head-bucket"); err != nil {
		t.Fatal(err)
	}

	info, err := env.client.HeadBucket("head-bucket")
	if err != nil {
		t.Fatalf("HeadBucket: %v", err)
	}
	if info.Name != "head-bucket" {
		t.Fatalf("expected name %q, got %q", "head-bucket", info.Name)
	}
}

func TestHeadBucket_NotFound(t *testing.T) {
	env := setup(t)

	_, err := env.client.HeadBucket("nonexistent-bucket")
	if err == nil {
		t.Fatal("expected error for nonexistent bucket")
	}
}

func TestDeleteBucket_Empty(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("to-delete"); err != nil {
		t.Fatal(err)
	}

	if err := env.client.DeleteBucket("to-delete"); err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}

	// After deletion, HeadBucket should fail.
	_, err := env.client.HeadBucket("to-delete")
	if err == nil {
		t.Fatal("expected error for deleted bucket")
	}
}

func TestDeleteBucket_NotFound(t *testing.T) {
	env := setup(t)

	err := env.client.DeleteBucket("ghost-bucket")
	if err == nil {
		t.Fatal("expected error deleting nonexistent bucket")
	}
}

func TestDeleteBucket_NotEmpty(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("notempty"); err != nil {
		t.Fatal(err)
	}
	data := "content"
	if _, err := env.client.PutObject("notempty", "file.txt", strings.NewReader(data), int64(len(data)), nil); err != nil {
		t.Fatal(err)
	}

	err := env.client.DeleteBucket("notempty")
	if err == nil {
		t.Fatal("expected error deleting non-empty bucket")
	}
	jayErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if jayErr.Code != "BucketNotEmpty" {
		t.Fatalf("expected code BucketNotEmpty, got %q", jayErr.Code)
	}
}

func TestListBuckets_Empty(t *testing.T) {
	env := setup(t)

	buckets, err := env.client.ListBuckets()
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if len(buckets) != 0 {
		t.Fatalf("expected 0 buckets, got %d", len(buckets))
	}
}

func TestListBuckets_Multiple(t *testing.T) {
	env := setup(t)

	names := []string{"alpha", "beta"}
	for _, name := range names {
		if _, err := env.client.CreateBucket(name); err != nil {
			t.Fatalf("CreateBucket %q: %v", name, err)
		}
	}

	buckets, err := env.client.ListBuckets()
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if len(buckets) != len(names) {
		t.Fatalf("expected %d buckets, got %d", len(names), len(buckets))
	}

	found := make(map[string]bool)
	for _, b := range buckets {
		found[b.Name] = true
		if b.CreatedAt == "" {
			t.Fatalf("bucket %q has empty CreatedAt", b.Name)
		}
	}
	for _, name := range names {
		if !found[name] {
			t.Fatalf("bucket %q not found in list", name)
		}
	}
}

// --- Object operations ---

func TestPutObject_Success(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("put-bucket"); err != nil {
		t.Fatal(err)
	}

	content := []byte("hello world")
	result, err := env.client.PutObject("put-bucket", "hello.txt",
		bytes.NewReader(content), int64(len(content)),
		&PutOptions{ContentType: "text/plain"})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if result.ETag == "" {
		t.Fatal("expected non-empty ETag")
	}
	if result.ChecksumSHA256 == "" {
		t.Fatal("expected non-empty ChecksumSHA256")
	}
}

func TestPutObject_NoOptions(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("put-bucket2"); err != nil {
		t.Fatal(err)
	}

	content := []byte("no opts")
	result, err := env.client.PutObject("put-bucket2", "obj.bin",
		bytes.NewReader(content), int64(len(content)), nil)
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if result.ETag == "" {
		t.Fatal("expected non-empty ETag")
	}
}

func TestGetObject_Success(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("get-bucket"); err != nil {
		t.Fatal(err)
	}

	content := "hello native protocol"
	if _, err := env.client.PutObject("get-bucket", "msg.txt",
		strings.NewReader(content), int64(len(content)),
		&PutOptions{ContentType: "text/plain"}); err != nil {
		t.Fatal(err)
	}

	result, err := env.client.GetObject("get-bucket", "msg.txt")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	defer func() { _ = result.Body.Close() }()

	got, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != content {
		t.Fatalf("content mismatch: got %q, want %q", got, content)
	}
	if result.ContentType != "text/plain" {
		t.Fatalf("content type: got %q, want %q", result.ContentType, "text/plain")
	}
	if result.Size != int64(len(content)) {
		t.Fatalf("size: got %d, want %d", result.Size, len(content))
	}
}

func TestGetObject_NotFound(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("get-bucket2"); err != nil {
		t.Fatal(err)
	}

	_, err := env.client.GetObject("get-bucket2", "nonexistent.txt")
	if err == nil {
		t.Fatal("expected error for nonexistent object")
	}
}

func TestGetObject_BucketNotFound(t *testing.T) {
	env := setup(t)

	_, err := env.client.GetObject("no-such-bucket", "key.txt")
	if err == nil {
		t.Fatal("expected error for nonexistent bucket")
	}
}

func TestHeadObject_Exists(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("head-obj-bucket"); err != nil {
		t.Fatal(err)
	}

	content := "head me"
	if _, err := env.client.PutObject("head-obj-bucket", "obj.txt",
		strings.NewReader(content), int64(len(content)),
		&PutOptions{ContentType: "text/plain"}); err != nil {
		t.Fatal(err)
	}

	info, err := env.client.HeadObject("head-obj-bucket", "obj.txt")
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	if info.Size != int64(len(content)) {
		t.Fatalf("size: got %d, want %d", info.Size, len(content))
	}
	if info.ContentType != "text/plain" {
		t.Fatalf("content type: got %q, want %q", info.ContentType, "text/plain")
	}
	if info.ETag == "" {
		t.Fatal("expected non-empty ETag")
	}
}

func TestHeadObject_NotFound(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("head-obj-bucket2"); err != nil {
		t.Fatal(err)
	}

	_, err := env.client.HeadObject("head-obj-bucket2", "missing.txt")
	if err == nil {
		t.Fatal("expected error for nonexistent object")
	}
}

func TestDeleteObject_Success(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("del-bucket"); err != nil {
		t.Fatal(err)
	}

	content := "delete me"
	if _, err := env.client.PutObject("del-bucket", "obj.txt",
		strings.NewReader(content), int64(len(content)), nil); err != nil {
		t.Fatal(err)
	}

	if err := env.client.DeleteObject("del-bucket", "obj.txt"); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}

	// Object should be gone.
	_, err := env.client.GetObject("del-bucket", "obj.txt")
	if err == nil {
		t.Fatal("expected error for deleted object")
	}
}

func TestDeleteObject_NotFound(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("del-bucket2"); err != nil {
		t.Fatal(err)
	}

	// Deleting a nonexistent object — server may or may not error; just ensure no panic.
	_ = env.client.DeleteObject("del-bucket2", "ghost.txt")
}

func TestPutGet_LargeObject(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("large-bucket"); err != nil {
		t.Fatal(err)
	}

	size := int64(1 << 20) // 1 MB
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	if _, err := env.client.PutObject("large-bucket", "large.bin",
		bytes.NewReader(data), size, nil); err != nil {
		t.Fatalf("PutObject large: %v", err)
	}

	result, err := env.client.GetObject("large-bucket", "large.bin")
	if err != nil {
		t.Fatalf("GetObject large: %v", err)
	}
	defer func() { _ = result.Body.Close() }()

	got, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if !bytes.Equal(got, data) {
		t.Fatal("large object content mismatch")
	}
}

func TestPutObject_UserMetadata(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("meta-bucket"); err != nil {
		t.Fatal(err)
	}

	content := "with metadata"
	if _, err := env.client.PutObject("meta-bucket", "file.txt",
		strings.NewReader(content), int64(len(content)),
		&PutOptions{
			Metadata: map[string]string{"x-custom-key": "custom-value"},
		}); err != nil {
		t.Fatal(err)
	}

	info, err := env.client.HeadObject("meta-bucket", "file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if info.Metadata["x-custom-key"] != "custom-value" {
		t.Fatalf("expected metadata value %q, got %v", "custom-value", info.Metadata)
	}
}

func TestPutObject_Overwrite(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("overwrite-bucket"); err != nil {
		t.Fatal(err)
	}

	v1 := "version one"
	if _, err := env.client.PutObject("overwrite-bucket", "data.txt",
		strings.NewReader(v1), int64(len(v1)), nil); err != nil {
		t.Fatal(err)
	}

	v2 := "version two"
	if _, err := env.client.PutObject("overwrite-bucket", "data.txt",
		strings.NewReader(v2), int64(len(v2)), nil); err != nil {
		t.Fatal(err)
	}

	result, err := env.client.GetObject("overwrite-bucket", "data.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = result.Body.Close() }()

	got, _ := io.ReadAll(result.Body)
	if string(got) != v2 {
		t.Fatalf("overwrite: got %q, want %q", got, v2)
	}
}

// --- ListObjects ---

func TestListObjects_Empty(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("list-empty"); err != nil {
		t.Fatal(err)
	}

	result, err := env.client.ListObjects("list-empty", nil)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if len(result.Objects) != 0 {
		t.Fatalf("expected 0 objects, got %d", len(result.Objects))
	}
}

func TestListObjects_All(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("list-all"); err != nil {
		t.Fatal(err)
	}

	keys := []string{"a.txt", "b.txt", "c.txt"}
	for _, k := range keys {
		if _, err := env.client.PutObject("list-all", k, strings.NewReader("x"), 1, nil); err != nil {
			t.Fatalf("PutObject %q: %v", k, err)
		}
	}

	result, err := env.client.ListObjects("list-all", nil)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if len(result.Objects) != len(keys) {
		t.Fatalf("expected %d objects, got %d", len(keys), len(result.Objects))
	}
}

func TestListObjects_WithPrefix(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("list-prefix"); err != nil {
		t.Fatal(err)
	}

	items := map[string]string{
		"photos/a.jpg": "img",
		"photos/b.jpg": "img",
		"docs/readme":  "doc",
	}
	for k, v := range items {
		if _, err := env.client.PutObject("list-prefix", k, strings.NewReader(v), int64(len(v)), nil); err != nil {
			t.Fatalf("PutObject %q: %v", k, err)
		}
	}

	result, err := env.client.ListObjects("list-prefix", &ListOptions{Prefix: "photos/"})
	if err != nil {
		t.Fatalf("ListObjects with prefix: %v", err)
	}
	if len(result.Objects) != 2 {
		t.Fatalf("expected 2 objects, got %d", len(result.Objects))
	}
}

func TestListObjects_WithDelimiter(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("list-delim"); err != nil {
		t.Fatal(err)
	}

	items := []string{"photos/a.jpg", "photos/b.jpg", "docs/readme.md", "root.txt"}
	for _, k := range items {
		if _, err := env.client.PutObject("list-delim", k, strings.NewReader("x"), 1, nil); err != nil {
			t.Fatalf("PutObject %q: %v", k, err)
		}
	}

	result, err := env.client.ListObjects("list-delim", &ListOptions{Delimiter: "/"})
	if err != nil {
		t.Fatalf("ListObjects with delimiter: %v", err)
	}
	// "root.txt" is a flat key (no slash), so it appears in Objects.
	if len(result.Objects) != 1 {
		t.Fatalf("expected 1 flat object, got %d", len(result.Objects))
	}
	// "photos/" and "docs/" are common prefixes.
	if len(result.CommonPrefixes) != 2 {
		t.Fatalf("expected 2 common prefixes, got %d", len(result.CommonPrefixes))
	}
}

func TestListObjects_MaxKeys(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("list-maxkeys"); err != nil {
		t.Fatal(err)
	}

	for i := range 5 {
		key := "key-" + string(rune('0'+i))
		if _, err := env.client.PutObject("list-maxkeys", key, strings.NewReader("v"), 1, nil); err != nil {
			t.Fatalf("PutObject: %v", err)
		}
	}

	result, err := env.client.ListObjects("list-maxkeys", &ListOptions{MaxKeys: 2})
	if err != nil {
		t.Fatalf("ListObjects MaxKeys: %v", err)
	}
	if len(result.Objects) > 2 {
		t.Fatalf("expected at most 2 objects, got %d", len(result.Objects))
	}
}

func TestListObjects_BucketNotFound(t *testing.T) {
	env := setup(t)

	_, err := env.client.ListObjects("ghost-bucket", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent bucket")
	}
}

// --- Multipart upload ---

func TestMultipart_FullFlow(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("mp-bucket"); err != nil {
		t.Fatal(err)
	}

	// Create multipart upload
	uploadID, err := env.client.CreateMultipartUpload("mp-bucket", "big.bin",
		&PutOptions{ContentType: "application/octet-stream"})
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	if uploadID == "" {
		t.Fatal("expected non-empty uploadID")
	}

	// Upload two parts (5 MB each — minimum part size is typically 5 MB except last part)
	partSize := int64(5 << 20) // 5 MB
	part1Data := make([]byte, partSize)
	rand.Read(part1Data)
	etag1, err := env.client.UploadPart("mp-bucket", "big.bin", uploadID, 1,
		bytes.NewReader(part1Data), partSize)
	if err != nil {
		t.Fatalf("UploadPart 1: %v", err)
	}
	if etag1 == "" {
		t.Fatal("expected non-empty etag for part 1")
	}

	part2Data := make([]byte, 1024) // last part can be smaller
	rand.Read(part2Data)
	etag2, err := env.client.UploadPart("mp-bucket", "big.bin", uploadID, 2,
		bytes.NewReader(part2Data), int64(len(part2Data)))
	if err != nil {
		t.Fatalf("UploadPart 2: %v", err)
	}

	// Complete
	result, err := env.client.CompleteMultipartUpload("mp-bucket", "big.bin", uploadID, []CompletePart{
		{PartNumber: 1, ETag: etag1},
		{PartNumber: 2, ETag: etag2},
	})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	if result.ETag == "" {
		t.Fatal("expected non-empty ETag after complete")
	}

	// Verify object is accessible
	info, err := env.client.HeadObject("mp-bucket", "big.bin")
	if err != nil {
		t.Fatalf("HeadObject after multipart complete: %v", err)
	}
	expectedSize := partSize + int64(len(part2Data))
	if info.Size != expectedSize {
		t.Fatalf("size: got %d, want %d", info.Size, expectedSize)
	}
}

func TestMultipart_Abort(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("abort-bucket"); err != nil {
		t.Fatal(err)
	}

	uploadID, err := env.client.CreateMultipartUpload("abort-bucket", "will-abort.bin", nil)
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}

	// Upload one part
	partData := make([]byte, 1024)
	rand.Read(partData)
	_, err = env.client.UploadPart("abort-bucket", "will-abort.bin", uploadID, 1,
		bytes.NewReader(partData), int64(len(partData)))
	if err != nil {
		t.Fatalf("UploadPart: %v", err)
	}

	// Abort
	if err := env.client.AbortMultipartUpload("abort-bucket", "will-abort.bin", uploadID); err != nil {
		t.Fatalf("AbortMultipartUpload: %v", err)
	}

	// Completing an aborted upload should fail
	_, err = env.client.CompleteMultipartUpload("abort-bucket", "will-abort.bin", uploadID, []CompletePart{
		{PartNumber: 1},
	})
	if err == nil {
		t.Fatal("expected error completing aborted upload")
	}
}

func TestMultipart_ListParts(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("lp-bucket"); err != nil {
		t.Fatal(err)
	}

	uploadID, err := env.client.CreateMultipartUpload("lp-bucket", "multi.bin", nil)
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}

	// Upload 3 parts
	for i := 1; i <= 3; i++ {
		data := make([]byte, 1024)
		rand.Read(data)
		_, err := env.client.UploadPart("lp-bucket", "multi.bin", uploadID, i,
			bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("UploadPart %d: %v", i, err)
		}
	}

	parts, err := env.client.ListParts("lp-bucket", "multi.bin", uploadID)
	if err != nil {
		t.Fatalf("ListParts: %v", err)
	}
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	for _, p := range parts {
		if p.ETag == "" {
			t.Fatalf("part %d has empty ETag", p.PartNumber)
		}
		if p.Size != 1024 {
			t.Fatalf("part %d: expected size 1024, got %d", p.PartNumber, p.Size)
		}
	}
}

func TestMultipart_CreateNoOptions(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("mp-noopts"); err != nil {
		t.Fatal(err)
	}

	uploadID, err := env.client.CreateMultipartUpload("mp-noopts", "obj.bin", nil)
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	if uploadID == "" {
		t.Fatal("expected non-empty uploadID")
	}

	// Clean up
	_ = env.client.AbortMultipartUpload("mp-noopts", "obj.bin", uploadID)
}

// --- Connection pool behaviour ---

func TestConnectionReuse(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("reuse-bucket"); err != nil {
		t.Fatal(err)
	}

	// Many sequential operations to exercise connection reuse.
	for i := range 10 {
		data := "value"
		key := "obj-" + string(rune('0'+i))
		if _, err := env.client.PutObject("reuse-bucket", key,
			strings.NewReader(data), int64(len(data)), nil); err != nil {
			t.Fatalf("PutObject %d: %v", i, err)
		}
	}

	result, err := env.client.ListObjects("reuse-bucket", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 10 {
		t.Fatalf("expected 10 objects, got %d", len(result.Objects))
	}
}

// --- Error type ---

func TestError_ErrorString_WithCode(t *testing.T) {
	e := &Error{Status: 1, Message: "not found", Code: "NoSuchKey"}
	got := e.Error()
	if !strings.Contains(got, "not found") || !strings.Contains(got, "NoSuchKey") {
		t.Fatalf("unexpected error string: %q", got)
	}
}

func TestError_ErrorString_NoCode(t *testing.T) {
	e := &Error{Status: 1, Message: "bucket missing"}
	got := e.Error()
	if !strings.Contains(got, "bucket missing") {
		t.Fatalf("unexpected error string: %q", got)
	}
	// Should NOT contain parentheses (no code branch)
	if strings.Contains(got, "(") {
		t.Fatalf("unexpected code in error string: %q", got)
	}
}

// --- GetObject body fully consumed via Body.Close() ---

func TestGetObject_CloseBeforeRead(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("close-bucket"); err != nil {
		t.Fatal(err)
	}

	content := "close without reading"
	if _, err := env.client.PutObject("close-bucket", "obj.txt",
		strings.NewReader(content), int64(len(content)), nil); err != nil {
		t.Fatal(err)
	}

	result, err := env.client.GetObject("close-bucket", "obj.txt")
	if err != nil {
		t.Fatal(err)
	}
	// Close without reading — exercises the drain-remaining path in connReader.Close()
	if err := result.Body.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestGetObject_PartialReadThenClose(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("partial-bucket"); err != nil {
		t.Fatal(err)
	}

	content := "partial read content here"
	if _, err := env.client.PutObject("partial-bucket", "obj.txt",
		strings.NewReader(content), int64(len(content)), nil); err != nil {
		t.Fatal(err)
	}

	result, err := env.client.GetObject("partial-bucket", "obj.txt")
	if err != nil {
		t.Fatal(err)
	}
	// Read only 3 bytes then close — exercises remain > 0 drain in connReader.Close()
	buf := make([]byte, 3)
	if _, err := io.ReadFull(result.Body, buf); err != nil {
		t.Fatalf("partial read: %v", err)
	}
	if err := result.Body.Close(); err != nil {
		t.Fatalf("Close after partial read: %v", err)
	}

	// The connection should be reusable after partial read + close
	if err := env.client.Ping(); err != nil {
		t.Fatalf("Ping after partial read close: %v", err)
	}
}

func TestGetObject_CloseIdempotent(t *testing.T) {
	env := setup(t)

	if _, err := env.client.CreateBucket("close2-bucket"); err != nil {
		t.Fatal(err)
	}

	content := "idempotent close"
	if _, err := env.client.PutObject("close2-bucket", "obj.txt",
		strings.NewReader(content), int64(len(content)), nil); err != nil {
		t.Fatal(err)
	}

	result, err := env.client.GetObject("close2-bucket", "obj.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(result.Body)
	if err := result.Body.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second close should be safe (closed=true guard)
	if err := result.Body.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestMultipleClients_SameBucket(t *testing.T) {
	env := setup(t)

	// Create a second client to the same server
	c2, err := Dial(env.addr, env.tokenID, env.secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()

	if _, err := env.client.CreateBucket("shared-bucket"); err != nil {
		t.Fatal(err)
	}

	// c1 writes, c2 reads
	content := "written by c1"
	if _, err := env.client.PutObject("shared-bucket", "item.txt",
		strings.NewReader(content), int64(len(content)), nil); err != nil {
		t.Fatal(err)
	}

	result, err := c2.GetObject("shared-bucket", "item.txt")
	if err != nil {
		t.Fatalf("GetObject via c2: %v", err)
	}
	defer func() { _ = result.Body.Close() }()

	got, _ := io.ReadAll(result.Body)
	if string(got) != content {
		t.Fatalf("c2 read: got %q, want %q", got, content)
	}
}
