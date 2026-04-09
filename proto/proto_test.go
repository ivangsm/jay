package proto_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/proto"
	"github.com/ivangsm/jay/proto/client"
	"github.com/ivangsm/jay/store"
)

type testEnv struct {
	db       *meta.DB
	store    *store.Store
	server   *proto.Server
	addr     string
	tokenID  string
	secret   string
	shutdown func() error
}

func setup(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetSigningSecret("test-secret")
	t.Cleanup(func() { _ = db.Close() })

	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	au := auth.New(db)

	// Create account and token
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

	srv := proto.NewServer(db, st, au, log, 0, 0)

	// Use random port
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

	return &testEnv{
		db:       db,
		store:    st,
		server:   srv,
		addr:     addr,
		tokenID:  "test-token",
		secret:   secret,
		shutdown: shutdown,
	}
}

func dial(t *testing.T, env *testEnv) *client.Client {
	t.Helper()
	c, err := client.Dial(env.addr, env.tokenID, env.secret, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestPing(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if err := c.Ping(); err != nil {
		t.Fatal(err)
	}
}

func TestBucketLifecycle(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	// Create
	info, err := c.CreateBucket("test-bucket")
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "test-bucket" {
		t.Fatalf("got name %q", info.Name)
	}

	// Head
	info, err = c.HeadBucket("test-bucket")
	if err != nil {
		t.Fatal(err)
	}
	if info.Visibility != "private" {
		t.Fatalf("got visibility %q", info.Visibility)
	}

	// Duplicate
	_, err = c.CreateBucket("test-bucket")
	if err == nil {
		t.Fatal("expected error for duplicate bucket")
	}

	// List
	buckets, err := c.ListBuckets()
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 1 || buckets[0].Name != "test-bucket" {
		t.Fatalf("list: got %v", buckets)
	}

	// Delete
	if err := c.DeleteBucket("test-bucket"); err != nil {
		t.Fatal(err)
	}

	// Head after delete
	_, err = c.HeadBucket("test-bucket")
	if err == nil {
		t.Fatal("expected error for deleted bucket")
	}
}

func TestObjectLifecycle(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if _, err := c.CreateBucket("mybucket"); err != nil {
		t.Fatal(err)
	}

	// Put
	content := "hello native protocol!"
	result, err := c.PutObject("mybucket", "greeting.txt",
		strings.NewReader(content), int64(len(content)),
		&client.PutOptions{ContentType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if result.ETag == "" {
		t.Fatal("missing etag")
	}
	if result.ChecksumSHA256 == "" {
		t.Fatal("missing checksum")
	}

	// Get
	getResult, err := c.GetObject("mybucket", "greeting.txt")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(getResult.Body)
	_ = getResult.Body.Close()
	if string(got) != content {
		t.Fatalf("get: got %q, want %q", got, content)
	}
	if getResult.ContentType != "text/plain" {
		t.Fatalf("content type: got %q", getResult.ContentType)
	}

	// Head
	info, err := c.HeadObject("mybucket", "greeting.txt")
	if err != nil {
		t.Fatal(err)
	}
	if info.Size != int64(len(content)) {
		t.Fatalf("head size: got %d, want %d", info.Size, len(content))
	}

	// Delete
	if err := c.DeleteObject("mybucket", "greeting.txt"); err != nil {
		t.Fatal(err)
	}

	// Get deleted
	_, err = c.GetObject("mybucket", "greeting.txt")
	if err == nil {
		t.Fatal("expected error for deleted object")
	}
}

func TestObjectOverwrite(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if _, err := c.CreateBucket("mybucket"); err != nil {
		t.Fatal(err)
	}

	v1 := "version1"
	if _, err := c.PutObject("mybucket", "data.bin", strings.NewReader(v1), int64(len(v1)), nil); err != nil {
		t.Fatal(err)
	}

	v2 := "version2"
	if _, err := c.PutObject("mybucket", "data.bin", strings.NewReader(v2), int64(len(v2)), nil); err != nil {
		t.Fatal(err)
	}

	result, err := c.GetObject("mybucket", "data.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(result.Body)
	_ = result.Body.Close()
	if string(got) != v2 {
		t.Fatalf("overwrite: got %q, want %q", got, v2)
	}
}

func TestLargeObject(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if _, err := c.CreateBucket("bigbucket"); err != nil {
		t.Fatal(err)
	}

	// 1MB object
	size := int64(1 << 20)
	data := make([]byte, size)
	rand.Read(data)

	_, err := c.PutObject("bigbucket", "large.bin", bytes.NewReader(data), size, nil)
	if err != nil {
		t.Fatal(err)
	}

	result, err := c.GetObject("bigbucket", "large.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(result.Body)
	_ = result.Body.Close()

	if !bytes.Equal(got, data) {
		t.Fatal("large object data mismatch")
	}
}

func TestListObjects(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if _, err := c.CreateBucket("listbucket"); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"photos/a.jpg", "photos/b.jpg", "docs/readme.md", "root.txt"} {
		if _, err := c.PutObject("listbucket", key, strings.NewReader("data"), 4, nil); err != nil {
			t.Fatal(err)
		}
	}

	// List all
	result, err := c.ListObjects("listbucket", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 4 {
		t.Fatalf("list all: got %d, want 4", len(result.Objects))
	}

	// List with prefix
	result, err = c.ListObjects("listbucket", &client.ListOptions{Prefix: "photos/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 2 {
		t.Fatalf("list prefix: got %d, want 2", len(result.Objects))
	}

	// List with delimiter
	result, err = c.ListObjects("listbucket", &client.ListOptions{Delimiter: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 1 {
		t.Fatalf("list delimiter objects: got %d, want 1", len(result.Objects))
	}
	if len(result.CommonPrefixes) != 2 {
		t.Fatalf("list delimiter prefixes: got %d, want 2", len(result.CommonPrefixes))
	}
}

func TestDeleteBucketNotEmpty(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if _, err := c.CreateBucket("notempty"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutObject("notempty", "file.txt", strings.NewReader("data"), 4, nil); err != nil {
		t.Fatal(err)
	}

	err := c.DeleteBucket("notempty")
	if err == nil {
		t.Fatal("expected error deleting non-empty bucket")
	}
	jayErr, ok := err.(*client.Error)
	if !ok {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if jayErr.Code != "BucketNotEmpty" {
		t.Fatalf("expected BucketNotEmpty, got %s", jayErr.Code)
	}
}

func TestAuthFailure(t *testing.T) {
	env := setup(t)

	_, err := client.Dial(env.addr, "bad-token", "bad-secret", 1)
	if err == nil {
		t.Fatal("expected auth failure")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUserMetadata(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if _, err := c.CreateBucket("metabucket"); err != nil {
		t.Fatal(err)
	}

	_, err := c.PutObject("metabucket", "file.txt", strings.NewReader("data"), 4,
		&client.PutOptions{
			Metadata: map[string]string{"x-custom": "value123"},
		})
	if err != nil {
		t.Fatal(err)
	}

	info, err := c.HeadObject("metabucket", "file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if info.Metadata["x-custom"] != "value123" {
		t.Fatalf("metadata: got %v", info.Metadata)
	}
}

func TestConnectionReuse(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if _, err := c.CreateBucket("reuse"); err != nil {
		t.Fatal(err)
	}

	// Multiple operations on the same client (reuses connections)
	for i := range 10 {
		data := "iteration"
		key := "obj-" + string(rune('0'+i))
		_, err := c.PutObject("reuse", key, strings.NewReader(data), int64(len(data)), nil)
		if err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}

	result, err := c.ListObjects("reuse", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 10 {
		t.Fatalf("expected 10 objects, got %d", len(result.Objects))
	}
}

// Ensure json package is used (for test compilation)
var _ = json.Marshal
