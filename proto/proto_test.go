package proto_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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
	dir      string
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

	srv := proto.NewServer(db, st, au, log, nil, 0, 0)

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
		dir:      dir,
		addr:     addr,
		tokenID:  "test-token",
		secret:   secret,
		shutdown: shutdown,
	}
}

func dial(t *testing.T, env *testEnv) *client.Client {
	t.Helper()
	c, err := client.Dial(context.Background(), env.addr, env.tokenID, env.secret, client.WithPoolSize(2))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestPing(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestBucketLifecycle(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	// Create
	info, err := c.CreateBucket(context.Background(), "test-bucket")
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "test-bucket" {
		t.Fatalf("got name %q", info.Name)
	}

	// Head
	info, err = c.HeadBucket(context.Background(), "test-bucket")
	if err != nil {
		t.Fatal(err)
	}
	if info.Visibility != "private" {
		t.Fatalf("got visibility %q", info.Visibility)
	}

	// Duplicate
	_, err = c.CreateBucket(context.Background(), "test-bucket")
	if err == nil {
		t.Fatal("expected error for duplicate bucket")
	}

	// List
	buckets, err := c.ListBuckets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 1 || buckets[0].Name != "test-bucket" {
		t.Fatalf("list: got %v", buckets)
	}

	// Delete
	if err := c.DeleteBucket(context.Background(), "test-bucket"); err != nil {
		t.Fatal(err)
	}

	// Head after delete
	_, err = c.HeadBucket(context.Background(), "test-bucket")
	if err == nil {
		t.Fatal("expected error for deleted bucket")
	}
}

func TestObjectLifecycle(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if _, err := c.CreateBucket(context.Background(), "mybucket"); err != nil {
		t.Fatal(err)
	}

	// Put
	content := "hello native protocol!"
	result, err := c.PutObject(context.Background(), "mybucket", "greeting.txt",
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
	getResult, err := c.GetObject(context.Background(), "mybucket", "greeting.txt")
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
	info, err := c.HeadObject(context.Background(), "mybucket", "greeting.txt")
	if err != nil {
		t.Fatal(err)
	}
	if info.Size != int64(len(content)) {
		t.Fatalf("head size: got %d, want %d", info.Size, len(content))
	}

	// Delete
	if err := c.DeleteObject(context.Background(), "mybucket", "greeting.txt"); err != nil {
		t.Fatal(err)
	}

	// Get deleted
	_, err = c.GetObject(context.Background(), "mybucket", "greeting.txt")
	if err == nil {
		t.Fatal("expected error for deleted object")
	}
}

func TestObjectOverwrite(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if _, err := c.CreateBucket(context.Background(), "mybucket"); err != nil {
		t.Fatal(err)
	}

	v1 := "version1"
	if _, err := c.PutObject(context.Background(), "mybucket", "data.bin", strings.NewReader(v1), int64(len(v1)), nil); err != nil {
		t.Fatal(err)
	}

	v2 := "version2"
	if _, err := c.PutObject(context.Background(), "mybucket", "data.bin", strings.NewReader(v2), int64(len(v2)), nil); err != nil {
		t.Fatal(err)
	}

	result, err := c.GetObject(context.Background(), "mybucket", "data.bin")
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

	if _, err := c.CreateBucket(context.Background(), "bigbucket"); err != nil {
		t.Fatal(err)
	}

	// 1MB object
	size := int64(1 << 20)
	data := make([]byte, size)
	rand.Read(data)

	_, err := c.PutObject(context.Background(), "bigbucket", "large.bin", bytes.NewReader(data), size, nil)
	if err != nil {
		t.Fatal(err)
	}

	result, err := c.GetObject(context.Background(), "bigbucket", "large.bin")
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

	if _, err := c.CreateBucket(context.Background(), "listbucket"); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"photos/a.jpg", "photos/b.jpg", "docs/readme.md", "root.txt"} {
		if _, err := c.PutObject(context.Background(), "listbucket", key, strings.NewReader("data"), 4, nil); err != nil {
			t.Fatal(err)
		}
	}

	// List all
	result, err := c.ListObjects(context.Background(), "listbucket", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 4 {
		t.Fatalf("list all: got %d, want 4", len(result.Objects))
	}

	// List with prefix
	result, err = c.ListObjects(context.Background(), "listbucket", &client.ListOptions{Prefix: "photos/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 2 {
		t.Fatalf("list prefix: got %d, want 2", len(result.Objects))
	}

	// List with delimiter
	result, err = c.ListObjects(context.Background(), "listbucket", &client.ListOptions{Delimiter: "/"})
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

	if _, err := c.CreateBucket(context.Background(), "notempty"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutObject(context.Background(), "notempty", "file.txt", strings.NewReader("data"), 4, nil); err != nil {
		t.Fatal(err)
	}

	err := c.DeleteBucket(context.Background(), "notempty")
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

	_, err := client.Dial(context.Background(), env.addr, "bad-token", "bad-secret", client.WithPoolSize(1))
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

	if _, err := c.CreateBucket(context.Background(), "metabucket"); err != nil {
		t.Fatal(err)
	}

	_, err := c.PutObject(context.Background(), "metabucket", "file.txt", strings.NewReader("data"), 4,
		&client.PutOptions{
			Metadata: map[string]string{"x-custom": "value123"},
		})
	if err != nil {
		t.Fatal(err)
	}

	info, err := c.HeadObject(context.Background(), "metabucket", "file.txt")
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

	if _, err := c.CreateBucket(context.Background(), "reuse"); err != nil {
		t.Fatal(err)
	}

	// Multiple operations on the same client (reuses connections)
	for i := range 10 {
		data := "iteration"
		key := "obj-" + string(rune('0'+i))
		_, err := c.PutObject(context.Background(), "reuse", key, strings.NewReader(data), int64(len(data)), nil)
		if err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}

	result, err := c.ListObjects(context.Background(), "reuse", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 10 {
		t.Fatalf("expected 10 objects, got %d", len(result.Objects))
	}
}

func requireClientErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected client error %s", code)
	}
	jayErr, ok := err.(*client.Error)
	if !ok {
		t.Fatalf("expected *client.Error, got %T: %v", err, err)
	}
	if jayErr.Code != code {
		t.Fatalf("expected code %s, got %s", code, jayErr.Code)
	}
}

func TestMultipartRejectsWrongBucketOrKeyAndKeepsConnection(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if _, err := c.CreateBucket(context.Background(), "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateBucket(context.Background(), "other"); err != nil {
		t.Fatal(err)
	}

	uploadID, err := c.CreateMultipartUpload(context.Background(), "owner", "image.bin", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.UploadPart(context.Background(), "other", "image.bin", uploadID, 1, strings.NewReader("data"), 4)
	requireClientErrorCode(t, err, "NoSuchUpload")
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("connection should remain reusable after rejected upload part: %v", err)
	}

	_, err = c.UploadPart(context.Background(), "owner", "other.bin", uploadID, 1, strings.NewReader("data"), 4)
	requireClientErrorCode(t, err, "NoSuchUpload")
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("connection should remain reusable after rejected upload part: %v", err)
	}

	if _, err := c.ListParts(context.Background(), "other", "image.bin", uploadID); err != nil {
		requireClientErrorCode(t, err, "NoSuchUpload")
	} else {
		t.Fatal("expected wrong-bucket list parts to fail")
	}

	parts, err := c.ListParts(context.Background(), "owner", "image.bin", uploadID)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 0 {
		t.Fatalf("wrong bucket/key must not register parts, got %d", len(parts))
	}
}

func TestMultipartHonorsBucketPolicyDeny(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if _, err := c.CreateBucket(context.Background(), "owner"); err != nil {
		t.Fatal(err)
	}
	policy := auth.BucketPolicy{
		Version: "1",
		Statements: []auth.PolicyStatement{{
			Effect:   "deny",
			Actions:  []string{meta.ActionMultipartUpload},
			Prefixes: []string{"private/"},
			Subjects: []string{env.tokenID},
		}},
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.db.UpdateBucketPolicy("owner", raw); err != nil {
		t.Fatal(err)
	}

	uploadID, err := c.CreateMultipartUpload(context.Background(), "owner", "private/image.bin", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.UploadPart(context.Background(), "owner", "private/image.bin", uploadID, 1, strings.NewReader("data"), 4)
	requireClientErrorCode(t, err, "AccessDenied")
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("connection should remain reusable after policy-denied upload part: %v", err)
	}

	parts, err := c.ListParts(context.Background(), "owner", "private/image.bin", uploadID)
	requireClientErrorCode(t, err, "AccessDenied")
	if parts != nil {
		t.Fatalf("policy-denied list should not return parts: %v", parts)
	}
}

func TestMultipartCompleteFailureLeavesUploadRetryable(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if _, err := c.CreateBucket(context.Background(), "owner"); err != nil {
		t.Fatal(err)
	}
	bucket, err := env.db.GetBucket("owner")
	if err != nil {
		t.Fatal(err)
	}
	uploadID, err := c.CreateMultipartUpload(context.Background(), "owner", "image.bin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.db.AddMultipartPart(uploadID, meta.MultipartPart{
		PartNumber:     1,
		Size:           4,
		ETag:           "8d777f385d3dfec8815d20f7496026dc",
		ChecksumSHA256: "missing",
		LocationRef:    "multipart/" + uploadID + "/part-00001",
	}); err != nil {
		t.Fatal(err)
	}

	_, err = c.CompleteMultipartUpload(context.Background(), "owner", "image.bin", uploadID, []client.CompletePart{{PartNumber: 1}})
	requireClientErrorCode(t, err, "InternalError")

	upload, err := env.db.GetMultipartUpload(uploadID)
	if err != nil {
		t.Fatal(err)
	}
	if upload.State != "initiated" {
		t.Fatalf("failed complete should remain retryable, got state %s", upload.State)
	}
	if _, err := env.db.GetObjectMeta(bucket.ID, "image.bin"); !errors.Is(err, meta.ErrObjectNotFound) {
		t.Fatalf("object should not be committed, got %v", err)
	}
}

// TestUploadPartStoreFailureKeepsConnection forces store.WritePart to fail
// before it consumes any body byte (parts are staged via os.CreateTemp in
// <dataDir>/tmp, so a read-only tmp dir fails the create). The handler must
// drain the unread body before responding, otherwise the next request on the
// same connection reads body bytes as a frame header and the connection is
// poisoned.
func TestUploadPartStoreFailureKeepsConnection(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if _, err := c.CreateBucket(context.Background(), "mpbucket"); err != nil {
		t.Fatal(err)
	}
	uploadID, err := c.CreateMultipartUpload(context.Background(), "mpbucket", "image.bin", nil)
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := filepath.Join(env.dir, "tmp")
	if err := os.Chmod(tmpDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(tmpDir, 0o755) })

	body := "payload that must be drained"
	_, err = c.UploadPart(context.Background(), "mpbucket", "image.bin", uploadID, 1, strings.NewReader(body), int64(len(body)))
	requireClientErrorCode(t, err, "InternalError")

	// Same connection must still be correctly framed.
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("connection desynced after store failure: %v", err)
	}

	// And after the store recovers, the same upload is still usable.
	if err := os.Chmod(tmpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UploadPart(context.Background(), "mpbucket", "image.bin", uploadID, 1, strings.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("upload after store recovery: %v", err)
	}
}

// gatedReader yields first, then runs hook once, then yields rest. It lets a
// test mutate server state while the server is mid-body inside
// store.WritePart (blocked waiting for the remaining bytes). first must be
// larger than the client's 64KB write buffer so the frame header and the
// leading body bytes actually reach the server before hook runs.
type gatedReader struct {
	first    []byte
	rest     []byte
	hook     func()
	hookDone bool
}

func (g *gatedReader) Read(p []byte) (int, error) {
	if len(g.first) > 0 {
		n := copy(p, g.first)
		g.first = g.first[n:]
		return n, nil
	}
	if !g.hookDone {
		g.hookDone = true
		if g.hook != nil {
			g.hook()
		}
	}
	if len(g.rest) > 0 {
		n := copy(p, g.rest)
		g.rest = g.rest[n:]
		return n, nil
	}
	return 0, io.EOF
}

// TestUploadPartMetaFailureAfterBodyConsumedKeepsConnection exercises
// drainData against an already-consumed body: the upload record is deleted
// while the server is mid-way through store.WritePart, so WritePart succeeds
// (consuming the whole body) and AddMultipartPart fails afterwards. The
// error path drains a fully-exhausted LimitReader — which must be treated as
// benign (frame fully consumed), delivering the error response instead of
// killing the connection.
func TestUploadPartMetaFailureAfterBodyConsumedKeepsConnection(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if _, err := c.CreateBucket(context.Background(), "mpbucket"); err != nil {
		t.Fatal(err)
	}
	uploadID, err := c.CreateMultipartUpload(context.Background(), "mpbucket", "image.bin", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 128KB first chunk: overflows the client's 64KB write buffer so the
	// server is guaranteed to be inside WritePart by the time hook runs.
	body := &gatedReader{
		first: bytes.Repeat([]byte("a"), 128*1024),
		rest:  []byte("second-half"),
		hook: func() {
			// Wait until the server is inside WritePart (it stages the part
			// via a jay-part-*.writing temp file) — that guarantees it
			// already passed the GetMultipartUpload lookup.
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				matches, _ := filepath.Glob(filepath.Join(env.dir, "tmp", "jay-part-*.writing"))
				if len(matches) > 0 {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			if err := env.db.DeleteMultipartUpload(uploadID); err != nil {
				t.Errorf("delete upload mid-body: %v", err)
			}
		},
	}

	size := int64(len(body.first) + len(body.rest))
	_, err = c.UploadPart(context.Background(), "mpbucket", "image.bin", uploadID, 1, body, size)
	requireClientErrorCode(t, err, "InternalError")

	// The error response was delivered and the connection stays usable.
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("connection desynced after meta failure: %v", err)
	}
}

// TestShutdownWithHungConnection verifies Shutdown force-closes connections
// that don't drain on their own. The idle client connection sits blocked in
// ReadHeader under the 60s idle deadline; Shutdown must not wait for it.
func TestShutdownWithHungConnection(t *testing.T) {
	env := setup(t)
	c := dial(t, env)

	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if err := env.shutdown(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("shutdown took %v, want <10s", elapsed)
	}
}

// Ensure json package is used (for test compilation)
var _ = json.Marshal

// --- wire limits ------------------------------------------------------------

// Strings are length-prefixed with a uint16. Anything longer than 64 KiB used
// to wrap silently and corrupt the frame; it must now surface an error.
func TestEncoder_StringTooLarge(t *testing.T) {
	huge := strings.Repeat("k", math.MaxUint16+1)

	if _, err := proto.EncodeBucketKey("bucket", huge); !errors.Is(err, proto.ErrFieldTooLarge) {
		t.Errorf("proto.EncodeBucketKey with oversized key: got %v, want proto.ErrFieldTooLarge", err)
	}
	if _, err := proto.EncodePutObjectRequest("bucket", "key", "text/plain", map[string]string{"x": huge}, false); !errors.Is(err, proto.ErrFieldTooLarge) {
		t.Errorf("proto.EncodePutObjectRequest with oversized metadata value: got %v, want proto.ErrFieldTooLarge", err)
	}
	if _, err := proto.EncodeObjectInfo("text/plain", 1, "etag", "sum", "now", map[string]string{"x": huge}); !errors.Is(err, proto.ErrFieldTooLarge) {
		t.Errorf("proto.EncodeObjectInfo with oversized metadata value: got %v, want proto.ErrFieldTooLarge", err)
	}
}

// Collections are count-prefixed with a uint16.
func TestEncoder_CollectionTooLarge(t *testing.T) {
	parts := make([]int, math.MaxUint16+1)
	if _, err := proto.EncodeCompleteMultipartRequest("bucket", "key", "upload", parts); !errors.Is(err, proto.ErrFieldTooLarge) {
		t.Errorf("proto.EncodeCompleteMultipartRequest with %d parts: got %v, want proto.ErrFieldTooLarge", len(parts), err)
	}

	md := make(map[string]string, math.MaxUint16+1)
	for i := range math.MaxUint16 + 1 {
		md[strconv.Itoa(i)] = "v"
	}
	if _, err := proto.EncodePutObjectRequest("bucket", "key", "", md, false); !errors.Is(err, proto.ErrFieldTooLarge) {
		t.Errorf("proto.EncodePutObjectRequest with %d metadata entries: got %v, want proto.ErrFieldTooLarge", len(md), err)
	}
}

// DecodePutObjectRequest must accept a message encoded before skipETag
// existed on the wire — the trailing field is optional, not required, so an
// older client's request cannot start failing on a newer server.
func TestDecodePutObjectRequest_PreSkipETagWireFormat(t *testing.T) {
	// Hand-build a request the same way EncodePutObjectRequest did before the
	// skipETag field was added: bucket, key, contentType, metadata, and
	// nothing else.
	e := proto.NewEncoder(nil)
	e.String("bucket")
	e.String("key")
	e.String("text/plain")
	e.StringMap(nil)
	old := e.Bytes()
	if err := e.Err(); err != nil {
		t.Fatalf("build legacy request: %v", err)
	}

	bucket, key, contentType, _, skipETag, err := proto.DecodePutObjectRequest(old)
	if err != nil {
		t.Fatalf("DecodePutObjectRequest on pre-skipETag wire format: %v", err)
	}
	if bucket != "bucket" || key != "key" || contentType != "text/plain" {
		t.Fatalf("unexpected decode: bucket=%q key=%q contentType=%q", bucket, key, contentType)
	}
	if skipETag {
		t.Fatal("expected skipETag to default to false when absent from the wire")
	}
}

// EncodePutObjectRequest/DecodePutObjectRequest must round-trip skipETag in
// both directions.
func TestEncodeDecodePutObjectRequest_SkipETag(t *testing.T) {
	for _, want := range []bool{true, false} {
		data, err := proto.EncodePutObjectRequest("bucket", "key", "text/plain", nil, want)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		_, _, _, _, got, err := proto.DecodePutObjectRequest(data)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got != want {
			t.Fatalf("skipETag round-trip: want %v, got %v", want, got)
		}
	}
}

// A value exactly at the limit must still encode and round-trip.
func TestEncoder_StringAtLimit(t *testing.T) {
	atLimit := strings.Repeat("k", math.MaxUint16)
	buf, err := proto.EncodeBucketKey("bucket", atLimit)
	if err != nil {
		t.Fatalf("proto.EncodeBucketKey at limit: %v", err)
	}
	bucket, key, err := proto.DecodeBucketKey(buf)
	if err != nil {
		t.Fatalf("proto.DecodeBucketKey: %v", err)
	}
	if bucket != "bucket" || key != atLimit {
		t.Errorf("round-trip mismatch: bucket=%q len(key)=%d", bucket, len(key))
	}
}

// EncodeError never fails — it clamps instead, so the server can always report
// an error (including one caused by an oversized field).
func TestEncodeError_TruncatesInsteadOfCorrupting(t *testing.T) {
	huge := strings.Repeat("m", math.MaxUint16+10)
	msg, code, err := proto.DecodeError(proto.EncodeError(huge, "InternalError"))
	if err != nil {
		t.Fatalf("proto.DecodeError: %v", err)
	}
	if len(msg) != math.MaxUint16 {
		t.Errorf("message len: got %d, want %d", len(msg), math.MaxUint16)
	}
	if code != "InternalError" {
		t.Errorf("code: got %q, want InternalError", code)
	}
}
