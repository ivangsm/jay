package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivangsm/jay/meta"
	"golang.org/x/time/rate"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// --- ObjectPath ---

func TestObjectPath(t *testing.T) {
	bucketID := "bucket1"
	objectID := "abcdef1234567890"
	got := ObjectPath(bucketID, objectID)
	want := filepath.Join("buckets", bucketID, "objects", "ab", "cd", objectID)
	if got != want {
		t.Errorf("ObjectPath = %q, want %q", got, want)
	}
}

// --- WriteObject ---

func TestWriteObject_HappyPath(t *testing.T) {
	s := newTestStore(t)
	data := []byte("hello jay store")
	bucketID := "bkt-a"
	objectID := "aabbccddeeff0011"

	checksum, size, locationRef, err := s.WriteObject(bucketID, objectID, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	if size != int64(len(data)) {
		t.Errorf("size = %d, want %d", size, len(data))
	}

	wantChecksum := sha256Hex(data)
	if checksum != wantChecksum {
		t.Errorf("checksum = %q, want %q", checksum, wantChecksum)
	}

	wantRef := ObjectPath(bucketID, objectID)
	if locationRef != wantRef {
		t.Errorf("locationRef = %q, want %q", locationRef, wantRef)
	}

	// Verify file actually exists on disk
	abs := filepath.Join(s.dataDir, locationRef)
	if _, err := os.Stat(abs); err != nil {
		t.Errorf("expected file at %s: %v", abs, err)
	}
}

func TestWriteObject_LocationRefPattern(t *testing.T) {
	s := newTestStore(t)
	bucketID := "bkt-pattern"
	objectID := "ffee99887766554433221100"

	_, _, locationRef, err := s.WriteObject(bucketID, objectID, strings.NewReader("data"))
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	expected := ObjectPath(bucketID, objectID)
	if locationRef != expected {
		t.Errorf("locationRef = %q, want %q", locationRef, expected)
	}

	parts := strings.Split(filepath.ToSlash(locationRef), "/")
	// buckets/<bucketID>/objects/<id[0:2]>/<id[2:4]>/<objectID>
	if len(parts) != 6 {
		t.Fatalf("locationRef has %d parts, want 6: %q", len(parts), locationRef)
	}
	if parts[0] != "buckets" {
		t.Errorf("parts[0] = %q, want \"buckets\"", parts[0])
	}
	if parts[1] != bucketID {
		t.Errorf("parts[1] = %q, want %q", parts[1], bucketID)
	}
	if parts[2] != "objects" {
		t.Errorf("parts[2] = %q, want \"objects\"", parts[2])
	}
	if parts[3] != objectID[:2] {
		t.Errorf("shard1 = %q, want %q", parts[3], objectID[:2])
	}
	if parts[4] != objectID[2:4] {
		t.Errorf("shard2 = %q, want %q", parts[4], objectID[2:4])
	}
	if parts[5] != objectID {
		t.Errorf("filename = %q, want %q", parts[5], objectID)
	}
}

func TestWriteObject_ChecksumMatchesSHA256(t *testing.T) {
	s := newTestStore(t)
	data := []byte("checksum test content")

	checksum, _, _, err := s.WriteObject("bkt", "aabbccddee112233", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	want := sha256Hex(data)
	if checksum != want {
		t.Errorf("checksum mismatch: got %s want %s", checksum, want)
	}
}

func TestWriteObject_LargeObject(t *testing.T) {
	s := newTestStore(t)
	const size1MB = 1 << 20
	data := make([]byte, size1MB)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	checksum, size, _, err := s.WriteObject("bkt-large", "1122334455667788", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("WriteObject large: %v", err)
	}
	if size != int64(size1MB) {
		t.Errorf("size = %d, want %d", size, size1MB)
	}
	want := sha256Hex(data)
	if checksum != want {
		t.Errorf("checksum mismatch for large object")
	}
}

func TestWriteObject_EmptyBody(t *testing.T) {
	s := newTestStore(t)

	checksum, size, _, err := s.WriteObject("bkt-empty", "aabb001122334455", bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("WriteObject empty: %v", err)
	}
	if size != 0 {
		t.Errorf("size = %d, want 0", size)
	}
	want := sha256Hex([]byte{})
	if checksum != want {
		t.Errorf("empty body checksum = %q, want %q", checksum, want)
	}
}

// --- ReadObject ---

func TestReadObject_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	data := []byte("read-back content")
	_, _, locationRef, err := s.WriteObject("bkt-read", "aabbccddeeff1122", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	f, err := s.ReadObject(locationRef)
	if err != nil {
		t.Fatalf("ReadObject: %v", err)
	}
	defer func() { _ = f.Close() }()

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("read data = %q, want %q", got, data)
	}
}

func TestReadObject_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.ReadObject("buckets/bkt/objects/aa/bb/aabbccdd11223344")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}

func TestReadObject_InvalidRef(t *testing.T) {
	s := newTestStore(t)
	_, err := s.ReadObject("../../etc/passwd")
	if err == nil {
		t.Fatal("expected error for path traversal, got nil")
	}
}

// --- DeleteObject ---

func TestDeleteObject_Existing(t *testing.T) {
	s := newTestStore(t)
	_, _, locationRef, err := s.WriteObject("bkt-del", "aabb0011ccdd2233", bytes.NewReader([]byte("to delete")))
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	if err := s.DeleteObject(locationRef); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}

	abs := filepath.Join(s.dataDir, locationRef)
	if _, err := os.Stat(abs); !os.IsNotExist(err) {
		t.Errorf("expected file to be gone; stat err = %v", err)
	}
}

func TestDeleteObject_Idempotent(t *testing.T) {
	s := newTestStore(t)
	ref := "buckets/bkt/objects/aa/bb/aabbccdd11223344"

	// Deleting a non-existent file must not return an error
	if err := s.DeleteObject(ref); err != nil {
		t.Errorf("DeleteObject non-existent: expected nil, got %v", err)
	}
}

func TestDeleteObject_InvalidRef(t *testing.T) {
	s := newTestStore(t)
	if err := s.DeleteObject("../../../escape"); err == nil {
		t.Fatal("expected error for traversal ref, got nil")
	}
}

// --- Quarantine ---

func TestQuarantine_MovesFile(t *testing.T) {
	s := newTestStore(t)
	data := []byte("quarantine me")
	_, _, locationRef, err := s.WriteObject("bkt-q", "aabb99887766554433221100"[:16], bytes.NewReader(data))
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	if err := s.Quarantine(locationRef); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	// Original must be gone
	abs := filepath.Join(s.dataDir, locationRef)
	if _, err := os.Stat(abs); !os.IsNotExist(err) {
		t.Error("file still at original location after quarantine")
	}

	// File must be in quarantine dir
	qPath := filepath.Join(s.dataDir, "quarantine", filepath.Base(locationRef))
	if _, err := os.Stat(qPath); err != nil {
		t.Errorf("file not in quarantine dir: %v", err)
	}
}

func TestQuarantine_InvalidRef(t *testing.T) {
	s := newTestStore(t)
	if err := s.Quarantine("../../../escape"); err == nil {
		t.Fatal("expected error for traversal ref, got nil")
	}
}

// --- VerifyChecksum ---

func TestVerifyChecksum_Correct(t *testing.T) {
	s := newTestStore(t)
	data := []byte("verify me correctly")
	checksum, _, locationRef, err := s.WriteObject("bkt-vc", "aabb1100ccdd3322", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	ok, actual, err := s.VerifyChecksum(locationRef, checksum)
	if err != nil {
		t.Fatalf("VerifyChecksum: %v", err)
	}
	if !ok {
		t.Errorf("VerifyChecksum = false, want true; actual=%s expected=%s", actual, checksum)
	}
	if actual != checksum {
		t.Errorf("actual = %q, want %q", actual, checksum)
	}
}

func TestVerifyChecksum_WrongChecksum(t *testing.T) {
	s := newTestStore(t)
	data := []byte("verify me wrong")
	_, _, locationRef, err := s.WriteObject("bkt-vcw", "bbaa0011ccddeeff", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	ok, actual, err := s.VerifyChecksum(locationRef, strings.Repeat("0", 64))
	if err != nil {
		t.Fatalf("VerifyChecksum: %v", err)
	}
	if ok {
		t.Error("VerifyChecksum = true, want false for wrong checksum")
	}
	if actual == strings.Repeat("0", 64) {
		t.Error("actual checksum should differ from bogus expected")
	}
}

func TestVerifyChecksum_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, _, err := s.VerifyChecksum("buckets/bkt/objects/aa/bb/aabbccdd11223344", "anything")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}

// --- VerifyChecksumRateLimited ---

func TestVerifyChecksumRateLimited_NilLimiter(t *testing.T) {
	s := newTestStore(t)
	data := []byte("rate limit nil path")
	checksum, _, locationRef, err := s.WriteObject("bkt-rl", "aabb1122ccddeeff", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	ok, actual, err := s.VerifyChecksumRateLimited(locationRef, checksum, nil)
	if err != nil {
		t.Fatalf("VerifyChecksumRateLimited nil: %v", err)
	}
	if !ok {
		t.Errorf("expected ok=true, got false; actual=%s", actual)
	}
}

func TestVerifyChecksumRateLimited_WithLimiter(t *testing.T) {
	s := newTestStore(t)
	data := []byte("rate limit with limiter")
	checksum, _, locationRef, err := s.WriteObject("bkt-rl2", "ccdd1122aabb3344", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	// Burst must be >= 1 MiB (chunkSize), so use a very large limiter that won't block in tests
	limiter := rate.NewLimiter(rate.Inf, 1<<20)

	ok, actual, err := s.VerifyChecksumRateLimited(locationRef, checksum, limiter)
	if err != nil {
		t.Fatalf("VerifyChecksumRateLimited with limiter: %v", err)
	}
	if !ok {
		t.Errorf("expected ok=true, got false; actual=%s", actual)
	}
	if actual != checksum {
		t.Errorf("actual = %q, want %q", actual, checksum)
	}
}

// --- SafePath / validateLocationRef ---

func TestSafePath_ValidRef(t *testing.T) {
	s := newTestStore(t)
	ref := "buckets/mybucket/objects/aa/bb/aabbccddeeff1122"
	got, err := s.SafePath(ref)
	if err != nil {
		t.Fatalf("SafePath valid: %v", err)
	}
	want := filepath.Join(s.dataDir, ref)
	if got != want {
		t.Errorf("SafePath = %q, want %q", got, want)
	}
}

func TestSafePath_DotDotRejected(t *testing.T) {
	s := newTestStore(t)
	cases := []string{
		"../../etc/passwd",
		"buckets/../../../etc/shadow",
		"buckets/bkt/../../secrets",
	}
	for _, c := range cases {
		_, err := s.SafePath(c)
		if err == nil {
			t.Errorf("SafePath(%q) should error but did not", c)
		}
	}
}

func TestSafePath_NullByteRejected(t *testing.T) {
	s := newTestStore(t)
	_, err := s.SafePath("buckets/bkt\x00objects/aa/bb/id")
	if err == nil {
		t.Error("SafePath with null byte should error but did not")
	}
}

func TestSafePath_EscapeDataDir(t *testing.T) {
	s := newTestStore(t)
	// Craft a path that after cleaning would escape dataDir
	ref := "buckets/" + strings.Repeat("../", 10) + "escape"
	_, err := s.SafePath(ref)
	if err == nil {
		t.Errorf("SafePath(%q) should have been rejected", ref)
	}
}

// --- CleanTmp ---

func TestCleanTmp_EmptyDir(t *testing.T) {
	s := newTestStore(t)
	count, err := s.CleanTmp()
	if err != nil {
		t.Fatalf("CleanTmp empty: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestCleanTmp_RemovesFiles(t *testing.T) {
	s := newTestStore(t)
	tmpDir := filepath.Join(s.dataDir, "tmp")

	for i := range 3 {
		f, err := os.CreateTemp(tmpDir, "test-leftover-*.writing")
		if err != nil {
			t.Fatalf("CreateTemp %d: %v", i, err)
		}
		_ = f.Close()
	}

	count, err := s.CleanTmp()
	if err != nil {
		t.Fatalf("CleanTmp: %v", err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}

	entries, _ := os.ReadDir(tmpDir)
	if len(entries) != 0 {
		t.Errorf("tmp dir still has %d entries after CleanTmp", len(entries))
	}
}

// --- EnsureBucketDir ---

func TestEnsureBucketDir_CreatesDir(t *testing.T) {
	s := newTestStore(t)
	bucketID := "new-bucket"

	if err := s.EnsureBucketDir(bucketID); err != nil {
		t.Fatalf("EnsureBucketDir: %v", err)
	}

	dir := filepath.Join(s.dataDir, "buckets", bucketID, "objects")
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Errorf("expected directory at %s; stat err = %v", dir, err)
	}
}

func TestEnsureBucketDir_Idempotent(t *testing.T) {
	s := newTestStore(t)
	bucketID := "idempotent-bucket"

	if err := s.EnsureBucketDir(bucketID); err != nil {
		t.Fatalf("first EnsureBucketDir: %v", err)
	}
	if err := s.EnsureBucketDir(bucketID); err != nil {
		t.Fatalf("second EnsureBucketDir: %v", err)
	}
}

// --- RemoveBucketDir ---

func TestRemoveBucketDir_RemovesTree(t *testing.T) {
	s := newTestStore(t)
	bucketID := "remove-me"

	if err := s.EnsureBucketDir(bucketID); err != nil {
		t.Fatalf("EnsureBucketDir: %v", err)
	}

	if err := s.RemoveBucketDir(bucketID); err != nil {
		t.Fatalf("RemoveBucketDir: %v", err)
	}

	dir := filepath.Join(s.dataDir, "buckets", bucketID)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("expected directory to be gone; stat err = %v", err)
	}
}

func TestRemoveBucketDir_NonExistent(t *testing.T) {
	s := newTestStore(t)
	// os.RemoveAll returns nil for missing directories
	if err := s.RemoveBucketDir("does-not-exist"); err != nil {
		t.Errorf("RemoveBucketDir non-existent: expected nil, got %v", err)
	}
}

// --- ListBucketFiles ---

func TestListBucketFiles_Empty(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnsureBucketDir("empty-bkt"); err != nil {
		t.Fatalf("EnsureBucketDir: %v", err)
	}

	files, err := s.ListBucketFiles("empty-bkt")
	if err != nil {
		t.Fatalf("ListBucketFiles: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestListBucketFiles_NoBucketDir(t *testing.T) {
	s := newTestStore(t)
	files, err := s.ListBucketFiles("nonexistent-bucket")
	if err != nil {
		t.Fatalf("ListBucketFiles non-existent bucket: %v", err)
	}
	if files != nil {
		t.Errorf("expected nil slice, got %v", files)
	}
}

func TestListBucketFiles_ThreeObjects(t *testing.T) {
	s := newTestStore(t)
	bucketID := "list-bkt"
	objectIDs := []string{
		"aabb1122334455aa",
		"bbcc2233445566bb",
		"ccdd3344556677cc",
	}

	for _, oid := range objectIDs {
		if _, _, _, err := s.WriteObject(bucketID, oid, strings.NewReader("data-"+oid)); err != nil {
			t.Fatalf("WriteObject %s: %v", oid, err)
		}
	}

	files, err := s.ListBucketFiles(bucketID)
	if err != nil {
		t.Fatalf("ListBucketFiles: %v", err)
	}
	if len(files) != 3 {
		t.Errorf("expected 3 files, got %d: %v", len(files), files)
	}

	// All entries must be relative paths containing the bucketID
	for _, f := range files {
		if filepath.IsAbs(f) {
			t.Errorf("path %q should be relative", f)
		}
		if !strings.Contains(f, bucketID) {
			t.Errorf("path %q doesn't contain bucketID %q", f, bucketID)
		}
	}
}

// --- ObjectExists ---

func TestObjectExists_True(t *testing.T) {
	s := newTestStore(t)
	_, _, locationRef, err := s.WriteObject("bkt-ex", "aabb1122ccdd3344", bytes.NewReader([]byte("exists")))
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	obj := &meta.Object{LocationRef: locationRef}
	if !s.ObjectExists(obj) {
		t.Error("ObjectExists = false, want true for written object")
	}
}

func TestObjectExists_False(t *testing.T) {
	s := newTestStore(t)
	obj := &meta.Object{LocationRef: "buckets/bkt/objects/aa/bb/aabbccdd11223344"}
	if s.ObjectExists(obj) {
		t.Error("ObjectExists = true, want false for non-existent object")
	}
}
