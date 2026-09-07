package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

	// File must be in quarantine dir. The destination name flattens the full
	// locationRef and appends a uniquifying suffix, so match on the prefix.
	flat := strings.ReplaceAll(filepath.Clean(locationRef), string(filepath.Separator), "_")
	matches, err := filepath.Glob(filepath.Join(s.dataDir, "quarantine", flat+".*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) != 1 {
		t.Errorf("expected 1 quarantined file for %q, got %v", flat, matches)
	}
}

// Multipart parts are named "part-00001" under every upload, so a
// basename-keyed quarantine destination would clobber the previous upload's
// evidence. Both files must survive.
func TestQuarantine_MultipartPartsDoNotCollide(t *testing.T) {
	s := newTestStore(t)

	refs := make([]string, 0, 2)
	for _, uploadID := range []string{"upload-aaa", "upload-bbb"} {
		dir := filepath.Join(s.dataDir, "buckets", "bkt-mp", "multipart", uploadID)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		ref := filepath.Join("buckets", "bkt-mp", "multipart", uploadID, "part-00001")
		if err := os.WriteFile(filepath.Join(s.dataDir, ref), []byte(uploadID), 0o644); err != nil {
			t.Fatalf("write part: %v", err)
		}
		refs = append(refs, ref)
	}

	for _, ref := range refs {
		if err := s.Quarantine(ref); err != nil {
			t.Fatalf("Quarantine(%s): %v", ref, err)
		}
	}

	entries, err := os.ReadDir(filepath.Join(s.dataDir, "quarantine"))
	if err != nil {
		t.Fatalf("read quarantine dir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 quarantined parts, got %d: %v", len(entries), entries)
	}

	// Contents must be distinct — neither part overwrote the other.
	seen := map[string]bool{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(s.dataDir, "quarantine", e.Name()))
		if err != nil {
			t.Fatalf("read quarantined file: %v", err)
		}
		seen[string(b)] = true
	}
	if !seen["upload-aaa"] || !seen["upload-bbb"] {
		t.Errorf("quarantined contents collided: %v", seen)
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

// --- WriteObjectVerified / WritePartVerified ---

// countFiles counts every regular file under the store's data dir.
func countFiles(t *testing.T, s *Store) int {
	t.Helper()
	n := 0
	err := filepath.Walk(s.DataDir(), func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return n
}

// A refused write must leave the store exactly as it found it — no object under
// buckets/, and no temp file either. The temp file matters: it is what a
// verifier running AFTER the rename would have turned into a real object for
// the duration, and what a crash in that window hands recovery/ to quarantine.
func TestWriteObjectVerified_AbortsBeforeRename(t *testing.T) {
	s := newTestStore(t)
	before := countFiles(t, s)

	sentinel := errors.New("refused")
	_, _, _, err := s.WriteObjectVerified("bucket1", "abcdef1234567890", strings.NewReader("payload"),
		func(string, int64) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("want the verifier's error back, got %v", err)
	}
	if got := countFiles(t, s); got != before {
		t.Fatalf("a refused write left %d file(s) behind", got-before)
	}
}

// The verifier sees what actually arrived, not what the caller hoped for.
func TestWriteObjectVerified_ReceivesTheRealDigestAndSize(t *testing.T) {
	s := newTestStore(t)
	data := []byte("verify me")

	var gotSum string
	var gotSize int64
	checksum, size, _, err := s.WriteObjectVerified("bucket1", "abcdef1234567890", bytes.NewReader(data),
		func(sha256Hex string, n int64) error {
			gotSum, gotSize = sha256Hex, n
			return nil
		})
	if err != nil {
		t.Fatalf("WriteObjectVerified: %v", err)
	}
	if gotSum != sha256Hex(data) || gotSum != checksum {
		t.Fatalf("verifier saw %q, want %q", gotSum, sha256Hex(data))
	}
	if gotSize != int64(len(data)) || gotSize != size {
		t.Fatalf("verifier saw size %d, want %d", gotSize, len(data))
	}
}

// A refused part must not replace the part already sitting at its path: the
// path is derived from the part number, so a retry aims at an existing file.
func TestWritePartVerified_RefusedRetryKeepsTheAcceptedPart(t *testing.T) {
	s := newTestStore(t)

	_, _, loc, err := s.WritePart("upload-1", 1, strings.NewReader("good part"))
	if err != nil {
		t.Fatalf("WritePart: %v", err)
	}
	path := filepath.Join(s.DataDir(), loc)

	sentinel := errors.New("refused")
	if _, _, _, err := s.WritePartVerified("upload-1", 1, strings.NewReader("bad part"),
		func(string, int64) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("want the verifier's error back, got %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the accepted part is gone: %v", err)
	}
	if string(got) != "good part" {
		t.Fatalf("the accepted part was overwritten: %q", got)
	}
}

// --- path validation on ID-derived paths ---

// CleanupUploadParts is an os.RemoveAll: a traversing upload ID must be
// refused, and the test asserts the directory it aimed at is still on disk
// rather than trusting the returned error.
func TestCleanupUploadParts_TraversalRefused(t *testing.T) {
	s := newTestStore(t)
	victim := filepath.Join(s.dataDir, "buckets", "important")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatalf("mkdir victim: %v", err)
	}

	err := s.CleanupUploadParts("../buckets/important")
	if _, statErr := os.Stat(victim); statErr != nil {
		t.Fatalf("traversing upload ID deleted %s: %v", victim, statErr)
	}
	if !errors.Is(err, errInvalidLocationRef) {
		t.Fatalf("CleanupUploadParts traversal: want errInvalidLocationRef, got %v", err)
	}
}

func TestRemoveBucketDir_TraversalRefused(t *testing.T) {
	s := newTestStore(t)
	victim := filepath.Join(s.dataDir, "quarantine")

	err := s.RemoveBucketDir("../quarantine")
	if _, statErr := os.Stat(victim); statErr != nil {
		t.Fatalf("traversing bucket ID deleted %s: %v", victim, statErr)
	}
	if !errors.Is(err, errInvalidLocationRef) {
		t.Fatalf("RemoveBucketDir traversal: want errInvalidLocationRef, got %v", err)
	}
}

func TestEnsureBucketDir_TraversalRefused(t *testing.T) {
	s := newTestStore(t)
	outside := filepath.Join(filepath.Dir(s.dataDir), "escaped")

	err := s.EnsureBucketDir("../../escaped")
	if _, statErr := os.Stat(outside); statErr == nil {
		t.Fatalf("traversing bucket ID created %s outside the data dir", outside)
	}
	if !errors.Is(err, errInvalidLocationRef) {
		t.Fatalf("EnsureBucketDir traversal: want errInvalidLocationRef, got %v", err)
	}
}

func TestListBucketFiles_TraversalRefused(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.ListBucketFiles("../.."); !errors.Is(err, errInvalidLocationRef) {
		t.Fatalf("ListBucketFiles traversal: want errInvalidLocationRef, got %v", err)
	}
}

// A location ref read back from metadata is externally-stored input, so a
// corrupted one must answer "missing" instead of reaching outside the store.
func TestObjectExists_InvalidRefIsMissing(t *testing.T) {
	s := newTestStore(t)
	outside := filepath.Join(filepath.Dir(s.dataDir), "outside.bin")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	if s.ObjectExists(&meta.Object{LocationRef: "../outside.bin"}) {
		t.Error("ObjectExists reported a file outside the data dir as present")
	}
}
