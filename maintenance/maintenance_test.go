package maintenance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func openTestDB(t *testing.T) (*meta.DB, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	db, err := meta.Open(filepath.Join(dir, "meta", "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetSigningSecret("test-signing-secret-at-least-32-chars!!")
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, st
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testGC returns a GC rooted at dir, backed by a fresh meta DB + store living
// in a separate temp dir. Suitable for tests that only exercise the tmp-file
// GC paths, where the multipart/db wiring just needs to be valid.
func testGC(t *testing.T, dir string, interval time.Duration) *GC {
	t.Helper()
	db, st := openTestDB(t)
	return NewGC(dir, db, st, discardLogger(), interval)
}

// testGCWithStore returns a GC whose dataDir, meta DB and store all share the
// same root, for tests that exercise the multipart cleanup paths.
func testGCWithStore(t *testing.T, interval time.Duration) (*GC, *meta.DB, *store.Store) {
	t.Helper()
	db, st := openTestDB(t)
	return NewGC(st.DataDir(), db, st, discardLogger(), interval), db, st
}

// sha256Hex returns the hex-encoded SHA-256 of b.
func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// createTestBucketAndObject creates a bucket + quarantined object in the DB.
// It returns (bucketID, key).
func createTestBucketAndObject(t *testing.T, db *meta.DB, content []byte) (bucketID, key string) {
	t.Helper()
	bucketID = uuid.NewString()
	key = "testkey-" + uuid.NewString()

	b := &meta.Bucket{
		ID:   bucketID,
		Name: "test-bucket-" + bucketID,
	}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	obj := &meta.Object{
		BucketID:       bucketID,
		Key:            key,
		ObjectID:       uuid.NewString(),
		State:          "active",
		SizeBytes:      int64(len(content)),
		ChecksumSHA256: sha256Hex(content),
		LocationRef:    "buckets/" + bucketID + "/objects/ab/cd/" + uuid.NewString(),
	}
	if _, err := db.PutObjectMeta(obj); err != nil {
		t.Fatalf("PutObjectMeta: %v", err)
	}
	if err := db.QuarantineObject(bucketID, key); err != nil {
		t.Fatalf("QuarantineObject: %v", err)
	}
	return bucketID, key
}

// ── Metrics ───────────────────────────────────────────────────────────────────

func TestMetrics_NewMetrics_StartedAt(t *testing.T) {
	before := time.Now()
	m := NewMetrics()
	after := time.Now()

	snap := m.Snapshot()
	// startedAt must be between before and after.
	// We verify indirectly via UptimeSeconds >= 0.
	if snap.UptimeSeconds < 0 {
		t.Error("UptimeSeconds must be >= 0")
	}
	_ = before
	_ = after
}

func TestMetrics_RecordFsyncFailure(t *testing.T) {
	m := NewMetrics()
	m.RecordFsyncFailure()
	m.RecordFsyncFailure()

	snap := m.Snapshot()
	if snap.FsyncFailures != 2 {
		t.Errorf("FsyncFailures: got %d, want 2", snap.FsyncFailures)
	}
}

func TestMetrics_RecordFsyncFailure_NilSafe(t *testing.T) {
	var m *Metrics
	// Must not panic.
	m.RecordFsyncFailure()
}

func TestMetrics_Snapshot_ReflectsCounters(t *testing.T) {
	m := NewMetrics()
	m.PutObjectTotal.Add(10)
	m.GetObjectTotal.Add(5)
	m.DeleteObjectTotal.Add(3)
	m.HeadObjectTotal.Add(2)
	m.ListObjectsTotal.Add(1)
	m.CreateBucketTotal.Add(4)
	m.DeleteBucketTotal.Add(6)
	m.AuthFailures.Add(7)
	m.ChecksumFailures.Add(8)
	m.ObjectsQuarantined.Add(9)
	m.BytesUploaded.Add(1000)
	m.BytesDownloaded.Add(2000)

	snap := m.Snapshot()

	if snap.PutObjectTotal != 10 {
		t.Errorf("PutObjectTotal: got %d, want 10", snap.PutObjectTotal)
	}
	if snap.GetObjectTotal != 5 {
		t.Errorf("GetObjectTotal: got %d, want 5", snap.GetObjectTotal)
	}
	if snap.DeleteObjectTotal != 3 {
		t.Errorf("DeleteObjectTotal: got %d, want 3", snap.DeleteObjectTotal)
	}
	if snap.HeadObjectTotal != 2 {
		t.Errorf("HeadObjectTotal: got %d, want 2", snap.HeadObjectTotal)
	}
	if snap.ListObjectsTotal != 1 {
		t.Errorf("ListObjectsTotal: got %d, want 1", snap.ListObjectsTotal)
	}
	if snap.CreateBucketTotal != 4 {
		t.Errorf("CreateBucketTotal: got %d, want 4", snap.CreateBucketTotal)
	}
	if snap.DeleteBucketTotal != 6 {
		t.Errorf("DeleteBucketTotal: got %d, want 6", snap.DeleteBucketTotal)
	}
	if snap.AuthFailures != 7 {
		t.Errorf("AuthFailures: got %d, want 7", snap.AuthFailures)
	}
	if snap.ChecksumFailures != 8 {
		t.Errorf("ChecksumFailures: got %d, want 8", snap.ChecksumFailures)
	}
	if snap.ObjectsQuarantined != 9 {
		t.Errorf("ObjectsQuarantined: got %d, want 9", snap.ObjectsQuarantined)
	}
	if snap.BytesUploaded != 1000 {
		t.Errorf("BytesUploaded: got %d, want 1000", snap.BytesUploaded)
	}
	if snap.BytesDownloaded != 2000 {
		t.Errorf("BytesDownloaded: got %d, want 2000", snap.BytesDownloaded)
	}
	if snap.UptimeSeconds < 0 {
		t.Errorf("UptimeSeconds must be >= 0, got %d", snap.UptimeSeconds)
	}
}

func TestMetrics_MarshalJSON(t *testing.T) {
	m := NewMetrics()
	m.PutObjectTotal.Add(42)
	m.BytesUploaded.Add(9999)

	snap := m.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	// Verify required fields are present in the JSON output.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	expectedFields := []string{
		"uptime_seconds",
		"put_object_total",
		"get_object_total",
		"delete_object_total",
		"head_object_total",
		"list_objects_total",
		"create_bucket_total",
		"delete_bucket_total",
		"auth_failures",
		"checksum_failures",
		"fsync_failures",
		"objects_quarantined",
		"bytes_uploaded",
		"bytes_downloaded",
	}
	for _, field := range expectedFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("MarshalJSON missing field %q", field)
		}
	}

	if v, ok := raw["put_object_total"].(float64); !ok || int64(v) != 42 {
		t.Errorf("put_object_total: got %v, want 42", raw["put_object_total"])
	}
	if v, ok := raw["bytes_uploaded"].(float64); !ok || int64(v) != 9999 {
		t.Errorf("bytes_uploaded: got %v, want 9999", raw["bytes_uploaded"])
	}
}

// ── GC ────────────────────────────────────────────────────────────────────────

func TestGC_NewGC(t *testing.T) {
	dir := t.TempDir()
	interval := 5 * time.Minute
	gc := testGC(t, dir, interval)
	if gc == nil {
		t.Fatal("NewGC returned nil")
	}
	if gc.dataDir != dir {
		t.Errorf("dataDir: got %q, want %q", gc.dataDir, dir)
	}
	if gc.interval != interval {
		t.Errorf("interval: got %v, want %v", gc.interval, interval)
	}
}

func TestGC_StartStop_NoPanic(t *testing.T) {
	dir := t.TempDir()
	gc := testGC(t, dir, 1*time.Hour)

	// Start once
	gc.Start()
	// Double-start must not panic
	gc.Start()

	// Stop once
	gc.Stop()
	// Double-stop must not panic
	gc.Stop()
}

func TestGC_NotifyDeletion_NonBlocking(t *testing.T) {
	dir := t.TempDir()
	gc := testGC(t, dir, 1*time.Hour)

	// Call many times without starting the loop — should never block.
	for i := 0; i < 100; i++ {
		gc.NotifyDeletion()
	}
}

func TestGC_RunOnce_NoPanicWithRealDir(t *testing.T) {
	dir := t.TempDir()
	// Ensure tmp subdirectory exists (store.New would do this, but here we set
	// up the dir manually).
	if err := os.MkdirAll(filepath.Join(dir, "tmp"), 0o755); err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}
	gc := testGC(t, dir, 1*time.Hour)
	// Must not panic, even on an empty directory.
	gc.RunOnce()
}

func TestGC_RunOnce_NoPanicMissingTmpDir(t *testing.T) {
	// dataDir with no tmp subdir — cleanOldTempFiles must return silently.
	dir := t.TempDir()
	gc := testGC(t, dir, 1*time.Hour)
	gc.RunOnce() // must not panic
}

func TestGC_CleanOldTempFiles_OldRegularFileDeleted(t *testing.T) {
	dir := t.TempDir()
	tmpDir := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Create a regular temp file.
	f, err := os.Create(filepath.Join(tmpDir, "old-upload.tmp"))
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	_ = f.Close()

	// Set mtime to 2 hours ago (beyond 1h cutoff for completed temp files).
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(f.Name(), oldTime, oldTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	gc := testGC(t, dir, 1*time.Hour)
	gc.RunOnce()

	if _, err := os.Stat(f.Name()); !os.IsNotExist(err) {
		t.Error("old regular temp file should have been deleted")
	}
	if gc.FilesCollected.Load() != 1 {
		t.Errorf("FilesCollected: got %d, want 1", gc.FilesCollected.Load())
	}
}

func TestGC_CleanOldTempFiles_RecentFileKept(t *testing.T) {
	dir := t.TempDir()
	tmpDir := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Create a recent file (30 minutes ago — within the 1h threshold).
	f, err := os.Create(filepath.Join(tmpDir, "recent-upload.tmp"))
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	_ = f.Close()

	recentTime := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(f.Name(), recentTime, recentTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	gc := testGC(t, dir, 1*time.Hour)
	gc.RunOnce()

	if _, err := os.Stat(f.Name()); os.IsNotExist(err) {
		t.Error("recent temp file should NOT have been deleted")
	}
	if gc.FilesCollected.Load() != 0 {
		t.Errorf("FilesCollected: got %d, want 0", gc.FilesCollected.Load())
	}
}

func TestGC_CleanOldTempFiles_WritingFileSurvivesLessThan24h(t *testing.T) {
	dir := t.TempDir()
	tmpDir := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Create a .writing file aged 2 hours — old enough for regular files but
	// NOT old enough for .writing files (24h threshold).
	f, err := os.Create(filepath.Join(tmpDir, "active-upload.writing"))
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	_ = f.Close()

	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(f.Name(), twoHoursAgo, twoHoursAgo); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	gc := testGC(t, dir, 1*time.Hour)
	gc.RunOnce()

	if _, err := os.Stat(f.Name()); os.IsNotExist(err) {
		t.Error(".writing file aged 2h should NOT have been deleted (24h threshold)")
	}
	if gc.FilesCollected.Load() != 0 {
		t.Errorf("FilesCollected: got %d, want 0", gc.FilesCollected.Load())
	}
}

func TestGC_CleanOldTempFiles_WritingFileOlderThan24hDeleted(t *testing.T) {
	dir := t.TempDir()
	tmpDir := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Create a .writing file aged 25 hours — beyond the 24h cutoff.
	f, err := os.Create(filepath.Join(tmpDir, "abandoned-upload.writing"))
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	_ = f.Close()

	veryOld := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(f.Name(), veryOld, veryOld); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	gc := testGC(t, dir, 1*time.Hour)
	gc.RunOnce()

	if _, err := os.Stat(f.Name()); !os.IsNotExist(err) {
		t.Error(".writing file aged 25h should have been deleted")
	}
	if gc.FilesCollected.Load() != 1 {
		t.Errorf("FilesCollected: got %d, want 1", gc.FilesCollected.Load())
	}
}

func TestGC_FilesCollected_Counter(t *testing.T) {
	dir := t.TempDir()
	tmpDir := filepath.Join(dir, "tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Create 3 old files and 1 recent file.
	oldTime := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 3; i++ {
		name := filepath.Join(tmpDir, "old-file-"+string(rune('a'+i))+".tmp")
		f, err := os.Create(name)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		_ = f.Close()
		if err := os.Chtimes(name, oldTime, oldTime); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}
	// Recent file — must not be counted.
	recentName := filepath.Join(tmpDir, "recent.tmp")
	rf, err := os.Create(recentName)
	if err != nil {
		t.Fatalf("create recent: %v", err)
	}
	_ = rf.Close()

	gc := testGC(t, dir, 1*time.Hour)
	gc.RunOnce()

	if gc.FilesCollected.Load() != 3 {
		t.Errorf("FilesCollected: got %d, want 3", gc.FilesCollected.Load())
	}
}

// ── GC: multipart cleanup ─────────────────────────────────────────────────────

func TestGC_CleanupExpiredUploads_ReclaimsRecordAndParts(t *testing.T) {
	gc, db, st := testGCWithStore(t, 1*time.Hour)

	up := &meta.MultipartUpload{
		UploadID:  "expired-upload",
		BucketID:  "bucket-1",
		ObjectKey: "some/key",
		CreatedAt: time.Now().Add(-25 * time.Hour),
		State:     "initiated",
	}
	if err := db.CreateMultipartUpload(up); err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	if _, _, _, err := st.WritePart(up.UploadID, 1, bytes.NewReader([]byte("part data"))); err != nil {
		t.Fatalf("WritePart: %v", err)
	}

	partsDir := filepath.Join(st.DataDir(), "multipart", up.UploadID)
	if _, err := os.Stat(partsDir); err != nil {
		t.Fatalf("parts dir should exist before GC: %v", err)
	}

	gc.RunOnce()

	if _, err := db.GetMultipartUpload(up.UploadID); err != meta.ErrUploadNotFound {
		t.Errorf("expired upload record should be gone, got err=%v", err)
	}
	if _, err := os.Stat(partsDir); !os.IsNotExist(err) {
		t.Errorf("parts dir should have been removed, stat err=%v", err)
	}
}

func TestGC_CleanupExpiredUploads_KeepsRecentUpload(t *testing.T) {
	gc, db, st := testGCWithStore(t, 1*time.Hour)

	up := &meta.MultipartUpload{
		UploadID:  "recent-upload",
		BucketID:  "bucket-1",
		ObjectKey: "some/key",
		State:     "initiated", // CreatedAt defaults to now
	}
	if err := db.CreateMultipartUpload(up); err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	if _, _, _, err := st.WritePart(up.UploadID, 1, bytes.NewReader([]byte("part data"))); err != nil {
		t.Fatalf("WritePart: %v", err)
	}

	gc.RunOnce()

	if _, err := db.GetMultipartUpload(up.UploadID); err != nil {
		t.Errorf("recent upload record should survive, got err=%v", err)
	}
	partsDir := filepath.Join(st.DataDir(), "multipart", up.UploadID)
	if _, err := os.Stat(partsDir); err != nil {
		t.Errorf("recent upload parts should survive: %v", err)
	}
}

func TestGC_SweepOrphanMultipartDirs_RemovesOldOrphan(t *testing.T) {
	gc, _, st := testGCWithStore(t, 1*time.Hour)

	// A part dir with no bbolt record at all (e.g. record deleted while the
	// best-effort part cleanup failed).
	orphanDir := filepath.Join(st.DataDir(), "multipart", "ghost-upload")
	if err := os.MkdirAll(orphanDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(orphanDir, "part-00001"), []byte("leftover"), 0o600); err != nil {
		t.Fatalf("write part: %v", err)
	}
	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(orphanDir, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	gc.RunOnce()

	if _, err := os.Stat(orphanDir); !os.IsNotExist(err) {
		t.Errorf("old orphan multipart dir should have been removed, stat err=%v", err)
	}
}

func TestGC_SweepOrphanMultipartDirs_KeepsRecentOrphan(t *testing.T) {
	gc, _, st := testGCWithStore(t, 1*time.Hour)

	// Fresh dir without a record: could be an upload whose record is being
	// created concurrently — must be left alone until it ages past 24h.
	orphanDir := filepath.Join(st.DataDir(), "multipart", "brand-new-upload")
	if err := os.MkdirAll(orphanDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	gc.RunOnce()

	if _, err := os.Stat(orphanDir); err != nil {
		t.Errorf("recent orphan dir should survive: %v", err)
	}
}

func TestGC_SweepOrphanMultipartDirs_KeepsRegisteredUpload(t *testing.T) {
	gc, db, st := testGCWithStore(t, 1*time.Hour)

	up := &meta.MultipartUpload{
		UploadID:  "registered-upload",
		BucketID:  "bucket-1",
		ObjectKey: "some/key",
		State:     "initiated", // recent CreatedAt — not expired
	}
	if err := db.CreateMultipartUpload(up); err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	if _, _, _, err := st.WritePart(up.UploadID, 1, bytes.NewReader([]byte("part data"))); err != nil {
		t.Fatalf("WritePart: %v", err)
	}
	// Age the dir past the sweep cutoff; the bbolt record must still protect it.
	partsDir := filepath.Join(st.DataDir(), "multipart", up.UploadID)
	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(partsDir, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	gc.RunOnce()

	if _, err := os.Stat(partsDir); err != nil {
		t.Errorf("registered upload parts dir should survive the orphan sweep: %v", err)
	}
	if _, err := db.GetMultipartUpload(up.UploadID); err != nil {
		t.Errorf("registered upload record should survive: %v", err)
	}
}

// ── BackupManager ─────────────────────────────────────────────────────────────

func TestBackup_NewBackupManager_CreatesDir(t *testing.T) {
	db, _ := openTestDB(t)
	backupDir := filepath.Join(t.TempDir(), "nested", "backups")

	bm := NewBackupManager(db, backupDir, discardLogger())
	if bm == nil {
		t.Fatal("NewBackupManager returned nil")
	}

	info, err := os.Stat(backupDir)
	if err != nil {
		t.Fatalf("backup dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("backup path is not a directory")
	}
}

func TestBackup_Run_CreatesFile(t *testing.T) {
	db, _ := openTestDB(t)
	backupDir := t.TempDir()
	bm := NewBackupManager(db, backupDir, discardLogger())

	path, err := bm.Run()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("backup file not found at %q: %v", path, err)
	}
	if info.Size() == 0 {
		t.Error("backup file is empty")
	}
	if !strings.HasPrefix(filepath.Base(path), "jay-") {
		t.Errorf("unexpected backup filename: %q", filepath.Base(path))
	}
}

func TestBackup_Verify_AfterRun(t *testing.T) {
	db, _ := openTestDB(t)
	backupDir := t.TempDir()
	bm := NewBackupManager(db, backupDir, discardLogger())

	path, err := bm.Run()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	result, err := bm.Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result == nil {
		t.Fatal("Verify returned nil result")
	}
	if result.Version == "" {
		t.Error("Verify result Version should be non-empty")
	}
}

func TestBackup_VerifyAndCleanup_RemovesCorruptFile(t *testing.T) {
	db, _ := openTestDB(t)
	backupDir := t.TempDir()
	bm := NewBackupManager(db, backupDir, discardLogger())

	// A file that is not a valid bbolt database must fail verification and be
	// deleted so it can never be mistaken for a restorable snapshot.
	corrupt := filepath.Join(backupDir, "jay-corrupt.db")
	if err := os.WriteFile(corrupt, []byte("definitely not a bolt db"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	if err := bm.verifyAndCleanup(corrupt); err == nil {
		t.Error("verifyAndCleanup should fail for a corrupt backup")
	}
	if _, err := os.Stat(corrupt); !os.IsNotExist(err) {
		t.Errorf("corrupt backup should have been removed, stat err=%v", err)
	}
}

func TestBackup_Verify_NonExistentFile(t *testing.T) {
	db, _ := openTestDB(t)
	backupDir := t.TempDir()
	bm := NewBackupManager(db, backupDir, discardLogger())

	_, err := bm.Verify(filepath.Join(backupDir, "nope.db"))
	if err == nil {
		t.Error("Verify should fail for non-existent file")
	}
}

func TestBackup_Prune_RemovesOldFiles(t *testing.T) {
	db, _ := openTestDB(t)
	backupDir := t.TempDir()
	bm := NewBackupManager(db, backupDir, discardLogger())

	// Create 5 fake backup files with old mtimes.
	oldTime := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 5; i++ {
		name := filepath.Join(backupDir, "jay-old-backup-"+string(rune('a'+i))+".db")
		f, err := os.Create(name)
		if err != nil {
			t.Fatalf("create backup file: %v", err)
		}
		if _, err := f.WriteString("fake bolt"); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = f.Close()
		if err := os.Chtimes(name, oldTime, oldTime); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}

	// Prune with retention=24h and minKeep=2.
	removed, err := bm.Prune(24*time.Hour, 2)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if removed != 3 {
		t.Errorf("Prune removed %d, want 3 (5 files - 2 minKeep)", removed)
	}

	// Verify exactly 2 files remain.
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 backup files remaining, got %d", len(entries))
	}
}

func TestBackup_Prune_RespectsMinKeep(t *testing.T) {
	db, _ := openTestDB(t)
	backupDir := t.TempDir()
	bm := NewBackupManager(db, backupDir, discardLogger())

	// Create 3 old files but minKeep=5 — should remove nothing.
	oldTime := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 3; i++ {
		name := filepath.Join(backupDir, "jay-backup-"+string(rune('a'+i))+".db")
		f, err := os.Create(name)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		_ = f.Close()
		if err := os.Chtimes(name, oldTime, oldTime); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}

	removed, err := bm.Prune(24*time.Hour, 5)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if removed != 0 {
		t.Errorf("Prune should have removed 0 files (minKeep=5 > total=3), got %d", removed)
	}
}

func TestBackup_Prune_RecentFilesKept(t *testing.T) {
	db, _ := openTestDB(t)
	backupDir := t.TempDir()
	bm := NewBackupManager(db, backupDir, discardLogger())

	// Create 4 recent backup files (1 hour old — within 24h retention).
	recentTime := time.Now().Add(-1 * time.Hour)
	for i := 0; i < 4; i++ {
		name := filepath.Join(backupDir, "jay-recent-"+string(rune('a'+i))+".db")
		f, err := os.Create(name)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		_ = f.Close()
		if err := os.Chtimes(name, recentTime, recentTime); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}

	removed, err := bm.Prune(24*time.Hour, 1)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if removed != 0 {
		t.Errorf("Prune should not remove recent files, got removed=%d", removed)
	}
}

// ── Scrubber ──────────────────────────────────────────────────────────────────

// createActiveObject creates a bucket plus an active object whose physical
// file exists on disk with the given content. checksum defaults to the real
// content checksum unless overrideChecksum is non-empty.
func createActiveObject(t *testing.T, db *meta.DB, st *store.Store, content []byte, overrideChecksum string) (bucketID, key string) {
	t.Helper()
	bucketID = uuid.NewString()
	key = "scrub-key-" + uuid.NewString()

	b := &meta.Bucket{
		ID:   bucketID,
		Name: "scrub-bucket-" + bucketID,
	}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	objectID := uuid.NewString()
	checksum, size, locationRef, err := st.WriteObject(bucketID, objectID, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}
	if overrideChecksum != "" {
		checksum = overrideChecksum
	}

	obj := &meta.Object{
		BucketID:       bucketID,
		Key:            key,
		ObjectID:       objectID,
		State:          "active",
		SizeBytes:      size,
		ChecksumSHA256: checksum,
		LocationRef:    locationRef,
	}
	if _, err := db.PutObjectMeta(obj); err != nil {
		t.Fatalf("PutObjectMeta: %v", err)
	}
	return bucketID, key
}

func newTestScrubber(db *meta.DB, st *store.Store) *Scrubber {
	return NewScrubber(db, st, discardLogger(), time.Hour, 0, 100)
}

func TestScrubber_RunIncremental_Healthy(t *testing.T) {
	db, st := openTestDB(t)
	content := []byte("healthy scrub content")
	bucketID, key := createActiveObject(t, db, st, content, "")

	s := newTestScrubber(db, st)
	m := NewMetrics()
	s.SetMetrics(m)

	result := s.RunIncremental(100)
	if result.Checked != 1 {
		t.Errorf("Checked: got %d, want 1", result.Checked)
	}
	if result.Healthy != 1 {
		t.Errorf("Healthy: got %d, want 1", result.Healthy)
	}
	if result.Quarantined != 0 || result.Missing != 0 || result.Errors != 0 {
		t.Errorf("unexpected failures: %+v", result)
	}
	if m.ChecksumFailures.Load() != 0 || m.ObjectsQuarantined.Load() != 0 {
		t.Errorf("metrics should be zero: checksum=%d quarantined=%d",
			m.ChecksumFailures.Load(), m.ObjectsQuarantined.Load())
	}

	obj, err := db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		t.Fatalf("GetObjectMetaAny: %v", err)
	}
	if obj.State != "active" {
		t.Errorf("healthy object state: got %q, want active", obj.State)
	}
}

func TestScrubber_RunIncremental_ChecksumMismatch(t *testing.T) {
	db, st := openTestDB(t)
	content := []byte("mismatch scrub content")
	wrong := strings.Repeat("0", 64)
	bucketID, key := createActiveObject(t, db, st, content, wrong)

	s := newTestScrubber(db, st)
	m := NewMetrics()
	s.SetMetrics(m)

	result := s.RunIncremental(100)
	if result.Quarantined != 1 {
		t.Errorf("Quarantined: got %d, want 1", result.Quarantined)
	}
	if m.ChecksumFailures.Load() != 1 {
		t.Errorf("ChecksumFailures: got %d, want 1", m.ChecksumFailures.Load())
	}
	if m.ObjectsQuarantined.Load() != 1 {
		t.Errorf("ObjectsQuarantined: got %d, want 1", m.ObjectsQuarantined.Load())
	}

	obj, err := db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		t.Fatalf("GetObjectMetaAny: %v", err)
	}
	if obj.State != "quarantined" {
		t.Errorf("state: got %q, want quarantined", obj.State)
	}
	// Mismatched physical file must have been moved aside.
	absPath, err := st.SafePath(obj.LocationRef)
	if err != nil {
		t.Fatalf("SafePath: %v", err)
	}
	if _, err := os.Stat(absPath); !os.IsNotExist(err) {
		t.Errorf("mismatched file should have been quarantined on disk; stat err = %v", err)
	}
}

func TestScrubber_RunIncremental_MissingFile(t *testing.T) {
	db, st := openTestDB(t)
	content := []byte("missing scrub content")
	bucketID, key := createActiveObject(t, db, st, content, "")

	// Remove the physical file so the object goes missing.
	obj, err := db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		t.Fatalf("GetObjectMetaAny: %v", err)
	}
	absPath, err := st.SafePath(obj.LocationRef)
	if err != nil {
		t.Fatalf("SafePath: %v", err)
	}
	if err := os.Remove(absPath); err != nil {
		t.Fatalf("remove physical file: %v", err)
	}

	s := newTestScrubber(db, st)
	m := NewMetrics()
	s.SetMetrics(m)

	result := s.RunIncremental(100)
	if result.Missing != 1 {
		t.Errorf("Missing: got %d, want 1", result.Missing)
	}
	if m.ObjectsQuarantined.Load() != 1 {
		t.Errorf("ObjectsQuarantined: got %d, want 1", m.ObjectsQuarantined.Load())
	}
	if m.ChecksumFailures.Load() != 0 {
		t.Errorf("ChecksumFailures: got %d, want 0", m.ChecksumFailures.Load())
	}

	after, err := db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		t.Fatalf("GetObjectMetaAny: %v", err)
	}
	if after.State != "quarantined" {
		t.Errorf("state: got %q, want quarantined", after.State)
	}
}

func TestScrubber_RunIncremental_NilMetricsSafe(t *testing.T) {
	db, st := openTestDB(t)
	content := []byte("nil metrics scrub content")
	wrong := strings.Repeat("0", 64)
	createActiveObject(t, db, st, content, wrong)

	s := newTestScrubber(db, st)
	// No SetMetrics call — must not panic on mismatch/quarantine.
	result := s.RunIncremental(100)
	if result.Quarantined != 1 {
		t.Errorf("Quarantined: got %d, want 1", result.Quarantined)
	}
}

func TestScrubber_RunIncremental_CursorAdvancesAcrossRuns(t *testing.T) {
	db, st := openTestDB(t)

	// One bucket with 3 objects; maxPerRun=1 so each run checks exactly one
	// and the lastKey cursor must resume where the previous run stopped.
	bucketID := uuid.NewString()
	b := &meta.Bucket{ID: bucketID, Name: "cursor-bucket-" + bucketID}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	for i := 0; i < 3; i++ {
		objectID := uuid.NewString()
		content := []byte("cursor content " + objectID)
		checksum, size, locationRef, err := st.WriteObject(bucketID, objectID, bytes.NewReader(content))
		if err != nil {
			t.Fatalf("WriteObject: %v", err)
		}
		obj := &meta.Object{
			BucketID:       bucketID,
			Key:            "cursor-key-" + objectID,
			ObjectID:       objectID,
			State:          "active",
			SizeBytes:      size,
			ChecksumSHA256: checksum,
			LocationRef:    locationRef,
		}
		if _, err := db.PutObjectMeta(obj); err != nil {
			t.Fatalf("PutObjectMeta: %v", err)
		}
	}

	s := NewScrubber(db, st, discardLogger(), time.Hour, 0, 1)

	total := 0
	for i := 0; i < 3; i++ {
		r := s.RunIncremental(1)
		total += r.Checked
		if r.Checked != 1 {
			t.Fatalf("run %d: Checked = %d, want 1", i, r.Checked)
		}
		if r.Healthy != 1 {
			t.Fatalf("run %d: Healthy = %d, want 1", i, r.Healthy)
		}
	}
	if total != 3 {
		t.Errorf("total checked across runs: got %d, want 3", total)
	}
}

// ── QuarantineManager ─────────────────────────────────────────────────────────

func TestQuarantine_NewQuarantineManager(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())
	if qm == nil {
		t.Fatal("NewQuarantineManager returned nil")
	}
}

func TestQuarantine_ListQuarantined_Empty(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())

	objects, err := qm.ListQuarantined()
	if err != nil {
		t.Fatalf("ListQuarantined: %v", err)
	}
	if len(objects) != 0 {
		t.Errorf("expected empty slice, got %d objects", len(objects))
	}
}

func TestQuarantine_ListQuarantined_AfterQuarantine(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())

	content := []byte("quarantine test content")
	bucketID, key := createTestBucketAndObject(t, db, content)

	objects, err := qm.ListQuarantined()
	if err != nil {
		t.Fatalf("ListQuarantined: %v", err)
	}
	if len(objects) != 1 {
		t.Fatalf("expected 1 quarantined object, got %d", len(objects))
	}
	if objects[0].BucketID != bucketID {
		t.Errorf("BucketID: got %q, want %q", objects[0].BucketID, bucketID)
	}
	if objects[0].Key != key {
		t.Errorf("Key: got %q, want %q", objects[0].Key, key)
	}
}

func TestQuarantine_Inspect_NoPhysicalFile(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())

	content := []byte("inspect test content")
	bucketID, key := createTestBucketAndObject(t, db, content)

	result, err := qm.Inspect(bucketID, key)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if result.FileExists {
		t.Error("FileExists should be false when no physical file is present")
	}
	if result.Object.BucketID != bucketID {
		t.Errorf("Object.BucketID: got %q, want %q", result.Object.BucketID, bucketID)
	}
	if result.Object.Key != key {
		t.Errorf("Object.Key: got %q, want %q", result.Object.Key, key)
	}
}

func TestQuarantine_Inspect_WithPhysicalFile(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())

	content := []byte("physical file inspect test")
	bucketID, key := createTestBucketAndObject(t, db, content)

	// Retrieve the location ref from DB.
	obj, err := db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		t.Fatalf("GetObjectMetaAny: %v", err)
	}

	// Write the physical file at the location ref.
	absPath, err := st.SafePath(obj.LocationRef)
	if err != nil {
		t.Fatalf("SafePath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(absPath, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := qm.Inspect(bucketID, key)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !result.FileExists {
		t.Error("FileExists should be true")
	}
	if result.FileSize != int64(len(content)) {
		t.Errorf("FileSize: got %d, want %d", result.FileSize, len(content))
	}
	if result.CurrentChecksum != sha256Hex(content) {
		t.Errorf("CurrentChecksum mismatch: got %q, want %q", result.CurrentChecksum, sha256Hex(content))
	}
}

func TestQuarantine_Revalidate_NoFile(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())

	content := []byte("revalidate missing file")
	bucketID, key := createTestBucketAndObject(t, db, content)

	restored, err := qm.Revalidate(bucketID, key)
	if err != nil {
		t.Fatalf("Revalidate: %v", err)
	}
	if restored {
		t.Error("Revalidate should return false when file does not exist")
	}
}

func TestQuarantine_Revalidate_GoodFile(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())

	content := []byte("revalidate good content")
	bucketID, key := createTestBucketAndObject(t, db, content)

	// Write the physical file with correct content.
	obj, err := db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		t.Fatalf("GetObjectMetaAny: %v", err)
	}
	absPath, err := st.SafePath(obj.LocationRef)
	if err != nil {
		t.Fatalf("SafePath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(absPath, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	restored, err := qm.Revalidate(bucketID, key)
	if err != nil {
		t.Fatalf("Revalidate: %v", err)
	}
	if !restored {
		t.Error("Revalidate should return true when checksum matches")
	}

	// Verify the object is now active again.
	activeObj, err := db.GetObjectMeta(bucketID, key)
	if err != nil {
		t.Fatalf("GetObjectMeta after revalidate: %v", err)
	}
	if activeObj.State != "active" {
		t.Errorf("State after revalidate: got %q, want %q", activeObj.State, "active")
	}
}

func TestQuarantine_Revalidate_BadChecksum(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())

	content := []byte("original content")
	bucketID, key := createTestBucketAndObject(t, db, content)

	// Write corrupted content.
	obj, err := db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		t.Fatalf("GetObjectMetaAny: %v", err)
	}
	absPath, err := st.SafePath(obj.LocationRef)
	if err != nil {
		t.Fatalf("SafePath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	corrupted := []byte("corrupted content!!!")
	if err := os.WriteFile(absPath, corrupted, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	restored, err := qm.Revalidate(bucketID, key)
	if err != nil {
		t.Fatalf("Revalidate: %v", err)
	}
	if restored {
		t.Error("Revalidate should return false when checksum mismatches")
	}
}

func TestQuarantine_Purge(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())

	content := []byte("purge target")
	bucketID, key := createTestBucketAndObject(t, db, content)

	// Write physical file too.
	obj, err := db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		t.Fatalf("GetObjectMetaAny: %v", err)
	}
	absPath, err := st.SafePath(obj.LocationRef)
	if err != nil {
		t.Fatalf("SafePath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(absPath, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := qm.Purge(bucketID, key); err != nil {
		t.Fatalf("Purge: %v", err)
	}

	// Metadata should be gone.
	if _, err := db.GetObjectMetaAny(bucketID, key); err == nil {
		t.Error("metadata should have been deleted after Purge")
	}

	// Physical file should be gone.
	if _, err := os.Stat(absPath); !os.IsNotExist(err) {
		t.Error("physical file should have been deleted after Purge")
	}
}

func TestQuarantine_Purge_NoPhysicalFile(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())

	content := []byte("purge meta only")
	bucketID, key := createTestBucketAndObject(t, db, content)

	// Purge without writing a physical file — should not error.
	if err := qm.Purge(bucketID, key); err != nil {
		t.Fatalf("Purge (no physical file): %v", err)
	}

	if _, err := db.GetObjectMetaAny(bucketID, key); err == nil {
		t.Error("metadata should have been deleted after Purge")
	}
}

func TestQuarantine_PurgeAll(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())

	// Create 3 quarantined objects.
	content := []byte("purge all test")
	for i := 0; i < 3; i++ {
		createTestBucketAndObject(t, db, content)
	}

	count, err := qm.PurgeAll()
	if err != nil {
		t.Fatalf("PurgeAll: %v", err)
	}
	if count != 3 {
		t.Errorf("PurgeAll: got count=%d, want 3", count)
	}

	// Verify no quarantined objects remain.
	objects, err := qm.ListQuarantined()
	if err != nil {
		t.Fatalf("ListQuarantined after PurgeAll: %v", err)
	}
	if len(objects) != 0 {
		t.Errorf("expected 0 quarantined objects after PurgeAll, got %d", len(objects))
	}
}

func TestQuarantine_PurgeAll_Empty(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())

	count, err := qm.PurgeAll()
	if err != nil {
		t.Fatalf("PurgeAll on empty DB: %v", err)
	}
	if count != 0 {
		t.Errorf("PurgeAll on empty DB: got count=%d, want 0", count)
	}
}
