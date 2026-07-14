package recovery

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

func openTestEnv(t *testing.T) (*meta.DB, *store.Store, *slog.Logger) {
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
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return db, st, log
}

// TestRun_EmptyDB verifies that Run succeeds on a completely empty store and DB.
func TestRun_EmptyDB(t *testing.T) {
	db, st, log := openTestEnv(t)
	if err := Run(db, st, log); err != nil {
		t.Fatalf("Run on empty DB: %v", err)
	}
}

// TestRun_CleansTmpFiles verifies that Run removes orphaned files from the tmp directory.
func TestRun_CleansTmpFiles(t *testing.T) {
	db, st, log := openTestEnv(t)

	// Manually create a leftover tmp file.
	tmpDir := filepath.Join(st.DataDir(), "tmp")
	tmpFile := filepath.Join(tmpDir, "leftover.tmp")
	if err := os.WriteFile(tmpFile, []byte("stale"), 0o644); err != nil {
		t.Fatalf("create tmp file: %v", err)
	}

	// Verify it exists before Run.
	if _, err := os.Stat(tmpFile); err != nil {
		t.Fatalf("tmp file should exist before Run: %v", err)
	}

	if err := Run(db, st, log); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The file must be gone after Run.
	if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
		t.Errorf("tmp file should be removed after Run; stat err = %v", err)
	}
}

// TestRun_QuarantinesMetaWithoutFile verifies that an active object whose
// physical file is missing gets quarantined in the DB.
func TestRun_QuarantinesMetaWithoutFile(t *testing.T) {
	db, st, log := openTestEnv(t)

	bucketID := uuid.New().String()
	bkt := &meta.Bucket{
		ID:         bucketID,
		Name:       "test-bucket-no-file",
		Visibility: "private",
		Status:     "active",
	}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	objectID := uuid.New().String()
	key := "orphaned-meta.bin"
	// Build a locationRef that points to a non-existent file.
	locationRef := store.ObjectPath(bucketID, objectID)

	obj := &meta.Object{
		BucketID:    bucketID,
		Key:         key,
		ObjectID:    objectID,
		State:       "active",
		SizeBytes:   42,
		ContentType: "application/octet-stream",
		LocationRef: locationRef,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if _, err := db.PutObjectMeta(obj); err != nil {
		t.Fatalf("PutObjectMeta: %v", err)
	}

	// Confirm there is no physical file.
	absPath := filepath.Join(st.DataDir(), locationRef)
	if _, err := os.Stat(absPath); err == nil {
		t.Fatal("test setup error: physical file should not exist")
	}

	if err := Run(db, st, log); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Object must now be quarantined in the DB.
	got, err := db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		t.Fatalf("GetObjectMetaAny: %v", err)
	}
	if got.State != "quarantined" {
		t.Errorf("want state=quarantined, got %q", got.State)
	}
}

// TestRunWithMetrics_CountsQuarantines verifies that RunWithMetrics increments
// ObjectsQuarantined for every effective quarantine (metadata without file and
// orphaned physical file), and that Run (nil metrics) keeps working.
func TestRunWithMetrics_CountsQuarantines(t *testing.T) {
	db, st, log := openTestEnv(t)

	bucketID := uuid.New().String()
	bkt := &meta.Bucket{
		ID:         bucketID,
		Name:       "test-bucket-metrics",
		Visibility: "private",
		Status:     "active",
	}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	// 1. Active metadata entry with no physical file → meta quarantine.
	orphanMetaID := uuid.New().String()
	obj := &meta.Object{
		BucketID:    bucketID,
		Key:         "metrics-orphan-meta.bin",
		ObjectID:    orphanMetaID,
		State:       "active",
		SizeBytes:   7,
		ContentType: "application/octet-stream",
		LocationRef: store.ObjectPath(bucketID, orphanMetaID),
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if _, err := db.PutObjectMeta(obj); err != nil {
		t.Fatalf("PutObjectMeta: %v", err)
	}

	// 2. Physical file with no metadata → file quarantine.
	if err := st.EnsureBucketDir(bucketID); err != nil {
		t.Fatalf("EnsureBucketDir: %v", err)
	}
	if _, _, _, err := st.WriteObject(bucketID, uuid.New().String(), strings.NewReader("orphan file")); err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	m := maintenance.NewMetrics()
	if err := RunWithMetrics(db, st, log, m); err != nil {
		t.Fatalf("RunWithMetrics: %v", err)
	}

	if got := m.ObjectsQuarantined.Load(); got != 2 {
		t.Errorf("ObjectsQuarantined: got %d, want 2", got)
	}

	// Metadata entry must actually be quarantined.
	got, err := db.GetObjectMetaAny(bucketID, "metrics-orphan-meta.bin")
	if err != nil {
		t.Fatalf("GetObjectMetaAny: %v", err)
	}
	if got.State != "quarantined" {
		t.Errorf("want state=quarantined, got %q", got.State)
	}
}

// TestRunWithMetrics_NilMetrics verifies nil metrics are tolerated even when
// quarantines occur.
func TestRunWithMetrics_NilMetrics(t *testing.T) {
	db, st, log := openTestEnv(t)

	bucketID := uuid.New().String()
	bkt := &meta.Bucket{
		ID:         bucketID,
		Name:       "test-bucket-nil-metrics",
		Visibility: "private",
		Status:     "active",
	}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	objectID := uuid.New().String()
	obj := &meta.Object{
		BucketID:    bucketID,
		Key:         "nil-metrics-orphan.bin",
		ObjectID:    objectID,
		State:       "active",
		SizeBytes:   3,
		ContentType: "application/octet-stream",
		LocationRef: store.ObjectPath(bucketID, objectID),
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if _, err := db.PutObjectMeta(obj); err != nil {
		t.Fatalf("PutObjectMeta: %v", err)
	}

	if err := RunWithMetrics(db, st, log, nil); err != nil {
		t.Fatalf("RunWithMetrics(nil): %v", err)
	}

	got, err := db.GetObjectMetaAny(bucketID, "nil-metrics-orphan.bin")
	if err != nil {
		t.Fatalf("GetObjectMetaAny: %v", err)
	}
	if got.State != "quarantined" {
		t.Errorf("want state=quarantined, got %q", got.State)
	}
}

// TestRun_ManyMissingObjects exercises the collect-then-quarantine path with
// enough entries to require multiple write transactions after the view tx.
func TestRun_ManyMissingObjects(t *testing.T) {
	db, st, log := openTestEnv(t)

	bucketID := uuid.New().String()
	bkt := &meta.Bucket{
		ID:         bucketID,
		Name:       "test-bucket-many-missing",
		Visibility: "private",
		Status:     "active",
	}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	const n = 50
	keys := make([]string, 0, n)
	for i := 0; i < n; i++ {
		objectID := uuid.New().String()
		key := "missing-" + objectID
		keys = append(keys, key)
		obj := &meta.Object{
			BucketID:    bucketID,
			Key:         key,
			ObjectID:    objectID,
			State:       "active",
			SizeBytes:   1,
			ContentType: "application/octet-stream",
			LocationRef: store.ObjectPath(bucketID, objectID),
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		}
		if _, err := db.PutObjectMeta(obj); err != nil {
			t.Fatalf("PutObjectMeta %d: %v", i, err)
		}
	}

	m := maintenance.NewMetrics()
	if err := RunWithMetrics(db, st, log, m); err != nil {
		t.Fatalf("RunWithMetrics: %v", err)
	}

	if got := m.ObjectsQuarantined.Load(); got != n {
		t.Errorf("ObjectsQuarantined: got %d, want %d", got, n)
	}
	for _, key := range keys {
		got, err := db.GetObjectMetaAny(bucketID, key)
		if err != nil {
			t.Fatalf("GetObjectMetaAny(%q): %v", key, err)
		}
		if got.State != "quarantined" {
			t.Fatalf("key %q: want state=quarantined, got %q", key, got.State)
		}
	}
}

// TestRun_QuarantinesOrphanedPhysicalFile verifies that a physical file with no
// corresponding metadata entry is moved to the quarantine directory.
func TestRun_QuarantinesOrphanedPhysicalFile(t *testing.T) {
	db, st, log := openTestEnv(t)

	bucketID := uuid.New().String()
	bkt := &meta.Bucket{
		ID:         bucketID,
		Name:       "test-bucket-orphan-file",
		Visibility: "private",
		Status:     "active",
	}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	// Ensure bucket directory exists on disk.
	if err := st.EnsureBucketDir(bucketID); err != nil {
		t.Fatalf("EnsureBucketDir: %v", err)
	}

	// Write a physical file with no metadata.
	objectID := uuid.New().String()
	_, _, locationRef, err := st.WriteObject(bucketID, objectID, strings.NewReader("orphaned content"))
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	// Confirm the file exists before Run.
	absPath := filepath.Join(st.DataDir(), locationRef)
	if _, err := os.Stat(absPath); err != nil {
		t.Fatalf("physical file should exist before Run: %v", err)
	}

	if err := Run(db, st, log); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The file must no longer be at its original location.
	if _, err := os.Stat(absPath); !os.IsNotExist(err) {
		t.Errorf("orphaned file should be removed from original location; stat err = %v", err)
	}

	// The file must have been moved to the quarantine directory. The
	// destination name flattens the full locationRef (so multipart parts from
	// different uploads can't collide) and appends a uniquifying suffix, so
	// match on the prefix rather than on the basename.
	flat := strings.ReplaceAll(filepath.Clean(locationRef), string(filepath.Separator), "_")
	matches, err := filepath.Glob(filepath.Join(st.DataDir(), "quarantine", flat+".*"))
	if err != nil {
		t.Fatalf("glob quarantine dir: %v", err)
	}
	if len(matches) != 1 {
		t.Errorf("orphaned file should be in quarantine dir as %q.*, got %v", flat, matches)
	}
}

// TestRun_HealthyObject_NotQuarantined verifies that a well-formed active
// object with a matching physical file is left untouched by Run.
func TestRun_HealthyObject_NotQuarantined(t *testing.T) {
	db, st, log := openTestEnv(t)

	bucketID := uuid.New().String()
	bkt := &meta.Bucket{
		ID:         bucketID,
		Name:       "test-bucket-healthy",
		Visibility: "private",
		Status:     "active",
	}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	// Write the physical file first to get the locationRef.
	objectID := uuid.New().String()
	_, size, locationRef, err := st.WriteObject(bucketID, objectID, strings.NewReader("healthy content"))
	if err != nil {
		t.Fatalf("WriteObject: %v", err)
	}

	// Register the matching metadata.
	obj := &meta.Object{
		BucketID:    bucketID,
		Key:         "healthy.bin",
		ObjectID:    objectID,
		State:       "active",
		SizeBytes:   size,
		ContentType: "application/octet-stream",
		LocationRef: locationRef,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if _, err := db.PutObjectMeta(obj); err != nil {
		t.Fatalf("PutObjectMeta: %v", err)
	}

	if err := Run(db, st, log); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Object must still be active after reconciliation.
	got, err := db.GetObjectMetaAny(bucketID, "healthy.bin")
	if err != nil {
		t.Fatalf("GetObjectMetaAny: %v", err)
	}
	if got.State != "active" {
		t.Errorf("want state=active, got %q", got.State)
	}
}

// TestRun_IgnoresNonActiveObjects verifies that Run does not double-quarantine
// objects that are already in a non-active state (e.g. already "quarantined").
func TestRun_IgnoresNonActiveObjects(t *testing.T) {
	db, st, log := openTestEnv(t)

	bucketID := uuid.New().String()
	bkt := &meta.Bucket{
		ID:         bucketID,
		Name:       "test-bucket-already-quarantined",
		Visibility: "private",
		Status:     "active",
	}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	objectID := uuid.New().String()
	key := "already-quar.bin"
	// Build a locationRef that has no physical file — intentional.
	locationRef := store.ObjectPath(bucketID, objectID)

	// Insert the object directly in "quarantined" state (no active→quarantine transition needed).
	obj := &meta.Object{
		BucketID:    bucketID,
		Key:         key,
		ObjectID:    objectID,
		State:       "quarantined",
		SizeBytes:   10,
		ContentType: "application/octet-stream",
		LocationRef: locationRef,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if _, err := db.PutObjectMeta(obj); err != nil {
		t.Fatalf("PutObjectMeta: %v", err)
	}

	// Run must not return an error or panic.
	if err := Run(db, st, log); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The object must remain quarantined — Run should not have touched it.
	got, err := db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		t.Fatalf("GetObjectMetaAny: %v", err)
	}
	if got.State != "quarantined" {
		t.Errorf("want state=quarantined (unchanged), got %q", got.State)
	}
}
