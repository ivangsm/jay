package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
	"uuid"

	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

// These tests are the disaster-recovery runbook, executed.
//
// The hourly snapshot covers metadata and nothing else, so "jay has verified
// backups" is only half a sentence: a restore needs the object bytes from
// somewhere else, and it needs them FIRST. Both halves of that claim are
// asserted here against real files and a real reconciliation pass, because the
// alternative — a page of instructions nobody has ever run — is exactly the
// kind of guarantee that turns out to be theatre at the worst possible moment.
//
// The procedure under test is the one documented in
// site/src/content/docs/guides/backup-and-restore.md. If it changes there, it
// changes here.

// liveInstall is a running jay: a metadata database, a store, and the objects
// written through both.
type liveInstall struct {
	dataDir  string
	db       *meta.DB
	st       *store.Store
	bucketID string
	objects  map[string][]byte // key → bytes
}

// newLiveInstall builds an installation with keys worth of real objects,
// written through the store's own write path so the checksums and location
// refs are the ones jay would have produced.
func newLiveInstall(t *testing.T, keys ...string) *liveInstall {
	t.Helper()

	dir := t.TempDir()
	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetSigningSecret("test-signing-secret-at-least-32-chars!!")
	t.Cleanup(func() { _ = db.Close() })

	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	bucketID := uuid.New().String()
	if err := db.CreateBucket(&meta.Bucket{
		ID:         bucketID,
		Name:       "dr-drill",
		Visibility: "private",
		Status:     "active",
	}); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	install := &liveInstall{dataDir: dir, db: db, st: st, bucketID: bucketID, objects: map[string][]byte{}}
	for _, key := range keys {
		install.objects[key] = install.put(t, key)
	}
	return install
}

// put writes one object exactly the way a PUT would: bytes first, metadata
// second.
func (li *liveInstall) put(t *testing.T, key string) []byte {
	t.Helper()

	content := []byte("contents of " + key + " — " + uuid.New().String())
	objectID := uuid.New().String()

	checksum, size, locationRef, err := li.st.WriteObject(li.bucketID, objectID, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("WriteObject %s: %v", key, err)
	}
	if _, err := li.db.PutObjectMeta(&meta.Object{
		BucketID:       li.bucketID,
		Key:            key,
		ObjectID:       objectID,
		State:          "active",
		SizeBytes:      size,
		ContentType:    "application/octet-stream",
		ChecksumSHA256: checksum,
		LocationRef:    locationRef,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("PutObjectMeta %s: %v", key, err)
	}
	return content
}

// snapshot runs the hourly metadata backup into a directory outside the data
// directory — the separate volume the documentation asks for — and returns the
// path of the snapshot file.
func (li *liveInstall) snapshot(t *testing.T) string {
	t.Helper()

	backupDir := t.TempDir()
	bm := maintenance.NewBackupManager(li.db, backupDir, li.dataDir, testLogger())
	path, err := bm.Run()
	if err != nil {
		t.Fatalf("metadata snapshot: %v", err)
	}
	return path
}

// restoredInstall is a fresh machine that a restore has been performed onto.
type restoredInstall struct {
	dataDir string
	db      *meta.DB
	st      *store.Store
	metrics *maintenance.Metrics
}

// restore builds a new data directory and performs the documented procedure.
// withObjectBytes selects between the complete restore and the metadata-only
// one, which is what an operator ends up with when they trusted the hourly
// snapshot to be the whole backup.
func restore(t *testing.T, source *liveInstall, snapshotPath string, withObjectBytes bool) *restoredInstall {
	t.Helper()

	dataDir := t.TempDir()
	st, err := store.New(dataDir)
	if err != nil {
		t.Fatalf("new store on restore target: %v", err)
	}

	// Step 1 of the runbook: the object bytes, from whatever file-level tool
	// copied buckets/. They are immutable once renamed into place, so copying
	// them from a running server is safe.
	if withObjectBytes {
		copyTree(t, filepath.Join(source.dataDir, "buckets"), filepath.Join(dataDir, "buckets"))
	}

	// Step 2: the metadata, from the snapshot jay verified when it wrote it.
	copyFile(t, snapshotPath, filepath.Join(dataDir, "meta", "jay.db"))

	db, err := meta.Open(filepath.Join(dataDir, "meta", "jay.db"))
	if err != nil {
		t.Fatalf("open restored db: %v", err)
	}
	db.SetSigningSecret("test-signing-secret-at-least-32-chars!!")
	t.Cleanup(func() { _ = db.Close() })

	return &restoredInstall{dataDir: dataDir, db: db, st: st, metrics: maintenance.NewMetrics()}
}

// boot runs startup reconciliation, which is what a restored installation does
// before it accepts its first request.
func (ri *restoredInstall) boot(t *testing.T) {
	t.Helper()
	if err := RunWithMetrics(ri.db, ri.st, testLogger(), ri.metrics); err != nil {
		t.Fatalf("recovery on restored install: %v", err)
	}
}

// readObject returns the bytes behind a key on the restored install, reading
// them off disk the way GetObject would.
func (ri *restoredInstall) readObject(t *testing.T, bucketID, key string) []byte {
	t.Helper()

	obj, err := ri.db.GetObjectMeta(bucketID, key)
	if err != nil {
		t.Fatalf("GetObjectMeta %s: %v", key, err)
	}
	if obj == nil {
		t.Fatalf("%s: no active record after restore", key)
	}
	path, err := ri.st.SafePath(obj.LocationRef)
	if err != nil {
		t.Fatalf("SafePath %s: %v", obj.LocationRef, err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // path came out of SafePath
	if err != nil {
		t.Fatalf("read restored object %s: %v", key, err)
	}
	// The stored checksum is what the scrubber compares against; a restore
	// that produced different bytes has to fail here and not on some later
	// background pass.
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != obj.ChecksumSHA256 {
		t.Errorf("%s: restored bytes do not match the stored checksum", key)
	}
	return got
}

// TestDisasterRecovery_ObjectsThenMetadata is the runbook's happy path: the
// object bytes go back first, the verified metadata snapshot second, and the
// installation comes up whole. Nothing is quarantined, and every object reads
// back byte for byte.
func TestDisasterRecovery_ObjectsThenMetadata(t *testing.T) {
	live := newLiveInstall(t, "invoices/2026-09.pdf", "avatars/ivan.webp", "big/blob.bin")
	snapshotPath := live.snapshot(t)

	restored := restore(t, live, snapshotPath, true)
	restored.boot(t)

	for key, want := range live.objects {
		if got := restored.readObject(t, live.bucketID, key); !bytes.Equal(got, want) {
			t.Errorf("%s: restored %d bytes, want %d", key, len(got), len(want))
		}
	}

	if n := restored.metrics.ObjectsQuarantined.Load(); n != 0 {
		t.Errorf("a complete restore must quarantine nothing, got %d", n)
	}
}

// TestDisasterRecovery_MetadataSnapshotAloneRecoversNothing is the claim that
// PND-0169 is about, asserted rather than documented: restoring only what jay
// backs up gives an installation that quarantines every object it ever held.
//
// The snapshot verifies fine and reports its object count. Not one of those
// records has bytes behind it.
func TestDisasterRecovery_MetadataSnapshotAloneRecoversNothing(t *testing.T) {
	keys := []string{"invoices/2026-09.pdf", "avatars/ivan.webp", "big/blob.bin"}
	live := newLiveInstall(t, keys...)
	snapshotPath := live.snapshot(t)

	// The snapshot is healthy by jay's own standard and knows about every
	// object — which is precisely why the count is not a recovery guarantee.
	bm := maintenance.NewBackupManager(live.db, filepath.Dir(snapshotPath), live.dataDir, testLogger())
	result, err := bm.Verify(snapshotPath)
	if err != nil {
		t.Fatalf("verify snapshot: %v", err)
	}
	if result.ObjectCount != len(keys) {
		t.Fatalf("snapshot object records: got %d, want %d", result.ObjectCount, len(keys))
	}

	restored := restore(t, live, snapshotPath, false)
	restored.boot(t)

	for _, key := range keys {
		assertQuarantined(t, restored.db, live.bucketID, key)
	}

	if n := restored.metrics.ObjectsQuarantined.Load(); n != int64(len(keys)) {
		t.Errorf("quarantined %d records, want %d — every object the snapshot knew about", n, len(keys))
	}
}

// TestDisasterRecovery_MetadataBeforeObjectsStrandsBoth is why the runbook puts
// the object bytes first and why that ordering is not a stylistic preference.
//
// Boot on metadata alone and every record is quarantined. Copying the bytes in
// afterwards does not undo it: the records stay quarantined, and the files that
// just arrived are now orphans with nothing pointing at them, so the next boot
// quarantines those too. The installation ends up holding both halves of every
// object and serving neither.
func TestDisasterRecovery_MetadataBeforeObjectsStrandsBoth(t *testing.T) {
	keys := []string{"invoices/2026-09.pdf", "avatars/ivan.webp"}
	live := newLiveInstall(t, keys...)
	snapshotPath := live.snapshot(t)

	restored := restore(t, live, snapshotPath, false)
	restored.boot(t)

	if n := restored.metrics.ObjectsQuarantined.Load(); n != int64(len(keys)) {
		t.Fatalf("first boot quarantined %d records, want %d", n, len(keys))
	}

	// Now do what someone would do on noticing: copy the bytes in and restart.
	copyTree(t, filepath.Join(live.dataDir, "buckets"), filepath.Join(restored.dataDir, "buckets"))
	restored.boot(t)

	for _, key := range keys {
		assertQuarantined(t, restored.db, live.bucketID, key)
	}

	// len(keys) records on the first boot, len(keys) files on the second.
	if want := int64(2 * len(keys)); restored.metrics.ObjectsQuarantined.Load() != want {
		t.Errorf("quarantined %d in total, want %d (the records, then their files)",
			restored.metrics.ObjectsQuarantined.Load(), want)
	}

	// Nothing was destroyed, which is the one thing that goes right here: the
	// bytes are in quarantine, recoverable by hand.
	entries, err := os.ReadDir(filepath.Join(restored.dataDir, "quarantine"))
	if err != nil {
		t.Fatalf("read quarantine dir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("quarantine is empty; the orphaned files were not preserved")
	}
}

// --- helpers -----------------------------------------------------------------

// assertQuarantined checks both halves of what quarantine means: the object is
// no longer reachable, and the record still exists. The second half is the one
// worth asserting — recovery must never delete the evidence of what went wrong.
func assertQuarantined(t *testing.T, db *meta.DB, bucketID, key string) {
	t.Helper()

	if _, err := db.GetObjectMeta(bucketID, key); !errors.Is(err, meta.ErrObjectNotFound) {
		t.Errorf("%s: should be unreachable after quarantine, got err=%v", key, err)
	}
	obj, err := db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		t.Fatalf("%s: the record must survive quarantine, got err=%v", key, err)
	}
	if obj.State != "quarantined" {
		t.Errorf("%s: state is %q, want quarantined", key, obj.State)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.RemoveAll(dst); err != nil {
		t.Fatalf("clear %s: %v", dst, err)
	}
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatalf("copy %s → %s: %v", src, dst, err)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src) //nolint:gosec // both paths are test temp dirs
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", dst, err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}
