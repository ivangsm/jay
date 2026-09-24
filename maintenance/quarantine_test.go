package maintenance

// What the quarantine surface must refuse, and what it must report. The happy
// paths are in maintenance_test.go.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivangsm/jay/meta"
)

// writeObjectFile puts content at the object's location, as a PUT would have.
func writeObjectFile(t *testing.T, db *meta.DB, st interface {
	SafePath(string) (string, error)
}, bucketID, key string, content []byte) string {
	t.Helper()
	obj, err := db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		t.Fatalf("GetObjectMetaAny: %v", err)
	}
	path, err := st.SafePath(obj.LocationRef)
	if err != nil {
		t.Fatalf("SafePath: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// unremovable turns path into a non-empty directory, which os.Remove cannot
// delete — as root too, unlike a permission change.
func unremovable(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(path, "blocker"), 0o755); err != nil {
		t.Fatalf("block: %v", err)
	}
}

// Purge is for quarantined objects. Naming an active one — a typo, a key from
// the wrong listing — used to delete its file and its record.
func TestQuarantine_PurgeRefusesAnActiveObject(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())
	content := []byte("live bytes")
	bucketID, key := createTestBucketAndObject(t, db, content)
	path := writeObjectFile(t, db, st, bucketID, key, content)
	if err := db.RestoreObject(bucketID, key); err != nil {
		t.Fatalf("make it active: %v", err)
	}

	if err := qm.Purge(bucketID, key); !errors.Is(err, meta.ErrObjectNotQuarantined) {
		t.Fatalf("Purge of an active object: err = %v, want ErrObjectNotQuarantined", err)
	}
	if obj, err := db.GetObjectMetaAny(bucketID, key); err != nil || obj.State != "active" {
		t.Fatalf("the active record after a refused purge: %+v, %v", obj, err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != string(content) {
		t.Fatalf("the active object's file after a refused purge: %q, %v", data, err)
	}
}

// Revalidating an active object used to rewrite its record and answer
// "restored".
func TestQuarantine_RevalidateRefusesAnActiveObject(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())
	content := []byte("live bytes")
	bucketID, key := createTestBucketAndObject(t, db, content)
	writeObjectFile(t, db, st, bucketID, key, content)
	if err := db.RestoreObject(bucketID, key); err != nil {
		t.Fatalf("make it active: %v", err)
	}
	before, err := db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	restored, err := qm.Revalidate(bucketID, key)
	if !errors.Is(err, meta.ErrObjectNotQuarantined) || restored {
		t.Fatalf("Revalidate of an active object: restored=%v err=%v", restored, err)
	}
	after, err := db.GetObjectMetaAny(bucketID, key)
	if err != nil || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("the record was rewritten: %v -> %v (%v)", before.UpdatedAt, after.UpdatedAt, err)
	}
}

// A file that cannot be removed fails the purge and keeps the record: still
// quarantined, still listed, and purged once the cause is gone. It used to be
// ignored — the record was deleted and the purge reported success over bytes
// still on disk.
func TestQuarantine_PurgeKeepsTheRecordWhenTheFileCannotBeRemoved(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())
	content := []byte("stuck")
	bucketID, key := createTestBucketAndObject(t, db, content)
	path := writeObjectFile(t, db, st, bucketID, key, content)
	unremovable(t, path)

	if err := qm.Purge(bucketID, key); err == nil {
		t.Fatal("Purge reported success although the file could not be removed")
	}
	if obj, err := db.GetObjectMetaAny(bucketID, key); err != nil || obj.State != "quarantined" {
		t.Fatalf("the record after a failed purge: %+v, %v", obj, err)
	}
	if listed, err := qm.ListQuarantined(); err != nil || len(listed) != 1 {
		t.Fatalf("the object is no longer listed after a failed purge: %v, %v", listed, err)
	}

	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("clear the obstacle: %v", err)
	}
	if err := qm.Purge(bucketID, key); err != nil {
		t.Fatalf("the retried purge: %v", err)
	}
	if _, err := db.GetObjectMetaAny(bucketID, key); !errors.Is(err, meta.ErrObjectNotFound) {
		t.Fatalf("the record survived the retried purge: %v", err)
	}
}

// PurgeAll keeps going past a failure but never reports a partial purge as a
// whole one.
func TestQuarantine_PurgeAllReportsEveryFailure(t *testing.T) {
	db, st := openTestDB(t)
	qm := NewQuarantineManager(db, st, discardLogger())

	var stuck []string
	for i := range 4 {
		content := []byte{byte('a' + i)}
		bucketID, key := createTestBucketAndObject(t, db, content)
		path := writeObjectFile(t, db, st, bucketID, key, content)
		if i%2 == 0 {
			unremovable(t, path)
			stuck = append(stuck, key)
		}
	}

	count, err := qm.PurgeAll()
	var partial *PurgeAllError
	if !errors.As(err, &partial) {
		t.Fatalf("PurgeAll with %d stuck objects: count=%d err=%v, want a *PurgeAllError", len(stuck), count, err)
	}
	if count != 2 || len(partial.Failed) != 2 {
		t.Fatalf("purged %d and reported %d failures, want 2 and 2", count, len(partial.Failed))
	}
	if msg := err.Error(); !strings.Contains(msg, "2 quarantined object(s) could not be purged") {
		t.Fatalf("the error does not say how many were left: %q", msg)
	}
	for _, f := range partial.Failed {
		if f.Error == "" || (f.Key != stuck[0] && f.Key != stuck[1]) {
			t.Fatalf("failure %+v does not name a stuck object with its reason", f)
		}
	}

	listed, err := qm.ListQuarantined()
	if err != nil || len(listed) != 2 {
		t.Fatalf("after the partial purge the quarantine holds %v (%v), want the 2 stuck objects", listed, err)
	}
}
