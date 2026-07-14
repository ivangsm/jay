package meta

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

func openBucketsTestDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestBucketStats_Empty(t *testing.T) {
	db := openBucketsTestDB(t)
	b := &Bucket{ID: uuid.New().String(), Name: "empty", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	count, size, err := db.BucketStats(b.ID)
	if err != nil {
		t.Fatalf("BucketStats: %v", err)
	}
	if count != 0 || size != 0 {
		t.Fatalf("expected 0/0, got %d/%d", count, size)
	}
}

func TestBucketStats_WithObjects(t *testing.T) {
	db := openBucketsTestDB(t)
	b := &Bucket{ID: uuid.New().String(), Name: "bk", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	for i, size := range []int64{100, 250, 700} {
		obj := &Object{
			BucketID:  b.ID,
			Key:       uuid.New().String(),
			ObjectID:  uuid.New().String(),
			SizeBytes: size,
			State:     "active",
			CreatedAt: time.Now().UTC(),
		}
		if _, err := db.PutObjectMeta(obj); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	count, size, err := db.BucketStats(b.ID)
	if err != nil {
		t.Fatalf("BucketStats: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected count=3, got %d", count)
	}
	if size != 1050 {
		t.Fatalf("expected size=1050, got %d", size)
	}
}

func TestBucketStats_IgnoresDeletedAndQuarantined(t *testing.T) {
	db := openBucketsTestDB(t)
	b := &Bucket{ID: uuid.New().String(), Name: "mix", Visibility: "private", Status: "active"}
	_ = db.CreateBucket(b)
	active := &Object{BucketID: b.ID, Key: "a", ObjectID: uuid.New().String(), SizeBytes: 100, State: "active"}
	quar := &Object{BucketID: b.ID, Key: "q", ObjectID: uuid.New().String(), SizeBytes: 200, State: "quarantined"}
	_, _ = db.PutObjectMeta(active)
	_, _ = db.PutObjectMeta(quar)
	count, size, err := db.BucketStats(b.ID)
	if err != nil {
		t.Fatalf("BucketStats: %v", err)
	}
	if count != 1 || size != 100 {
		t.Fatalf("expected 1/100, got %d/%d", count, size)
	}
}

// TestRebuildBucketStats_GobRecords verifies that RebuildBucketStats decodes
// objects persisted with the current binary (gob) codec. A previous version
// used json.Unmarshal directly, silently skipping every gob record and
// rebuilding the counter as (0,0).
func TestRebuildBucketStats_GobRecords(t *testing.T) {
	db := openBucketsTestDB(t)
	b := &Bucket{ID: uuid.New().String(), Name: "rebuild", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	// PutObjectMeta persists records via encodeObject (gob envelope).
	for i, size := range []int64{100, 250, 700} {
		obj := &Object{
			BucketID:  b.ID,
			Key:       uuid.New().String(),
			ObjectID:  uuid.New().String(),
			SizeBytes: size,
			State:     "active",
			CreatedAt: time.Now().UTC(),
		}
		if _, err := db.PutObjectMeta(obj); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	// A non-active record must not count toward the rebuilt stats.
	quar := &Object{BucketID: b.ID, Key: "q", ObjectID: uuid.New().String(), SizeBytes: 999, State: "quarantined"}
	if _, err := db.PutObjectMeta(quar); err != nil {
		t.Fatalf("put quarantined: %v", err)
	}

	// Sanity: records really are gob-encoded on disk (format byte 0x01).
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(objectsBucketName(b.ID))
		return bk.ForEach(func(k, v []byte) error {
			if len(v) == 0 || v[0] != formatGob {
				t.Fatalf("record %q not gob-encoded (first byte 0x%02x)", k, v[0])
			}
			return nil
		})
	}); err != nil {
		t.Fatalf("inspect records: %v", err)
	}

	// Clobber the maintained counter so a correct rebuild is observable.
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		stats := tx.Bucket(bucketSys).Bucket(sysBucketStats)
		return stats.Put([]byte(b.ID), encodeBucketStatsEntry(0, 0))
	}); err != nil {
		t.Fatalf("clobber stats: %v", err)
	}

	if err := db.RebuildBucketStats(b.ID); err != nil {
		t.Fatalf("RebuildBucketStats: %v", err)
	}

	count, size, err := db.BucketStats(b.ID)
	if err != nil {
		t.Fatalf("BucketStats: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected count=3 after rebuild, got %d", count)
	}
	if size != 1050 {
		t.Fatalf("expected size=1050 after rebuild, got %d", size)
	}
}

// TestRebuildBucketStats_LegacyJSONRecords verifies the rebuild also counts
// records still stored in the legacy JSON envelope.
func TestRebuildBucketStats_LegacyJSONRecords(t *testing.T) {
	db := openBucketsTestDB(t)
	b := &Bucket{ID: uuid.New().String(), Name: "rebuild-legacy", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	// Write a legacy JSON record directly, bypassing the codec.
	legacy := &Object{
		BucketID:  b.ID,
		Key:       "legacy-key",
		ObjectID:  uuid.New().String(),
		SizeBytes: 512,
		State:     "active",
		CreatedAt: time.Now().UTC(),
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(objectsBucketName(b.ID)).Put([]byte(legacy.Key), raw)
	}); err != nil {
		t.Fatalf("write legacy record: %v", err)
	}

	if err := db.RebuildBucketStats(b.ID); err != nil {
		t.Fatalf("RebuildBucketStats: %v", err)
	}

	count, size, err := db.BucketStats(b.ID)
	if err != nil {
		t.Fatalf("BucketStats: %v", err)
	}
	if count != 1 || size != 512 {
		t.Fatalf("expected 1/512 after rebuild, got %d/%d", count, size)
	}
}

func TestBucketStats_NonexistentBucket(t *testing.T) {
	db := openBucketsTestDB(t)
	count, size, err := db.BucketStats("nonexistent-id")
	if err != nil {
		t.Fatalf("should not error on missing bucket: %v", err)
	}
	if count != 0 || size != 0 {
		t.Fatalf("expected 0/0, got %d/%d", count, size)
	}
}
