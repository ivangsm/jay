package meta

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
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
