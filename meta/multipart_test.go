package meta

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

func openMultipartTestDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetSigningSecret("test-signing-secret-at-least-32-chars!!")
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestCreateMultipartUpload_PersistsAndRetrievable(t *testing.T) {
	db := openMultipartTestDB(t)
	upload := &MultipartUpload{
		UploadID:    uuid.New().String(),
		BucketID:    uuid.New().String(),
		ObjectKey:   "photos/sunset.jpg",
		ContentType: "image/jpeg",
		InitiatedBy: "token-abc",
	}
	if err := db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	got, err := db.GetMultipartUpload(upload.UploadID)
	if err != nil {
		t.Fatalf("GetMultipartUpload: %v", err)
	}
	if got.UploadID != upload.UploadID {
		t.Fatalf("upload id mismatch: want %s, got %s", upload.UploadID, got.UploadID)
	}
	if got.BucketID != upload.BucketID {
		t.Fatalf("bucket id mismatch: want %s, got %s", upload.BucketID, got.BucketID)
	}
	if got.ObjectKey != upload.ObjectKey {
		t.Fatalf("object key mismatch: want %s, got %s", upload.ObjectKey, got.ObjectKey)
	}
	if got.State != "initiated" {
		t.Fatalf("expected state=initiated, got %s", got.State)
	}
	if got.CreatedAt.IsZero() {
		t.Fatalf("expected CreatedAt to be set")
	}
}

func TestCreateMultipartUpload_DefaultsSetCorrectly(t *testing.T) {
	db := openMultipartTestDB(t)
	upload := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "file.bin",
	}
	if err := db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	if upload.State != "initiated" {
		t.Fatalf("want State=initiated, got %s", upload.State)
	}
	if upload.CreatedAt.IsZero() {
		t.Fatalf("want CreatedAt set, got zero")
	}
}

func TestCreateMultipartUpload_ExplicitCreatedAt(t *testing.T) {
	db := openMultipartTestDB(t)
	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	upload := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "file.bin",
		CreatedAt: ts,
		State:     "initiated",
	}
	if err := db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	got, err := db.GetMultipartUpload(upload.UploadID)
	if err != nil {
		t.Fatalf("GetMultipartUpload: %v", err)
	}
	if !got.CreatedAt.Equal(ts) {
		t.Fatalf("want CreatedAt=%v, got %v", ts, got.CreatedAt)
	}
}

func TestGetMultipartUpload_NotFound(t *testing.T) {
	db := openMultipartTestDB(t)
	_, err := db.GetMultipartUpload("nonexistent-upload-id")
	if !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("want ErrUploadNotFound, got %v", err)
	}
}

func TestGetMultipartUpload_NoBucketInitialised(t *testing.T) {
	db := openMultipartTestDB(t)
	_, err := db.GetMultipartUpload("some-id")
	if !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("want ErrUploadNotFound when multipart bucket absent, got %v", err)
	}
}

func TestAddMultipartPart_AppendsPart(t *testing.T) {
	db := openMultipartTestDB(t)
	upload := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "data.bin",
	}
	if err := db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("create: %v", err)
	}
	part := MultipartPart{PartNumber: 1, Size: 1024, ETag: "abc123"}
	if err := db.AddMultipartPart(upload.UploadID, part); err != nil {
		t.Fatalf("AddMultipartPart: %v", err)
	}
	got, err := db.GetMultipartUpload(upload.UploadID)
	if err != nil {
		t.Fatalf("GetMultipartUpload: %v", err)
	}
	if len(got.Parts) != 1 {
		t.Fatalf("want 1 part, got %d", len(got.Parts))
	}
	if got.Parts[0].PartNumber != 1 || got.Parts[0].Size != 1024 || got.Parts[0].ETag != "abc123" {
		t.Fatalf("unexpected part: %+v", got.Parts[0])
	}
}

func TestAddMultipartPart_ReplacesExistingPart(t *testing.T) {
	db := openMultipartTestDB(t)
	upload := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "data.bin",
	}
	if err := db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.AddMultipartPart(upload.UploadID, MultipartPart{PartNumber: 1, Size: 512, ETag: "first"}); err != nil {
		t.Fatalf("add first: %v", err)
	}
	if err := db.AddMultipartPart(upload.UploadID, MultipartPart{PartNumber: 1, Size: 2048, ETag: "second"}); err != nil {
		t.Fatalf("add second (replace): %v", err)
	}
	got, err := db.GetMultipartUpload(upload.UploadID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Parts) != 1 {
		t.Fatalf("want 1 part after replace, got %d", len(got.Parts))
	}
	if got.Parts[0].ETag != "second" || got.Parts[0].Size != 2048 {
		t.Fatalf("part not replaced: %+v", got.Parts[0])
	}
}

func TestAddMultipartPart_SortedByPartNumber(t *testing.T) {
	db := openMultipartTestDB(t)
	upload := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "data.bin",
	}
	if err := db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, pn := range []int{3, 1, 2} {
		if err := db.AddMultipartPart(upload.UploadID, MultipartPart{PartNumber: pn, Size: int64(pn * 100), ETag: "x"}); err != nil {
			t.Fatalf("add part %d: %v", pn, err)
		}
	}
	got, err := db.GetMultipartUpload(upload.UploadID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Parts) != 3 {
		t.Fatalf("want 3 parts, got %d", len(got.Parts))
	}
	for i, p := range got.Parts {
		if p.PartNumber != i+1 {
			t.Fatalf("parts not sorted: index %d has PartNumber %d", i, p.PartNumber)
		}
	}
}

func TestAddMultipartPart_InvalidPartNumber(t *testing.T) {
	db := openMultipartTestDB(t)
	upload := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "x",
	}
	if err := db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.AddMultipartPart(upload.UploadID, MultipartPart{PartNumber: 0}); !errors.Is(err, ErrInvalidPartNumber) {
		t.Fatalf("PartNumber=0: want ErrInvalidPartNumber, got %v", err)
	}
	if err := db.AddMultipartPart(upload.UploadID, MultipartPart{PartNumber: MaxMultipartParts + 1}); !errors.Is(err, ErrInvalidPartNumber) {
		t.Fatalf("PartNumber>max: want ErrInvalidPartNumber, got %v", err)
	}
}

func TestAddMultipartPart_UploadNotFound(t *testing.T) {
	db := openMultipartTestDB(t)
	_ = db.CreateMultipartUpload(&MultipartUpload{UploadID: "seed", BucketID: "b", ObjectKey: "k"})
	err := db.AddMultipartPart("nonexistent", MultipartPart{PartNumber: 1})
	if !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("want ErrUploadNotFound, got %v", err)
	}
}

func TestAddMultipartPart_UploadNotActive(t *testing.T) {
	db := openMultipartTestDB(t)
	upload := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "x",
	}
	if err := db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.AbortMultipartUpload(upload.UploadID); err != nil {
		t.Fatalf("abort: %v", err)
	}
	err := db.AddMultipartPart(upload.UploadID, MultipartPart{PartNumber: 1})
	if !errors.Is(err, ErrUploadNotActive) {
		t.Fatalf("want ErrUploadNotActive on aborted upload, got %v", err)
	}
}

func TestCompleteMultipartUpload_TransitionToCompleted(t *testing.T) {
	db := openMultipartTestDB(t)
	upload := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "archive.tar.gz",
	}
	if err := db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, pn := range []int{1, 2, 3} {
		if err := db.AddMultipartPart(upload.UploadID, MultipartPart{PartNumber: pn, Size: 500, ETag: "e"}); err != nil {
			t.Fatalf("add part %d: %v", pn, err)
		}
	}
	completed, err := db.CompleteMultipartUpload(upload.UploadID, []int{1, 2, 3})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	if completed.State != "completed" {
		t.Fatalf("want state=completed, got %s", completed.State)
	}
	if len(completed.Parts) != 3 {
		t.Fatalf("want 3 parts, got %d", len(completed.Parts))
	}

	got, err := db.GetMultipartUpload(upload.UploadID)
	if err != nil {
		t.Fatalf("get after complete: %v", err)
	}
	if got.State != "completed" {
		t.Fatalf("persisted state: want completed, got %s", got.State)
	}
}

func TestCompleteMultipartUpload_SubsetOfParts(t *testing.T) {
	db := openMultipartTestDB(t)
	upload := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "x",
	}
	if err := db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, pn := range []int{1, 2, 3} {
		_ = db.AddMultipartPart(upload.UploadID, MultipartPart{PartNumber: pn, Size: 100, ETag: "e"})
	}
	completed, err := db.CompleteMultipartUpload(upload.UploadID, []int{1, 3})
	if err != nil {
		t.Fatalf("complete with subset: %v", err)
	}
	if len(completed.Parts) != 2 {
		t.Fatalf("want 2 parts, got %d", len(completed.Parts))
	}
	if completed.Parts[0].PartNumber != 1 || completed.Parts[1].PartNumber != 3 {
		t.Fatalf("unexpected parts: %+v", completed.Parts)
	}
}

func TestCompleteMultipartUpload_NotFound(t *testing.T) {
	db := openMultipartTestDB(t)
	_ = db.CreateMultipartUpload(&MultipartUpload{UploadID: "seed", BucketID: "b", ObjectKey: "k"})
	_, err := db.CompleteMultipartUpload("nonexistent", []int{1})
	if !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("want ErrUploadNotFound, got %v", err)
	}
}

func TestCompleteMultipartUpload_NotActive(t *testing.T) {
	db := openMultipartTestDB(t)
	upload := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "x",
	}
	if err := db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := db.AbortMultipartUpload(upload.UploadID); err != nil {
		t.Fatalf("abort: %v", err)
	}
	_, err := db.CompleteMultipartUpload(upload.UploadID, []int{})
	if !errors.Is(err, ErrUploadNotActive) {
		t.Fatalf("want ErrUploadNotActive, got %v", err)
	}
}

func TestCompleteMultipartUpload_MissingPart(t *testing.T) {
	db := openMultipartTestDB(t)
	upload := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "x",
	}
	if err := db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = db.AddMultipartPart(upload.UploadID, MultipartPart{PartNumber: 1, Size: 100, ETag: "e"})
	_, err := db.CompleteMultipartUpload(upload.UploadID, []int{1, 99})
	if err == nil {
		t.Fatalf("expected error for missing part 99, got nil")
	}
}

func TestAbortMultipartUpload_TransitionToAborted(t *testing.T) {
	db := openMultipartTestDB(t)
	upload := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "x",
	}
	if err := db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("create: %v", err)
	}
	aborted, err := db.AbortMultipartUpload(upload.UploadID)
	if err != nil {
		t.Fatalf("AbortMultipartUpload: %v", err)
	}
	if aborted.State != "aborted" {
		t.Fatalf("want state=aborted, got %s", aborted.State)
	}
	got, err := db.GetMultipartUpload(upload.UploadID)
	if err != nil {
		t.Fatalf("get after abort: %v", err)
	}
	if got.State != "aborted" {
		t.Fatalf("persisted state: want aborted, got %s", got.State)
	}
}

func TestAbortMultipartUpload_NotFound(t *testing.T) {
	db := openMultipartTestDB(t)
	_ = db.CreateMultipartUpload(&MultipartUpload{UploadID: "seed", BucketID: "b", ObjectKey: "k"})
	_, err := db.AbortMultipartUpload("nonexistent")
	if !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("want ErrUploadNotFound, got %v", err)
	}
}

func TestListMultipartUploads_ReturnsInitiatedForBucket(t *testing.T) {
	db := openMultipartTestDB(t)
	bucketID := uuid.New().String()
	otherBucketID := uuid.New().String()

	ids := []string{uuid.New().String(), uuid.New().String(), uuid.New().String()}
	for _, id := range ids {
		if err := db.CreateMultipartUpload(&MultipartUpload{
			UploadID:  id,
			BucketID:  bucketID,
			ObjectKey: "obj-" + id,
		}); err != nil {
			t.Fatalf("create upload %s: %v", id, err)
		}
	}
	// one upload for a different bucket
	if err := db.CreateMultipartUpload(&MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  otherBucketID,
		ObjectKey: "other",
	}); err != nil {
		t.Fatalf("create other bucket upload: %v", err)
	}
	// complete one so it is excluded
	_ = db.AddMultipartPart(ids[0], MultipartPart{PartNumber: 1, Size: 1, ETag: "e"})
	if _, err := db.CompleteMultipartUpload(ids[0], []int{1}); err != nil {
		t.Fatalf("complete: %v", err)
	}

	uploads, err := db.ListMultipartUploads(bucketID)
	if err != nil {
		t.Fatalf("ListMultipartUploads: %v", err)
	}
	if len(uploads) != 2 {
		t.Fatalf("want 2 initiated uploads, got %d", len(uploads))
	}
	for _, u := range uploads {
		if u.BucketID != bucketID {
			t.Fatalf("wrong bucket in result: %s", u.BucketID)
		}
		if u.State != "initiated" {
			t.Fatalf("expected initiated, got %s", u.State)
		}
	}
}

func TestListMultipartUploads_EmptyWhenNoBucketBucket(t *testing.T) {
	db := openMultipartTestDB(t)
	uploads, err := db.ListMultipartUploads("some-bucket-id")
	if err != nil {
		t.Fatalf("ListMultipartUploads on fresh DB: %v", err)
	}
	if len(uploads) != 0 {
		t.Fatalf("want 0, got %d", len(uploads))
	}
}

func TestDeleteMultipartUpload_RemovesRecord(t *testing.T) {
	db := openMultipartTestDB(t)
	upload := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "x",
	}
	if err := db.CreateMultipartUpload(upload); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.DeleteMultipartUpload(upload.UploadID); err != nil {
		t.Fatalf("DeleteMultipartUpload: %v", err)
	}
	_, err := db.GetMultipartUpload(upload.UploadID)
	if !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("want ErrUploadNotFound after delete, got %v", err)
	}
}

func TestCleanupExpiredUploads_RemovesExpiredInitiated(t *testing.T) {
	db := openMultipartTestDB(t)
	old := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "old",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		State:     "initiated",
	}
	recent := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "recent",
		CreatedAt: time.Now(),
		State:     "initiated",
	}
	if err := db.CreateMultipartUpload(old); err != nil {
		t.Fatalf("create old: %v", err)
	}
	if err := db.CreateMultipartUpload(recent); err != nil {
		t.Fatalf("create recent: %v", err)
	}

	expired, err := db.CleanupExpiredUploads(time.Hour)
	if err != nil {
		t.Fatalf("CleanupExpiredUploads: %v", err)
	}
	if len(expired) != 1 {
		t.Fatalf("want 1 expired upload, got %d", len(expired))
	}
	if expired[0].UploadID != old.UploadID {
		t.Fatalf("wrong upload expired: %s", expired[0].UploadID)
	}
	_, err = db.GetMultipartUpload(old.UploadID)
	if !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("expired upload should be deleted, got %v", err)
	}
	_, err = db.GetMultipartUpload(recent.UploadID)
	if err != nil {
		t.Fatalf("recent upload should remain, got %v", err)
	}
}

func TestCleanupExpiredUploads_RemovesCompletedAndAborted(t *testing.T) {
	db := openMultipartTestDB(t)
	completed := &MultipartUpload{
		UploadID:  uuid.New().String(),
		BucketID:  uuid.New().String(),
		ObjectKey: "done",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		State:     "initiated",
	}
	if err := db.CreateMultipartUpload(completed); err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = db.AddMultipartPart(completed.UploadID, MultipartPart{PartNumber: 1, Size: 1, ETag: "e"})
	if _, err := db.CompleteMultipartUpload(completed.UploadID, []int{1}); err != nil {
		t.Fatalf("complete: %v", err)
	}

	_, err := db.CleanupExpiredUploads(time.Hour)
	if err != nil {
		t.Fatalf("CleanupExpiredUploads: %v", err)
	}
	_, err = db.GetMultipartUpload(completed.UploadID)
	if !errors.Is(err, ErrUploadNotFound) {
		t.Fatalf("completed old upload should be cleaned up, got %v", err)
	}
}
