package meta

// The quarantine-only writes. Their whole point is that the state check and
// the write are one bbolt transaction, so these tests look at what can and
// cannot happen in between, not only at the happy path.

import (
	"errors"
	"testing"
	"time"
	"uuid"
)

// seedQuarantineObject creates a bucket holding one object of size bytes and
// returns it, quarantined when quarantine is true.
func seedQuarantineObject(t *testing.T, db *DB, size int64, quarantine bool) *Object {
	t.Helper()
	b := &Bucket{ID: uuid.New().String(), Name: "q-" + uuid.New().String()[:8]}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	obj := &Object{
		BucketID: b.ID, Key: "k", ObjectID: uuid.New().String(), State: "active",
		SizeBytes: size, LocationRef: "buckets/" + b.ID + "/objects/x",
	}
	if _, err := db.PutObjectMeta(obj); err != nil {
		t.Fatalf("put object: %v", err)
	}
	if quarantine {
		if err := db.QuarantineObject(b.ID, "k"); err != nil {
			t.Fatalf("quarantine: %v", err)
		}
	}
	got, err := db.GetObjectMetaAny(b.ID, "k")
	if err != nil {
		t.Fatalf("get object: %v", err)
	}
	return got
}

func TestDeleteQuarantinedObject_RefusesWhatIsNotQuarantined(t *testing.T) {
	db := openExtraTestDB(t)
	active := seedQuarantineObject(t, db, 5, false)

	called := false
	removeFile := func(*Object) error { called = true; return nil }

	if _, err := db.DeleteQuarantinedObject(active.BucketID, "k", removeFile); !errors.Is(err, ErrObjectNotQuarantined) {
		t.Fatalf("active object: err = %v, want ErrObjectNotQuarantined", err)
	}
	if called {
		t.Fatal("the file of an active object was handed to removeFile")
	}
	if got, err := db.GetObjectMetaAny(active.BucketID, "k"); err != nil || got.State != "active" {
		t.Fatalf("the active record after a refused purge: %+v, %v", got, err)
	}

	if _, err := db.DeleteQuarantinedObject(active.BucketID, "missing", removeFile); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("missing key: err = %v, want ErrObjectNotFound", err)
	}
	if _, err := db.DeleteQuarantinedObject("no-such-bucket", "k", removeFile); !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("missing bucket: err = %v, want ErrBucketNotFound", err)
	}
	if called {
		t.Fatal("removeFile ran for an object that does not exist")
	}
}

func TestDeleteQuarantinedObject_DeletesFileThenRecord(t *testing.T) {
	db := openExtraTestDB(t)
	obj := seedQuarantineObject(t, db, 5, true)

	var removed string
	deleted, err := db.DeleteQuarantinedObject(obj.BucketID, "k", func(o *Object) error {
		removed = o.LocationRef
		return nil
	})
	if err != nil {
		t.Fatalf("DeleteQuarantinedObject: %v", err)
	}
	if removed != obj.LocationRef || deleted.ObjectID != obj.ObjectID {
		t.Fatalf("removed %q (object %s), want %q (object %s)", removed, deleted.ObjectID, obj.LocationRef, obj.ObjectID)
	}
	if _, err := db.GetObjectMetaAny(obj.BucketID, "k"); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("the record survived: %v", err)
	}
}

// A file that cannot be removed leaves the record exactly as it was — still
// quarantined, still listed, purgeable again — rather than a record deleted
// over bytes that are still on disk.
func TestDeleteQuarantinedObject_AFileErrorKeepsTheRecord(t *testing.T) {
	db := openExtraTestDB(t)
	obj := seedQuarantineObject(t, db, 5, true)
	boom := errors.New("device busy")

	if _, err := db.DeleteQuarantinedObject(obj.BucketID, "k", func(*Object) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want it to wrap the removal error", err)
	}
	got, err := db.GetObjectMetaAny(obj.BucketID, "k")
	if err != nil || got.State != "quarantined" {
		t.Fatalf("the record after a failed removal: %+v, %v", got, err)
	}
}

// The check and the delete are one write transaction: nothing can restore (or
// overwrite) the record while the file is being removed. A restore started in
// the middle has to wait for the purge, and then finds nothing to restore.
func TestDeleteQuarantinedObject_NothingInterleavesWithTheCheck(t *testing.T) {
	db := openExtraTestDB(t)
	obj := seedQuarantineObject(t, db, 5, true)

	restored := make(chan error, 1)
	_, err := db.DeleteQuarantinedObject(obj.BucketID, "k", func(*Object) error {
		go func() { restored <- db.RestoreObject(obj.BucketID, "k") }()
		select {
		case err := <-restored:
			t.Errorf("a restore completed between the state check and the delete (err %v)", err)
		case <-time.After(50 * time.Millisecond):
		}
		return nil
	})
	if err != nil {
		t.Fatalf("DeleteQuarantinedObject: %v", err)
	}
	if err := <-restored; !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("the restore that waited: err = %v, want ErrObjectNotFound", err)
	}
}

// A revalidation hashes the file outside any transaction, so by the time it
// restores, the record may be a different object. Only the one it verified,
// still quarantined, is restored.
func TestRestoreQuarantinedObject_OnlyTheObjectThatWasVerified(t *testing.T) {
	db := openExtraTestDB(t)
	obj := seedQuarantineObject(t, db, 7, true)

	if err := db.RestoreQuarantinedObject(obj.BucketID, "k", "another-object-id"); !errors.Is(err, ErrObjectNotQuarantined) {
		t.Fatalf("a different object id: err = %v, want ErrObjectNotQuarantined", err)
	}
	if got, _ := db.GetObjectMetaAny(obj.BucketID, "k"); got.State != "quarantined" {
		t.Fatalf("restored on another object's checksum: state %q", got.State)
	}
	if count, size, err := db.BucketStats(obj.BucketID); err != nil || count != 0 || size != 0 {
		t.Fatalf("stats after a refused restore: %d objects, %d bytes, %v", count, size, err)
	}

	if err := db.RestoreQuarantinedObject(obj.BucketID, "k", obj.ObjectID); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, _ := db.GetObjectMetaAny(obj.BucketID, "k"); got.State != "active" {
		t.Fatalf("state after restore = %q", got.State)
	}
	if count, size, err := db.BucketStats(obj.BucketID); err != nil || count != 1 || size != 7 {
		t.Fatalf("stats after restore: %d objects, %d bytes, %v; want 1 and 7", count, size, err)
	}

	// Restoring again: it is active now, not quarantined, and the stats do not
	// count it twice.
	if err := db.RestoreQuarantinedObject(obj.BucketID, "k", obj.ObjectID); !errors.Is(err, ErrObjectNotQuarantined) {
		t.Fatalf("second restore: err = %v, want ErrObjectNotQuarantined", err)
	}
	if count, _, _ := db.BucketStats(obj.BucketID); count != 1 {
		t.Fatalf("a second restore counted the object again: %d", count)
	}
	if err := db.RestoreQuarantinedObject(obj.BucketID, "missing", obj.ObjectID); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("missing key: err = %v", err)
	}
}

func TestValidAction(t *testing.T) {
	for _, a := range append([]string{"*"}, AllActions...) {
		if !ValidAction(a) {
			t.Errorf("ValidAction(%q) = false", a)
		}
	}
	for _, a := range []string{"", "object:read", "object:*", "Object:Get", " object:get", "**"} {
		if ValidAction(a) {
			t.Errorf("ValidAction(%q) = true", a)
		}
	}
}
