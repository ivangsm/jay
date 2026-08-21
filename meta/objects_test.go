package meta

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"
	"uuid"
)

func openObjectsTestDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestGetBucketAndObject_HappyPath(t *testing.T) {
	db := openObjectsTestDB(t)
	bkt := &Bucket{ID: uuid.New().String(), Name: "bk", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	obj := &Object{
		BucketID:  bkt.ID,
		Key:       "hello.txt",
		ObjectID:  uuid.New().String(),
		SizeBytes: 11,
		State:     "active",
	}
	if _, err := db.PutObjectMeta(obj); err != nil {
		t.Fatalf("put object: %v", err)
	}

	gotBucket, gotObj, err := db.GetBucketAndObject("bk", "hello.txt")
	if err != nil {
		t.Fatalf("GetBucketAndObject: %v", err)
	}
	if gotBucket == nil || gotBucket.ID != bkt.ID || gotBucket.Name != "bk" {
		t.Fatalf("unexpected bucket: %+v", gotBucket)
	}
	if gotObj == nil || gotObj.Key != "hello.txt" || gotObj.SizeBytes != 11 {
		t.Fatalf("unexpected object: %+v", gotObj)
	}
	if gotObj.State != "active" {
		t.Fatalf("want state=active, got %q", gotObj.State)
	}
}

func TestGetBucketAndObject_BucketMissing(t *testing.T) {
	db := openObjectsTestDB(t)
	_, _, err := db.GetBucketAndObject("ghost", "x")
	if !errors.Is(err, ErrBucketNotFound) {
		t.Fatalf("want ErrBucketNotFound, got %v", err)
	}
}

func TestGetBucketAndObject_ObjectMissing(t *testing.T) {
	db := openObjectsTestDB(t)
	bkt := &Bucket{ID: uuid.New().String(), Name: "bk", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	gotBucket, gotObj, err := db.GetBucketAndObject("bk", "missing.txt")
	if !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("want ErrObjectNotFound, got %v", err)
	}
	if gotObj != nil {
		t.Fatalf("want nil object, got %+v", gotObj)
	}
	if gotBucket == nil || gotBucket.ID != bkt.ID {
		t.Fatalf("want bucket returned alongside ErrObjectNotFound, got %+v", gotBucket)
	}
}

func TestGetBucketAndObject_ObjectQuarantined(t *testing.T) {
	db := openObjectsTestDB(t)
	bkt := &Bucket{ID: uuid.New().String(), Name: "bk", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	obj := &Object{
		BucketID:  bkt.ID,
		Key:       "q.bin",
		ObjectID:  uuid.New().String(),
		SizeBytes: 42,
		State:     "active",
	}
	if _, err := db.PutObjectMeta(obj); err != nil {
		t.Fatalf("put object: %v", err)
	}
	if err := db.QuarantineObject(bkt.ID, "q.bin"); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	gotBucket, gotObj, err := db.GetBucketAndObject("bk", "q.bin")
	if !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("want ErrObjectNotFound, got %v", err)
	}
	if gotObj != nil {
		t.Fatalf("want nil object for quarantined record, got %+v", gotObj)
	}
	if gotBucket == nil || gotBucket.ID != bkt.ID {
		t.Fatalf("want bucket returned alongside ErrObjectNotFound, got %+v", gotBucket)
	}
}

// seedListObjectsBucket inserts `n` active objects with zero-padded numeric
// suffixes under `prefix`. Keys sort lexicographically.
func seedListObjectsBucket(t *testing.T, db *DB, bucketID, prefix string, n int) []string {
	t.Helper()
	keys := make([]string, 0, n)
	for i := range n {
		key := fmt.Sprintf("%s%06d", prefix, i)
		keys = append(keys, key)
		obj := &Object{
			BucketID:  bucketID,
			Key:       key,
			ObjectID:  uuid.New().String(),
			SizeBytes: int64(i),
			State:     "active",
		}
		if _, err := db.PutObjectMeta(obj); err != nil {
			t.Fatalf("put object %q: %v", key, err)
		}
	}
	return keys
}

func TestListObjectsPaginatedSemantics_TruncationAndResume(t *testing.T) {
	db := openObjectsTestDB(t)
	bkt := &Bucket{ID: uuid.New().String(), Name: "page", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	const total = 275
	keys := seedListObjectsBucket(t, db, bkt.ID, "k/", total)

	// Page 1: maxKeys=100, expect truncation at the 100th active object.
	page1, err := db.ListObjects(bkt.ID, "", "", "", 100)
	if err != nil {
		t.Fatalf("page1 ListObjects: %v", err)
	}
	if !page1.IsTruncated {
		t.Fatalf("page1: want IsTruncated=true, got false")
	}
	if len(page1.Objects) != 100 {
		t.Fatalf("page1: want 100 objects, got %d", len(page1.Objects))
	}
	if page1.NextStartAfter != keys[99] {
		t.Fatalf("page1: want NextStartAfter=%q, got %q", keys[99], page1.NextStartAfter)
	}
	for i, o := range page1.Objects {
		if o.Key != keys[i] {
			t.Fatalf("page1[%d]: want key %q, got %q", i, keys[i], o.Key)
		}
	}

	// Page 2: resume from NextStartAfter, expect the next 100, disjoint.
	page2, err := db.ListObjects(bkt.ID, "", "", page1.NextStartAfter, 100)
	if err != nil {
		t.Fatalf("page2 ListObjects: %v", err)
	}
	if !page2.IsTruncated {
		t.Fatalf("page2: want IsTruncated=true, got false")
	}
	if len(page2.Objects) != 100 {
		t.Fatalf("page2: want 100 objects, got %d", len(page2.Objects))
	}
	if page2.NextStartAfter != keys[199] {
		t.Fatalf("page2: want NextStartAfter=%q, got %q", keys[199], page2.NextStartAfter)
	}
	for i, o := range page2.Objects {
		if o.Key != keys[100+i] {
			t.Fatalf("page2[%d]: want key %q, got %q", i, keys[100+i], o.Key)
		}
	}

	// Disjointness check.
	seen := make(map[string]bool, 200)
	for _, o := range page1.Objects {
		seen[o.Key] = true
	}
	for _, o := range page2.Objects {
		if seen[o.Key] {
			t.Fatalf("page2 reintroduced key %q from page1", o.Key)
		}
	}

	// Page 3: 75 remaining, not truncated.
	page3, err := db.ListObjects(bkt.ID, "", "", page2.NextStartAfter, 100)
	if err != nil {
		t.Fatalf("page3 ListObjects: %v", err)
	}
	if page3.IsTruncated {
		t.Fatalf("page3: want IsTruncated=false, got true")
	}
	if len(page3.Objects) != total-200 {
		t.Fatalf("page3: want %d objects, got %d", total-200, len(page3.Objects))
	}
	if page3.NextStartAfter != keys[total-1] {
		t.Fatalf("page3: want NextStartAfter=%q, got %q", keys[total-1], page3.NextStartAfter)
	}
}

func TestListObjectsPaginatedSemantics_DelimiterCommonPrefixes(t *testing.T) {
	db := openObjectsTestDB(t)
	bkt := &Bucket{ID: uuid.New().String(), Name: "dlm", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	// Keys: a/1, a/2, b/1, top. With prefix="" and delimiter="/", the expected
	// result is CommonPrefixes=[a/, b/] and Objects=[top].
	inputs := []string{"a/1", "a/2", "b/1", "top"}
	for _, k := range inputs {
		obj := &Object{
			BucketID:  bkt.ID,
			Key:       k,
			ObjectID:  uuid.New().String(),
			SizeBytes: 1,
			State:     "active",
		}
		if _, err := db.PutObjectMeta(obj); err != nil {
			t.Fatalf("put %q: %v", k, err)
		}
	}

	res, err := db.ListObjects(bkt.ID, "", "/", "", 1000)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if res.IsTruncated {
		t.Fatalf("want IsTruncated=false, got true")
	}
	wantPrefixes := []string{"a/", "b/"}
	if len(res.CommonPrefixes) != len(wantPrefixes) {
		t.Fatalf("common prefixes: want %v, got %v", wantPrefixes, res.CommonPrefixes)
	}
	for i, cp := range res.CommonPrefixes {
		if cp != wantPrefixes[i] {
			t.Fatalf("common prefixes[%d]: want %q, got %q", i, wantPrefixes[i], cp)
		}
	}
	if len(res.Objects) != 1 || res.Objects[0].Key != "top" {
		t.Fatalf("objects: want [top], got %+v", res.Objects)
	}

	// With prefix="a/" and delimiter="/", expect both a/1 and a/2 as flat
	// objects (no further delimiter appears in the rest).
	res, err = db.ListObjects(bkt.ID, "a/", "/", "", 1000)
	if err != nil {
		t.Fatalf("ListObjects(a/): %v", err)
	}
	if res.IsTruncated {
		t.Fatalf("a/: want IsTruncated=false, got true")
	}
	if len(res.CommonPrefixes) != 0 {
		t.Fatalf("a/: want no common prefixes, got %v", res.CommonPrefixes)
	}
	if len(res.Objects) != 2 {
		t.Fatalf("a/: want 2 objects, got %d", len(res.Objects))
	}
	if res.Objects[0].Key != "a/1" || res.Objects[1].Key != "a/2" {
		t.Fatalf("a/: unexpected objects: %+v", res.Objects)
	}
}

func TestListObjectsPaginatedSemantics_EmptyBucket(t *testing.T) {
	db := openObjectsTestDB(t)
	bkt := &Bucket{ID: uuid.New().String(), Name: "empty", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	res, err := db.ListObjects(bkt.ID, "", "", "", 100)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if res.IsTruncated {
		t.Fatalf("want IsTruncated=false")
	}
	if len(res.Objects) != 0 {
		t.Fatalf("want 0 objects, got %d", len(res.Objects))
	}
	if res.NextStartAfter != "" {
		t.Fatalf("want empty NextStartAfter, got %q", res.NextStartAfter)
	}
}

func TestListObjectsPaginatedSemantics_BatchBoundaryTruncation(t *testing.T) {
	// Regression guard: the refactor reads in batches of 100. Ensure that when
	// the request asks for exactly a batch-aligned number of keys and more
	// exist, IsTruncated is correctly set (requires cross-batch lookahead).
	db := openObjectsTestDB(t)
	bkt := &Bucket{ID: uuid.New().String(), Name: "batch", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	keys := seedListObjectsBucket(t, db, bkt.ID, "x/", 101)

	res, err := db.ListObjects(bkt.ID, "", "", "", 100)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if !res.IsTruncated {
		t.Fatalf("want IsTruncated=true when max+1 keys exist, got false")
	}
	if len(res.Objects) != 100 {
		t.Fatalf("want 100 objects, got %d", len(res.Objects))
	}
	if res.NextStartAfter != keys[99] {
		t.Fatalf("want NextStartAfter=%q, got %q", keys[99], res.NextStartAfter)
	}

	// Same scenario but bucket has exactly 100 — must NOT be truncated.
	bkt2 := &Bucket{ID: uuid.New().String(), Name: "batch2", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(bkt2); err != nil {
		t.Fatalf("create bucket2: %v", err)
	}
	seedListObjectsBucket(t, db, bkt2.ID, "x/", 100)
	res2, err := db.ListObjects(bkt2.ID, "", "", "", 100)
	if err != nil {
		t.Fatalf("ListObjects (exact): %v", err)
	}
	if res2.IsTruncated {
		t.Fatalf("exact-100: want IsTruncated=false, got true")
	}
	if len(res2.Objects) != 100 {
		t.Fatalf("exact-100: want 100 objects, got %d", len(res2.Objects))
	}
}

func TestListObjectsPaginatedSemantics_PrefixNoMatches(t *testing.T) {
	db := openObjectsTestDB(t)
	bkt := &Bucket{ID: uuid.New().String(), Name: "pfx", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	seedListObjectsBucket(t, db, bkt.ID, "foo/", 10)

	res, err := db.ListObjects(bkt.ID, "bar/", "", "", 100)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if res.IsTruncated {
		t.Fatalf("want IsTruncated=false")
	}
	if len(res.Objects) != 0 {
		t.Fatalf("want 0 objects, got %d", len(res.Objects))
	}
}

// putActiveObjects inserts the given keys as active objects.
func putActiveObjects(t *testing.T, db *DB, bucketID string, keys ...string) {
	t.Helper()
	for _, k := range keys {
		obj := &Object{
			BucketID:  bucketID,
			Key:       k,
			ObjectID:  uuid.New().String(),
			SizeBytes: 1,
			State:     "active",
		}
		if _, err := db.PutObjectMeta(obj); err != nil {
			t.Fatalf("put %q: %v", k, err)
		}
	}
}

// drainList pages through ListObjects following NextStartAfter, returning the
// concatenated objects and common prefixes. Fails the test if pagination does
// not terminate (i.e. the continuation token stops making progress).
func drainList(t *testing.T, db *DB, bucketID, prefix, delimiter string, maxKeys int) (objects, prefixes []string) {
	t.Helper()
	startAfter := ""
	for page := 0; ; page++ {
		if page > 50 {
			t.Fatalf("pagination did not terminate after 50 pages (startAfter=%q)", startAfter)
		}
		res, err := db.ListObjects(bucketID, prefix, delimiter, startAfter, maxKeys)
		if err != nil {
			t.Fatalf("ListObjects page %d: %v", page, err)
		}
		for _, o := range res.Objects {
			objects = append(objects, o.Key)
		}
		prefixes = append(prefixes, res.CommonPrefixes...)
		if !res.IsTruncated {
			return objects, prefixes
		}
		if res.NextStartAfter == "" || res.NextStartAfter == startAfter {
			t.Fatalf("page %d: truncated but NextStartAfter=%q does not advance past %q",
				page, res.NextStartAfter, startAfter)
		}
		startAfter = res.NextStartAfter
	}
}

func assertNoDuplicates(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: want %v, got %v", label, want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: want %v, got %v", label, want, got)
		}
	}
}

func TestListObjects_DelimiterPagination_NoDuplicateCommonPrefixes(t *testing.T) {
	db := openObjectsTestDB(t)
	bkt := &Bucket{ID: uuid.New().String(), Name: "cpp", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	putActiveObjects(t, db, bkt.ID, "a/1", "a/2", "b/1", "b/2", "c/1")

	objects, prefixes := drainList(t, db, bkt.ID, "", "/", 2)
	if len(objects) != 0 {
		t.Fatalf("want no top-level objects, got %v", objects)
	}
	assertNoDuplicates(t, "common prefixes", prefixes, []string{"a/", "b/", "c/"})
}

func TestListObjects_DelimiterPagination_MixedRootObjectsAndPrefixes(t *testing.T) {
	db := openObjectsTestDB(t)
	bkt := &Bucket{ID: uuid.New().String(), Name: "mix", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	// Sorted order: a/1, a/2, b.txt, c/1, c/2, d.txt, e/1
	putActiveObjects(t, db, bkt.ID, "a/1", "a/2", "b.txt", "c/1", "c/2", "d.txt", "e/1")

	for _, maxKeys := range []int{1, 2, 3} {
		objects, prefixes := drainList(t, db, bkt.ID, "", "/", maxKeys)
		assertNoDuplicates(t, "objects (maxKeys="+strconv.Itoa(maxKeys)+")", objects,
			[]string{"b.txt", "d.txt"})
		assertNoDuplicates(t, "common prefixes (maxKeys="+strconv.Itoa(maxKeys)+")", prefixes,
			[]string{"a/", "c/", "e/"})
	}
}

func TestListObjects_DelimiterPagination_TrailingCommonPrefixTruncates(t *testing.T) {
	db := openObjectsTestDB(t)
	bkt := &Bucket{ID: uuid.New().String(), Name: "trail", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	putActiveObjects(t, db, bkt.ID, "a/1", "a/2", "b/1")

	// maxKeys=1 → page 1 emits only common prefix "a/". NextStartAfter must point
	// past the last key rolled up into "a/" (i.e. "a/2"), never to "" or "a/1".
	page1, err := db.ListObjects(bkt.ID, "", "/", "", 1)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if !page1.IsTruncated {
		t.Fatalf("page1: want IsTruncated=true")
	}
	if len(page1.CommonPrefixes) != 1 || page1.CommonPrefixes[0] != "a/" {
		t.Fatalf("page1: want [a/], got %v", page1.CommonPrefixes)
	}
	if page1.NextStartAfter != "a/2" {
		t.Fatalf("page1: want NextStartAfter=%q, got %q", "a/2", page1.NextStartAfter)
	}

	page2, err := db.ListObjects(bkt.ID, "", "/", page1.NextStartAfter, 1)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if page2.IsTruncated {
		t.Fatalf("page2: want IsTruncated=false")
	}
	if len(page2.CommonPrefixes) != 1 || page2.CommonPrefixes[0] != "b/" {
		t.Fatalf("page2: want [b/], got %v", page2.CommonPrefixes)
	}
}

func TestListObjects_NoDelimiterPagination_Unchanged(t *testing.T) {
	// Regression guard: without a delimiter, NextStartAfter must still be the key
	// of the last object returned, and pages must remain disjoint.
	db := openObjectsTestDB(t)
	bkt := &Bucket{ID: uuid.New().String(), Name: "flat", Visibility: "private", Status: "active"}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	keys := seedListObjectsBucket(t, db, bkt.ID, "k/", 7)

	res, err := db.ListObjects(bkt.ID, "", "", "", 3)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if !res.IsTruncated || res.NextStartAfter != keys[2] {
		t.Fatalf("want truncated with NextStartAfter=%q, got truncated=%v next=%q",
			keys[2], res.IsTruncated, res.NextStartAfter)
	}

	objects, prefixes := drainList(t, db, bkt.ID, "", "", 3)
	if len(prefixes) != 0 {
		t.Fatalf("want no common prefixes, got %v", prefixes)
	}
	assertNoDuplicates(t, "objects", objects, keys)
}
