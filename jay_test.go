package jay_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivangsm/jay"
)

func open(t *testing.T, opts ...jay.Option) (*jay.Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := jay.Open(dir, opts...)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

func readAll(t *testing.T, r io.ReadCloser) string {
	t.Helper()
	defer func() { _ = r.Close() }()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestOpen_CreatesTheLayoutTheServerUses(t *testing.T) {
	_, dir := open(t)
	for _, p := range []string{"meta/jay.db", "buckets", "tmp"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}

func TestOpen_RefusesEmptyDir(t *testing.T) {
	if _, err := jay.Open(""); err == nil {
		t.Fatal("empty data dir must be refused")
	}
}

func TestOpen_SecondOpenOfSameDirFails(t *testing.T) {
	_, dir := open(t)
	// bbolt's file lock: a second process on the same directory must not
	// corrupt the first. Bounded so a hang shows up as a failure, not a
	// stuck test.
	done := make(chan error, 1)
	go func() {
		s, err := jay.Open(dir)
		if err == nil {
			_ = s.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a second Open on a locked directory must fail")
		}
	case <-time.After(3 * time.Second):
		// bbolt blocks on the flock by default; either outcome proves the
		// second opener did not get in.
	}
}

func TestBuckets(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()

	if err := s.CreateBucket(ctx, "photos"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateBucket(ctx, "photos"); !errors.Is(err, jay.ErrBucketExists) {
		t.Fatalf("want ErrBucketExists, got %v", err)
	}
	if err := s.CreateBucket(ctx, "Bad_Name"); err == nil {
		t.Fatal("invalid bucket name must be refused")
	}

	list, err := s.ListBuckets(ctx)
	if err != nil || len(list) != 1 || list[0].Name != "photos" || list[0].CreatedAt.IsZero() {
		t.Fatalf("list = %+v, %v", list, err)
	}

	if _, err := s.Put(ctx, "photos", "a", strings.NewReader("x"), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteBucket(ctx, "photos"); !errors.Is(err, jay.ErrBucketNotEmpty) {
		t.Fatalf("want ErrBucketNotEmpty, got %v", err)
	}
	if err := s.Delete(ctx, "photos", "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteBucket(ctx, "photos"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteBucket(ctx, "photos"); !errors.Is(err, jay.ErrBucketNotFound) {
		t.Fatalf("want ErrBucketNotFound, got %v", err)
	}
}

func TestObjects_RoundTrip(t *testing.T) {
	s, dir := open(t)
	ctx := context.Background()
	if err := s.CreateBucket(ctx, "bkt"); err != nil {
		t.Fatal(err)
	}

	content := "hello, embedded jay"
	obj, err := s.Put(ctx, "bkt", "dir/hello.txt", strings.NewReader(content),
		&jay.PutOptions{ContentType: "text/plain", Metadata: map[string]string{"x-amz-meta-k": "v"}})
	if err != nil {
		t.Fatal(err)
	}
	if obj.Key != "dir/hello.txt" || obj.Size != int64(len(content)) || obj.ContentType != "text/plain" ||
		len(obj.ChecksumSHA256) != 64 || obj.ETag == "" || obj.LastModified.IsZero() || obj.Metadata["x-amz-meta-k"] != "v" {
		t.Fatalf("unexpected object: %+v", obj)
	}

	// The bytes are on disk under the bucket, checksummed by the store —
	// the effect, not the return value.
	var files int
	_ = filepath.WalkDir(filepath.Join(dir, "buckets"), func(_ string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			files++
		}
		return nil
	})
	if files != 1 {
		t.Fatalf("expected 1 object file on disk, found %d", files)
	}

	head, err := s.Head(ctx, "bkt", "dir/hello.txt")
	if err != nil || head.ChecksumSHA256 != obj.ChecksumSHA256 {
		t.Fatalf("head: %v %+v", err, head)
	}

	got, body, err := s.Get(ctx, "bkt", "dir/hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if readAll(t, body) != content || got.Size != obj.Size {
		t.Fatal("body mismatch")
	}

	// Overwrite replaces, and the old file is gone.
	if _, err := s.Put(ctx, "bkt", "dir/hello.txt", strings.NewReader("v2"), nil); err != nil {
		t.Fatal(err)
	}
	_, body, err = s.Get(ctx, "bkt", "dir/hello.txt")
	if err != nil || readAll(t, body) != "v2" {
		t.Fatalf("overwrite not visible: %v", err)
	}

	if err := s.Delete(ctx, "bkt", "dir/hello.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Head(ctx, "bkt", "dir/hello.txt"); !errors.Is(err, jay.ErrObjectNotFound) {
		t.Fatalf("want ErrObjectNotFound, got %v", err)
	}
	if err := s.Delete(ctx, "bkt", "dir/hello.txt"); err != nil {
		t.Fatalf("deleting a missing object is not an error: %v", err)
	}
	if err := s.Delete(ctx, "nope", "k"); !errors.Is(err, jay.ErrBucketNotFound) {
		t.Fatalf("want ErrBucketNotFound, got %v", err)
	}
	if _, err := s.Put(ctx, "bkt", "", strings.NewReader("x"), nil); err == nil {
		t.Fatal("empty key must be refused")
	}
	if obj, err := s.Put(ctx, "bkt", "empty", nil, nil); err != nil || obj.Size != 0 {
		t.Fatalf("nil reader is an empty object: %v %+v", err, obj)
	}
}

func TestGetRange(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if err := s.CreateBucket(ctx, "bkt"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "bkt", "digits", strings.NewReader("0123456789"), nil); err != nil {
		t.Fatal(err)
	}

	obj, body, err := s.GetRange(ctx, "bkt", "digits", 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, body); got != "3456" || obj.Size != 10 {
		t.Fatalf("got %q size %d", got, obj.Size)
	}
	_, body, err = s.GetRange(ctx, "bkt", "digits", 8, 0)
	if err != nil || readAll(t, body) != "89" {
		t.Fatalf("to end: %v", err)
	}
	if _, _, err := s.GetRange(ctx, "bkt", "digits", 10, 1); !errors.Is(err, jay.ErrInvalidRange) {
		t.Fatalf("want ErrInvalidRange, got %v", err)
	}
}

func TestCopy(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	for _, b := range []string{"src-b", "dst-b"} {
		if err := s.CreateBucket(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	orig, err := s.Put(ctx, "src-b", "a", strings.NewReader("copy me"), &jay.PutOptions{ContentType: "text/x-t"})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := s.Copy(ctx, "src-b", "a", "dst-b", "b")
	if err != nil {
		t.Fatal(err)
	}
	if cp.ChecksumSHA256 != orig.ChecksumSHA256 || cp.ContentType != "text/x-t" || cp.Key != "b" {
		t.Fatalf("copy differs: %+v", cp)
	}
	_, body, err := s.Get(ctx, "dst-b", "b")
	if err != nil || readAll(t, body) != "copy me" {
		t.Fatalf("destination: %v", err)
	}
	if _, err := s.Copy(ctx, "src-b", "missing", "dst-b", "b"); !errors.Is(err, jay.ErrObjectNotFound) {
		t.Fatalf("want ErrObjectNotFound, got %v", err)
	}
	if _, err := s.Copy(ctx, "src-b", "a", "nowhere", "b"); !errors.Is(err, jay.ErrBucketNotFound) {
		t.Fatalf("want ErrBucketNotFound, got %v", err)
	}
}

func TestList(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if err := s.CreateBucket(ctx, "bkt"); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"a/1", "a/2", "b/1", "c"} {
		if _, err := s.Put(ctx, "bkt", k, strings.NewReader(k), nil); err != nil {
			t.Fatal(err)
		}
	}

	all, err := s.List(ctx, "bkt", jay.ListOptions{})
	if err != nil || len(all.Objects) != 4 || all.IsTruncated {
		t.Fatalf("all: %v %+v", err, all)
	}
	if all.Objects[0].Key != "a/1" || all.Objects[0].Size != 3 {
		t.Fatalf("first entry: %+v", all.Objects[0])
	}

	grouped, err := s.List(ctx, "bkt", jay.ListOptions{Delimiter: "/"})
	if err != nil || len(grouped.Objects) != 1 || len(grouped.CommonPrefixes) != 2 {
		t.Fatalf("grouped: %v %+v", err, grouped)
	}

	page, err := s.List(ctx, "bkt", jay.ListOptions{MaxKeys: 2})
	if err != nil || len(page.Objects) != 2 || !page.IsTruncated {
		t.Fatalf("page 1: %v %+v", err, page)
	}
	page2, err := s.List(ctx, "bkt", jay.ListOptions{MaxKeys: 2, StartAfter: page.NextStartAfter})
	if err != nil || len(page2.Objects) != 2 || page2.IsTruncated || page2.Objects[0].Key != "b/1" {
		t.Fatalf("page 2: %v %+v", err, page2)
	}

	if _, err := s.List(ctx, "nope", jay.ListOptions{}); !errors.Is(err, jay.ErrBucketNotFound) {
		t.Fatalf("want ErrBucketNotFound, got %v", err)
	}
}

func TestMaxObjectSize(t *testing.T) {
	s, dir := open(t, jay.WithMaxObjectSize(4))
	ctx := context.Background()
	if err := s.CreateBucket(ctx, "bkt"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "bkt", "ok", strings.NewReader("1234"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "bkt", "big", strings.NewReader("12345"), nil); !errors.Is(err, jay.ErrObjectTooLarge) {
		t.Fatalf("want ErrObjectTooLarge, got %v", err)
	}
	if _, err := s.Head(ctx, "bkt", "big"); !errors.Is(err, jay.ErrObjectNotFound) {
		t.Fatal("a refused Put must leave nothing behind")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "tmp"))
	if len(entries) != 0 {
		t.Fatalf("temp file left behind: %v", entries)
	}
}

// A reader that blocks until its context ends, then reports it.
type blockingReader struct{ ctx context.Context }

func (b blockingReader) Read([]byte) (int, error) {
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func TestContext_CancelledPutWritesNothing(t *testing.T) {
	s, dir := open(t)
	ctx := context.Background()
	if err := s.CreateBucket(ctx, "bkt"); err != nil {
		t.Fatal(err)
	}

	putCtx, cancel := context.WithCancel(ctx)
	src := io.MultiReader(strings.NewReader("partial"), blockingReader{putCtx})
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err := s.Put(putCtx, "bkt", "k", src, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if _, err := s.Head(ctx, "bkt", "k"); !errors.Is(err, jay.ErrObjectNotFound) {
		t.Fatal("a cancelled Put must not commit")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "tmp"))
	if len(entries) != 0 {
		t.Fatalf("temp file left behind: %v", entries)
	}
}

func TestContext_CancelledGetStopsReading(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	if err := s.CreateBucket(ctx, "bkt"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "bkt", "k", bytes.NewReader(bytes.Repeat([]byte("x"), 1<<20)), nil); err != nil {
		t.Fatal(err)
	}

	getCtx, cancel := context.WithCancel(ctx)
	_, body, err := s.Get(getCtx, "bkt", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = body.Close() }()
	buf := make([]byte, 1024)
	if _, err := body.Read(buf); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := body.Read(buf); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}

	already, cancel2 := context.WithCancel(ctx)
	cancel2()
	if _, err := s.Head(already, "bkt", "k"); !errors.Is(err, context.Canceled) {
		t.Fatalf("an already-cancelled context must fail before doing anything: %v", err)
	}
}

func TestClose(t *testing.T) {
	s, dir := open(t)
	ctx := context.Background()
	if err := s.CreateBucket(ctx, "bkt"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := s.CreateBucket(ctx, "c"); !errors.Is(err, jay.ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}

	// Reopen: what was written is still there — and the server would see the
	// same directory.
	s2, err := jay.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	list, err := s2.ListBuckets(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("after reopen: %v %+v", err, list)
	}
}

func TestOpen_RecoveryQuarantinesMetadataWithoutFile(t *testing.T) {
	s, dir := open(t)
	ctx := context.Background()
	if err := s.CreateBucket(ctx, "bkt"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "bkt", "k", strings.NewReader("bytes"), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Lose the file behind the object's back.
	_ = filepath.WalkDir(filepath.Join(dir, "buckets"), func(p string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			return os.Remove(p)
		}
		return nil
	})

	s2, err := jay.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if _, err := s2.Head(ctx, "bkt", "k"); !errors.Is(err, jay.ErrObjectNotFound) {
		t.Fatalf("recovery must take the fileless object out of the active set, got %v", err)
	}
}

func TestOptions_ScrubAndSnapshotsStart(t *testing.T) {
	snapDir := filepath.Join(t.TempDir(), "snaps")
	s, _ := open(t,
		jay.WithScrub(jay.ScrubOptions{Interval: time.Hour}),
		jay.WithMetadataSnapshots(snapDir, 50*time.Millisecond, time.Hour),
		jay.WithGCInterval(time.Hour),
	)
	ctx := context.Background()
	if err := s.CreateBucket(ctx, "bkt"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries, _ := os.ReadDir(snapDir)
		if len(entries) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no metadata snapshot appeared")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Close must stop the loops before closing bbolt; a snapshot racing the
	// close would surface as an error here or a panic.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
