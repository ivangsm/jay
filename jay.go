// Package jay is the embeddable form of the jay object store: the same engine
// the server runs — bbolt metadata, atomic writes, SHA-256 per object, startup
// recovery, scrubbing, GC — opened in-process by a Go program, with no
// listener, no token and no serialization.
//
//	s, err := jay.Open("/var/lib/myapp/objects")
//	if err != nil { ... }
//	defer s.Close()
//
//	ctx := context.Background()
//	_ = s.CreateBucket(ctx, "photos")
//	obj, err := s.Put(ctx, "photos", "2026/cat.jpg", file, &jay.PutOptions{ContentType: "image/jpeg"})
//	info, body, err := s.Get(ctx, "photos", "2026/cat.jpg")
//	defer body.Close()
//
// The server (cmd/jay) and this package share internal/objops; a bug fixed in
// one is fixed in the other. What the library does NOT have is everything a
// listener needs: accounts, tokens, bucket policies, rate limits. Buckets it
// creates have no owner, and every call is authorized by virtue of being made
// from inside the process. A data directory written by the library is a valid
// one for the server and vice versa.
package jay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
	"uuid"

	"github.com/ivangsm/jay/internal/objops"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/recovery"
	"github.com/ivangsm/jay/store"
)

// Sentinel errors. Match them with errors.Is.
var (
	ErrBucketNotFound = objops.ErrBucketNotFound
	ErrObjectNotFound = objops.ErrObjectNotFound
	ErrBucketExists   = meta.ErrBucketExists
	ErrBucketNotEmpty = meta.ErrBucketNotEmpty
	ErrInvalidRange   = objops.ErrInvalidRange
	ErrObjectTooLarge = objops.ErrObjectTooLarge
	ErrClosed         = errors.New("jay: store is closed")
)

// Defaults for what Open starts on its own.
const (
	DefaultGCInterval = 15 * time.Minute

	// The scrubber is off unless WithScrub asks for it; these are the values
	// it takes when it does, the same the server uses.
	DefaultScrubInterval    = 6 * time.Hour
	DefaultScrubBytesPerSec = int64(50 << 20)
	DefaultScrubMaxPerRun   = 100
)

// Option configures Open.
type Option func(*config)

type config struct {
	log           *slog.Logger
	maxObjectSize int64
	gcInterval    time.Duration // <= 0: GC off
	scrub         *ScrubOptions
	snapshotDir   string
	snapshotEvery time.Duration
	snapshotKeep  time.Duration
}

// ScrubOptions tune the background integrity scrubber (see WithScrub). Zero
// fields take the Default* values.
type ScrubOptions struct {
	// Interval is how often a scrub pass starts.
	Interval time.Duration
	// BytesPerSec caps the read rate of a pass so it does not compete with
	// the application for the disk.
	BytesPerSec int64
	// MaxPerRun bounds how many objects one pass verifies.
	MaxPerRun int
}

// WithLogger sets the logger. Nothing is logged by default; recovery, the GC
// and the scrubber all report through it, and an application that embeds jay
// wants those lines in its own log.
func WithLogger(log *slog.Logger) Option {
	return func(c *config) {
		if log != nil {
			c.log = log
		}
	}
}

// WithMaxObjectSize refuses any Put larger than n bytes with ErrObjectTooLarge,
// before the bytes are committed. Zero (the default) means no limit.
func WithMaxObjectSize(n int64) Option {
	return func(c *config) { c.maxObjectSize = n }
}

// WithGCInterval sets how often the garbage collector reclaims the parts of
// abandoned multipart uploads and deleted objects' files. It runs every
// DefaultGCInterval unless told otherwise; a non-positive value turns it off,
// which an application that opens the store for one short operation may
// prefer.
func WithGCInterval(d time.Duration) Option {
	return func(c *config) { c.gcInterval = d }
}

// WithScrub turns on the background integrity scrubber: it re-hashes stored
// objects at the configured pace and quarantines any whose bytes no longer
// match their SHA-256. Off by default because it is sustained disk reads,
// which is a decision for the application, not the library.
func WithScrub(opts ScrubOptions) Option {
	return func(c *config) {
		o := opts
		if o.Interval <= 0 {
			o.Interval = DefaultScrubInterval
		}
		if o.BytesPerSec <= 0 {
			o.BytesPerSec = DefaultScrubBytesPerSec
		}
		if o.MaxPerRun <= 0 {
			o.MaxPerRun = DefaultScrubMaxPerRun
		}
		c.scrub = &o
	}
}

// WithMetadataSnapshots takes a verified snapshot of the metadata database
// into dir every interval, keeping them for retention (at least three are
// always kept). It covers the bbolt file ONLY — object bytes are not backed
// up by jay, in the library any more than in the server. Off by default.
func WithMetadataSnapshots(dir string, every, retention time.Duration) Option {
	return func(c *config) {
		c.snapshotDir = dir
		c.snapshotEvery = every
		c.snapshotKeep = retention
	}
}

// Store is an open jay data directory. It is safe for concurrent use. Close it
// when done: the background loops stop before the database closes, in the
// same order the server shuts down.
type Store struct {
	db      *meta.DB
	st      *store.Store
	ops     *objops.Service
	log     *slog.Logger
	metrics *maintenance.Metrics

	mu     sync.Mutex
	closed bool
	stops  []func() // in the order they must run at Close
}

// Open opens (creating if needed) the data directory, runs startup recovery —
// which reconciles metadata against the files on disk and quarantines, never
// deletes, whatever disagrees — and starts the background loops the options
// ask for. It returns only when the store is consistent and ready to serve.
//
// Two processes must not open the same directory: bbolt takes an exclusive
// lock on its file, so the second Open fails rather than corrupting the first.
func Open(dataDir string, opts ...Option) (*Store, error) {
	cfg := config{
		log:        slog.New(slog.DiscardHandler),
		gcInterval: DefaultGCInterval,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	if dataDir == "" {
		return nil, errors.New("jay: data directory is required")
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("jay: create data dir: %w", err)
	}

	db, err := meta.Open(filepath.Join(dataDir, "meta", "jay.db"))
	if err != nil {
		return nil, fmt.Errorf("jay: open metadata: %w", err)
	}

	st, err := store.New(dataDir)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("jay: open store: %w", err)
	}

	s := &Store{
		db:      db,
		st:      st,
		log:     cfg.log,
		metrics: maintenance.NewMetrics(),
	}
	db.SetDecodeFailureHook(func(string, string) { s.metrics.RecordMetadataDecodeFailure() })
	st.SetFsyncErrorHook(func(error) { s.metrics.RecordFsyncFailure() })

	if err := recovery.RunWithMetrics(db, st, cfg.log, s.metrics); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("jay: recovery: %w", err)
	}

	s.ops = objops.New(db, st, cfg.log)
	s.ops.SetMaxObjectSize(cfg.maxObjectSize)

	s.startMaintenance(dataDir, cfg)
	return s, nil
}

// startMaintenance mirrors cmd/jay: GC, scrubber and snapshots, each with its
// stop function recorded in the order Close must call them. The snapshot loop
// is stopped first — a snapshot in flight when bbolt closes underneath it is a
// corrupt backup that still satisfies retention.
func (s *Store) startMaintenance(dataDir string, cfg config) {
	if cfg.snapshotDir != "" && cfg.snapshotEvery > 0 {
		bm := maintenance.NewBackupManager(s.db, cfg.snapshotDir, dataDir, s.log)
		done := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			ticker := time.NewTicker(cfg.snapshotEvery)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					if _, err := bm.Run(); err != nil {
						s.log.Error("jay: metadata snapshot failed", "err", err)
					}
					if cfg.snapshotKeep > 0 {
						if _, err := bm.Prune(cfg.snapshotKeep, 3); err != nil {
							s.log.Error("jay: metadata snapshot prune failed", "err", err)
						}
					}
				}
			}
		})
		s.stops = append(s.stops, func() { close(done); wg.Wait() })
	}

	if cfg.gcInterval > 0 {
		gc := maintenance.NewGC(dataDir, s.db, s.st, s.log, cfg.gcInterval)
		s.db.SetDeletionHook(gc.NotifyDeletion)
		gc.Start()
		s.stops = append(s.stops, gc.Stop)
	}

	if cfg.scrub != nil {
		sc := maintenance.NewScrubber(s.db, s.st, s.log, cfg.scrub.Interval, cfg.scrub.BytesPerSec, cfg.scrub.MaxPerRun)
		sc.SetMetrics(s.metrics)
		sc.Start()
		s.stops = append(s.stops, sc.Stop)
	}
}

// Close stops the background loops, in order, and closes the database. It is
// safe to call more than once; every operation after it returns ErrClosed.
func (s *Store) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	for _, stop := range s.stops {
		stop()
	}
	return s.db.Close()
}

func (s *Store) check(ctx context.Context) error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrClosed
	}
	return ctx.Err()
}

// identity is what every operation runs as: no token, no account. objops
// skips token and cross-account checks for a nil token and still applies a
// bucket's deny policy, which a library user could only have installed by
// writing it into the database themselves.
func identity(action string) objops.Identity {
	return objops.Identity{Action: action}
}

// --- Buckets ---

// Bucket describes a bucket.
type Bucket struct {
	Name      string
	CreatedAt time.Time
}

// CreateBucket creates a bucket. ErrBucketExists if the name is taken.
// Names follow the S3 rules (3-63 chars, lowercase letters, digits, dots and
// hyphens, no leading or trailing separator).
func (s *Store) CreateBucket(ctx context.Context, name string) error {
	if err := s.check(ctx); err != nil {
		return err
	}
	if !meta.ValidBucketName(name) {
		return fmt.Errorf("jay: invalid bucket name %q", name)
	}
	b := &meta.Bucket{
		ID:         uuid.New().String(),
		Name:       name,
		Visibility: meta.VisibilityPrivate,
		Status:     "active",
	}
	if err := s.db.CreateBucket(b); err != nil {
		return err
	}
	if err := s.st.EnsureBucketDir(b.ID); err != nil {
		s.log.Error("jay: ensure bucket dir", "err", err, "bucket", name)
	}
	return nil
}

// DeleteBucket deletes an empty bucket. ErrBucketNotEmpty otherwise.
func (s *Store) DeleteBucket(ctx context.Context, name string) error {
	if err := s.check(ctx); err != nil {
		return err
	}
	b, err := s.db.GetBucket(name)
	if err != nil {
		return mapBucketErr(err)
	}
	if err := s.db.DeleteBucket(name); err != nil {
		return mapBucketErr(err)
	}
	if err := s.st.RemoveBucketDir(b.ID); err != nil {
		s.log.Error("jay: remove bucket dir", "err", err, "bucket", name)
	}
	return nil
}

// ListBuckets returns every bucket, in name order.
func (s *Store) ListBuckets(ctx context.Context) ([]Bucket, error) {
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.ListBuckets("")
	if err != nil {
		return nil, err
	}
	out := make([]Bucket, len(rows))
	for i, b := range rows {
		out[i] = Bucket{Name: b.Name, CreatedAt: b.CreatedAt}
	}
	return out, nil
}

func mapBucketErr(err error) error {
	if errors.Is(err, meta.ErrBucketNotFound) {
		return ErrBucketNotFound
	}
	return err
}

// --- Objects ---

// Object describes a stored object.
type Object struct {
	Key            string
	Size           int64
	ContentType    string
	ETag           string // MD5 of the bytes, hex
	ChecksumSHA256 string // SHA-256 of the bytes, hex — what the scrubber verifies
	LastModified   time.Time
	Metadata       map[string]string
}

func fromMeta(o *meta.Object) *Object {
	return &Object{
		Key:            o.Key,
		Size:           o.SizeBytes,
		ContentType:    o.ContentType,
		ETag:           o.ETag,
		ChecksumSHA256: o.ChecksumSHA256,
		LastModified:   o.UpdatedAt,
		Metadata:       o.MetadataHeaders,
	}
}

// PutOptions are the optional parts of a Put.
type PutOptions struct {
	// ContentType is stored with the object; "application/octet-stream" when
	// empty.
	ContentType string
	// Metadata is free-form key/value stored with the object and returned by
	// Head, Get and List.
	Metadata map[string]string
}

// Put stores the bytes read from r as bucket/key, replacing any object with
// that key. The bytes go to a temporary file, are fsynced, and only then
// renamed into place and committed to metadata: a crash in the middle leaves
// the previous version, not a torn one.
//
// Cancelling ctx while r is being read aborts the write and leaves nothing
// behind.
func (s *Store) Put(ctx context.Context, bucket, key string, r io.Reader, opts *PutOptions) (*Object, error) {
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	if key == "" {
		return nil, errors.New("jay: object key is required")
	}
	var contentType string
	var metadata map[string]string
	if opts != nil {
		contentType = opts.ContentType
		metadata = opts.Metadata
	}
	if r == nil {
		// A nil reader is an empty object, not a nil dereference.
		r = bytesEmpty{}
	}
	obj, err := s.ops.PutObject(ctx, nil, bucket, key, contentType, &ctxReader{ctx: ctx, r: r},
		objops.PutOptions{UserMetadata: metadata}, identity(meta.ActionObjectPut))
	if err != nil {
		return nil, wrapCtx(ctx, err)
	}
	return fromMeta(obj), nil
}

// Get opens an object for reading. The caller must Close the body. Cancelling
// ctx fails the next Read.
func (s *Store) Get(ctx context.Context, bucket, key string) (*Object, io.ReadCloser, error) {
	if err := s.check(ctx); err != nil {
		return nil, nil, err
	}
	obj, err := s.ops.HeadObject(ctx, nil, bucket, key, identity(meta.ActionObjectGet))
	if err != nil {
		return nil, nil, err
	}
	f, err := s.ops.OpenObjectFile(obj)
	if err != nil {
		return nil, nil, fmt.Errorf("jay: open object: %w", err)
	}
	return fromMeta(obj), &ctxReadCloser{ctxReader: ctxReader{ctx: ctx, r: f}, c: f}, nil
}

// GetRange opens length bytes of an object starting at offset; length <= 0
// means "to the end", and a length past the end is clamped. A range that does
// not intersect the object is ErrInvalidRange. The returned Object describes
// the whole object; the body yields only the slice.
func (s *Store) GetRange(ctx context.Context, bucket, key string, offset, length int64) (*Object, io.ReadCloser, error) {
	if err := s.check(ctx); err != nil {
		return nil, nil, err
	}
	obj, err := s.ops.HeadObject(ctx, nil, bucket, key, identity(meta.ActionObjectGet))
	if err != nil {
		return nil, nil, err
	}
	start, n, err := objops.ResolveRange(offset, length, obj.SizeBytes)
	if err != nil {
		return nil, nil, err
	}
	f, err := s.ops.OpenObjectRange(obj, start)
	if err != nil {
		return nil, nil, fmt.Errorf("jay: open object: %w", err)
	}
	return fromMeta(obj), &ctxReadCloser{ctxReader: ctxReader{ctx: ctx, r: io.LimitReader(f, n)}, c: f}, nil
}

// Head returns an object's description without opening it.
func (s *Store) Head(ctx context.Context, bucket, key string) (*Object, error) {
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	obj, err := s.ops.HeadObject(ctx, nil, bucket, key, identity(meta.ActionObjectGet))
	if err != nil {
		return nil, err
	}
	return fromMeta(obj), nil
}

// Delete removes an object. Deleting one that does not exist is not an error;
// a missing bucket is.
func (s *Store) Delete(ctx context.Context, bucket, key string) error {
	if err := s.check(ctx); err != nil {
		return err
	}
	return s.ops.DeleteObject(ctx, nil, bucket, key, identity(meta.ActionObjectDelete))
}

// Copy writes srcBucket/srcKey's bytes as a new object at dstBucket/dstKey,
// carrying content type and metadata over, without the bytes leaving the
// store. errors.Is(err, ErrObjectNotFound) is the missing source; a missing
// bucket on either side is ErrBucketNotFound.
func (s *Store) Copy(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) (*Object, error) {
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	if dstKey == "" {
		return nil, errors.New("jay: destination key is required")
	}
	obj, err := s.ops.CopyObject(ctx, nil, srcBucket, srcKey, dstBucket, dstKey, objops.CopyOptions{}, identity(meta.ActionObjectPut))
	if err != nil {
		return nil, err
	}
	return fromMeta(obj), nil
}

// ListOptions narrow a List.
type ListOptions struct {
	// Prefix keeps only keys that start with it.
	Prefix string
	// Delimiter groups keys by the segment after Prefix, S3-style: with "/"
	// the keys "a/b" and "a/c" collapse into the common prefix "a/".
	Delimiter string
	// StartAfter resumes a listing after this key.
	StartAfter string
	// MaxKeys caps the page; 1000 when zero, 10000 at most.
	MaxKeys int
}

// ListResult is one page of a listing.
type ListResult struct {
	Objects        []Object
	CommonPrefixes []string
	// IsTruncated means there is another page; pass NextStartAfter as
	// StartAfter to get it.
	IsTruncated    bool
	NextStartAfter string
}

// List returns one page of the objects in a bucket, in key order.
func (s *Store) List(ctx context.Context, bucket string, opts ListOptions) (*ListResult, error) {
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	b, err := s.db.GetBucket(bucket)
	if err != nil {
		return nil, mapBucketErr(err)
	}
	maxKeys := opts.MaxKeys
	if maxKeys <= 0 {
		maxKeys = 1000
	}
	if maxKeys > 10000 {
		maxKeys = 10000
	}
	res, err := s.db.ListObjects(b.ID, opts.Prefix, opts.Delimiter, opts.StartAfter, maxKeys)
	if err != nil {
		return nil, err
	}
	out := &ListResult{
		Objects:        make([]Object, len(res.Objects)),
		CommonPrefixes: res.CommonPrefixes,
		IsTruncated:    res.IsTruncated,
		NextStartAfter: res.NextStartAfter,
	}
	for i := range res.Objects {
		out.Objects[i] = *fromMeta(&res.Objects[i])
	}
	return out, nil
}

// --- Context-aware readers ---

type bytesEmpty struct{}

func (bytesEmpty) Read([]byte) (int, error) { return 0, io.EOF }

// ctxReader fails a Read once ctx is done. objops streams without looking at
// the context, so this is where a cancelled Put stops reading its source and
// a cancelled Get stops handing out bytes.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

type ctxReadCloser struct {
	ctxReader
	c io.Closer
}

func (c *ctxReadCloser) Close() error { return c.c.Close() }

// wrapCtx reports the context's error when it is what stopped the operation:
// the store sees a read failure, the caller sees why.
func wrapCtx(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
