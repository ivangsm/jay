// Package objops implements the transport-agnostic object operations
// (Put/Get/Head/Delete) shared by the HTTP S3 handler and the native proto
// handler. It is the single place where:
//
//   - token-level authorization is applied (via auth.Authorize)
//   - bucket-policy deny overlays are evaluated (via auth.EvaluatePolicyDeny)
//   - metadata is written / read / deleted against meta.DB
//   - bytes are streamed to/from the physical store
//
// Both transports must route through this package. Do not duplicate these
// rules in the handlers.
package objops

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

// Exported errors so handlers can map them to transport-specific status codes.
var (
	// ErrBucketNotFound: the named bucket does not exist.
	ErrBucketNotFound = errors.New("objops: bucket not found")
	// ErrObjectNotFound: the named object does not exist in the bucket.
	ErrObjectNotFound = errors.New("objops: object not found")
	// ErrPolicyDenied: bucket-policy evaluator returned a deny match. This is
	// distinct from a token-level authorization failure (see ErrAccessDenied).
	ErrPolicyDenied = errors.New("objops: access denied by bucket policy")
	// ErrAccessDenied: token-level authorization failed.
	ErrAccessDenied = errors.New("objops: access denied")
	// ErrBadPolicy: the bucket policy JSON could not be unmarshalled. Treated
	// as deny (fail-closed) — never as allow.
	ErrBadPolicy = errors.New("objops: malformed bucket policy")
)

// Identity carries the authenticated caller context needed for policy
// evaluation. TokenID may be empty for anonymous reads on public-read buckets
// (the handler will not build an Identity in that case unless asked to).
type Identity struct {
	TokenID   string
	AccountID string
	SourceIP  string
	// Action is the meta.Action* constant for the operation (e.g.
	// meta.ActionObjectGet). This is what the bucket policy evaluator matches
	// against — the actions field of policy statements uses the same strings.
	Action string
}

// Service is the transport-agnostic object-operations service.
type Service struct {
	db    *meta.DB
	store *store.Store
	log   *slog.Logger
}

// New constructs a Service. db, st, and log must all be non-nil.
func New(db *meta.DB, st *store.Store, log *slog.Logger) *Service {
	return &Service{db: db, store: st, log: log}
}

// md5Pool is shared between PUT paths so every transport can compute ETag
// without allocating a fresh hasher per request.
var md5Pool = sync.Pool{
	New: func() any { return md5.New() },
}

// authorize runs token authorization + bucket-policy deny evaluation. Returns
// ErrAccessDenied or ErrPolicyDenied on failure. ErrBadPolicy is folded into
// ErrPolicyDenied (fail-closed) — callers don't need a separate code path.
//
// If token is nil the bucket must allow public anonymous read for the action;
// the HTTP handler pre-filters these cases and will not call objops for
// anonymous writes/deletes. If a nil token reaches a write/delete path here,
// authorize returns ErrAccessDenied.
func (s *Service) authorize(
	bucket *meta.Bucket,
	identity Identity,
	token *meta.Token,
	objectKey string,
) error {
	if token != nil {
		if err := checkTokenAction(token, identity.Action, bucket.Name, objectKey); err != nil {
			return err
		}
	}

	if len(bucket.PolicyJSON) == 0 {
		return nil
	}

	var policy auth.BucketPolicy
	if err := json.Unmarshal(bucket.PolicyJSON, &policy); err != nil {
		s.log.Warn("malformed bucket policy — failing closed",
			"bucket", bucket.Name, "err", err)
		return ErrPolicyDenied
	}
	policy.Compile()

	if auth.EvaluatePolicyDeny(&policy, identity.TokenID, identity.Action, objectKey, identity.SourceIP) {
		return ErrPolicyDenied
	}
	return nil
}

// checkTokenAction mirrors auth.Authorize but returns objops.ErrAccessDenied so
// callers can uniformly compare. We don't call auth.AuthorizeWithPolicy here
// because this function needs to run before policy evaluation to preserve
// deny-overlay semantics regardless.
func checkTokenAction(token *meta.Token, action, bucketName, objectKey string) error {
	if !containsStr(token.AllowedActions, action) && !containsStr(token.AllowedActions, "*") {
		return ErrAccessDenied
	}
	if len(token.BucketScope) > 0 && !containsStr(token.BucketScope, bucketName) {
		return ErrAccessDenied
	}
	if len(token.PrefixScope) > 0 && objectKey != "" {
		matched := false
		for _, p := range token.PrefixScope {
			if hasPrefix(objectKey, p) {
				matched = true
				break
			}
		}
		if !matched {
			return ErrAccessDenied
		}
	}
	return nil
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

// resolveBucket loads the bucket by name, mapping not-found → ErrBucketNotFound.
func (s *Service) resolveBucket(name string) (*meta.Bucket, error) {
	bucket, err := s.db.GetBucket(name)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return nil, ErrBucketNotFound
		}
		return nil, err
	}
	return bucket, nil
}

// lookupBucketAndObject loads the bucket and an active object in a single
// bbolt view transaction, mapping meta errors to the objops-level sentinels.
// On ErrObjectNotFound the returned bucket is non-nil when the bucket itself
// does exist; this lets callers authorize an idempotent delete without a
// second view transaction.
func (s *Service) lookupBucketAndObject(bucketName, key string) (*meta.Bucket, *meta.Object, error) {
	bucket, obj, err := s.db.GetBucketAndObject(bucketName, key)
	if err != nil {
		switch {
		case errors.Is(err, meta.ErrBucketNotFound):
			return nil, nil, ErrBucketNotFound
		case errors.Is(err, meta.ErrObjectNotFound):
			return bucket, nil, ErrObjectNotFound
		default:
			return nil, nil, err
		}
	}
	return bucket, obj, nil
}

// PutOptions carry per-request metadata that doesn't fit in the required args.
type PutOptions struct {
	// UserMetadata holds x-amz-meta-* headers (HTTP) or a decoded metadata map
	// (native proto). Keys should already be lower-cased and sanitized.
	UserMetadata map[string]string
}

// PutResult is returned by PutObject so both transports can produce the same
// response shape (ETag / checksum / size).
type PutResult struct {
	Object *meta.Object
}

// PutObject writes body to the store, commits metadata, and returns the new
// object. On overwrite the previous version's physical file is GC'd. On
// metadata commit failure the freshly-written file is cleaned up.
//
// The caller is responsible for setting Content-Length / Content-Type headers
// on HTTP responses — PutObject only fills *meta.Object and returns it.
func (s *Service) PutObject(
	_ context.Context,
	token *meta.Token,
	bucketName, key, contentType string,
	body io.Reader,
	opts PutOptions,
	identity Identity,
) (*meta.Object, error) {
	bucket, err := s.resolveBucket(bucketName)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(bucket, identity, token, key); err != nil {
		return nil, err
	}

	objectID := uuid.New().String()

	md5Hash := md5Pool.Get().(hash.Hash)
	md5Hash.Reset()
	defer md5Pool.Put(md5Hash)

	var teeBody io.Reader = body
	if body != nil {
		teeBody = io.TeeReader(body, md5Hash)
	} else {
		teeBody = emptyReader{}
	}

	checksum, size, locationRef, err := s.store.WriteObject(bucket.ID, objectID, teeBody)
	if err != nil {
		s.log.Error("objops: write object", "err", err, "bucket", bucketName, "key", key)
		return nil, err
	}

	etag := hex.EncodeToString(md5Hash.Sum(nil))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	obj := &meta.Object{
		BucketID:        bucket.ID,
		Key:             key,
		ObjectID:        objectID,
		State:           "active",
		SizeBytes:       size,
		ContentType:     contentType,
		ETag:            etag,
		ChecksumSHA256:  checksum,
		LocationRef:     locationRef,
		CreatedAt:       time.Now().UTC(),
		MetadataHeaders: opts.UserMetadata,
	}

	prev, err := s.db.PutObjectMeta(obj)
	if err != nil {
		// Metadata commit failed — don't leave an orphaned physical file.
		s.store.Cleanup(locationRef)
		s.log.Error("objops: put object meta", "err", err, "bucket", bucketName, "key", key)
		return nil, err
	}

	// GC the previous version's physical file (if this overwrite replaced one).
	if prev != nil && prev.LocationRef != locationRef {
		if err := s.store.DeleteObject(prev.LocationRef); err != nil {
			s.log.Warn("objops: gc previous object", "err", err, "location", prev.LocationRef)
		}
	}

	return obj, nil
}

// GetObject resolves metadata + opens the stored file and streams it to w via
// io.Copy. On Linux, when w is a *net.TCPConn or an io.ReaderFrom that wraps
// one (e.g. api.statusWriter), the kernel's sendfile(2) takes over and the
// bytes never touch userspace. For that reason we do NOT re-hash on read here
// — the scrubber owns integrity verification (maintenance/scrub.go).
//
// The object is returned so callers can set transport-specific response
// headers (ETag, Content-Length, Content-Type, Last-Modified, x-amz-meta-*).
//
// If w is nil, GetObject returns the Object without streaming bytes — this is
// HEAD semantics. Callers should prefer HeadObject for clarity.
func (s *Service) GetObject(
	_ context.Context,
	token *meta.Token,
	bucketName, key string,
	w io.Writer,
	identity Identity,
) (*meta.Object, error) {
	bucket, obj, err := s.lookupBucketAndObject(bucketName, key)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(bucket, identity, token, key); err != nil {
		return nil, err
	}

	if w == nil {
		return obj, nil
	}

	f, err := s.store.ReadObject(obj.LocationRef)
	if err != nil {
		s.log.Error("objops: read object", "err", err, "location", obj.LocationRef)
		return obj, err
	}
	defer func() { _ = f.Close() }()

	// io.Copy lets sendfile(2) kick in: (*os.File).WriteTo → (*net.TCPConn).ReadFrom.
	// Also works with api.statusWriter which forwards ReadFrom.
	if _, err := io.Copy(w, f); err != nil {
		// Log but return obj+err so caller can decide whether headers have
		// been flushed already.
		s.log.Warn("objops: stream object", "err", err, "bucket", bucketName, "key", key)
		return obj, err
	}
	return obj, nil
}

// OpenObjectFile opens the physical file at obj.LocationRef for direct
// transport use. The HTTP handler needs Seek for Range support; the proto
// handler needs a reader for its frame writer. Caller must Close the file.
//
// This is the one place outside GetObject where the store is opened by
// location_ref — it skips the auth check (the caller already has an
// authorized *meta.Object in hand). Do NOT export this to callers that
// received the Object from an untrusted source.
func (s *Service) OpenObjectFile(obj *meta.Object) (*os.File, error) {
	return s.store.ReadObject(obj.LocationRef)
}

// HeadObject returns object metadata only — no body stream.
func (s *Service) HeadObject(
	_ context.Context,
	token *meta.Token,
	bucketName, key string,
	identity Identity,
) (*meta.Object, error) {
	bucket, obj, err := s.lookupBucketAndObject(bucketName, key)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(bucket, identity, token, key); err != nil {
		return nil, err
	}
	return obj, nil
}

// DeleteObject marks the object deleted in metadata and GCs its physical file.
// Returns nil if the object did not exist (S3 semantics: DELETE is idempotent).
func (s *Service) DeleteObject(
	_ context.Context,
	token *meta.Token,
	bucketName, key string,
	identity Identity,
) error {
	bucket, _, err := s.lookupBucketAndObject(bucketName, key)
	if err != nil && !errors.Is(err, ErrObjectNotFound) {
		return err
	}
	if err := s.authorize(bucket, identity, token, key); err != nil {
		return err
	}
	if errors.Is(err, ErrObjectNotFound) {
		// S3 semantics: deleting a non-existent object is not an error.
		return nil
	}

	obj, err := s.db.DeleteObjectMeta(bucket.ID, key)
	if err != nil {
		if errors.Is(err, meta.ErrObjectNotFound) {
			return nil
		}
		return err
	}
	if err := s.store.DeleteObject(obj.LocationRef); err != nil {
		s.log.Warn("objops: gc deleted object", "err", err, "location", obj.LocationRef)
	}
	return nil
}

// emptyReader returns EOF on the first Read. Used when a PUT carries no body
// (zero-byte object) to keep the store.WriteObject signature uniform.
type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }
