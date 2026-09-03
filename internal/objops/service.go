// Package objops implements the transport-agnostic object operations
// (Put/Get/Head/Delete) shared by the HTTP S3 handler and the native proto
// handler. It is the single place where:
//
//   - token-level authorization is applied (via auth.Authorize)
//   - the cross-account gate is applied (via auth.AuthorizeBucketAccess)
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
	"errors"
	"hash"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

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
	// ErrObjectTooLarge: the request body exceeded the configured maximum
	// object size. The partially written file is removed before returning.
	ErrObjectTooLarge = errors.New("objops: object exceeds maximum allowed size")
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

	// maxObjectSize is the largest object body accepted by PutObject, in bytes.
	// 0 means unlimited. Stored atomically because it is set from main() during
	// wiring while handlers may already be constructed.
	maxObjectSize atomic.Int64
}

// New constructs a Service. db, st, and log must all be non-nil.
func New(db *meta.DB, st *store.Store, log *slog.Logger) *Service {
	return &Service{db: db, store: st, log: log}
}

// SetMaxObjectSize sets the maximum accepted object size in bytes. 0 (or a
// negative value, normalized to 0) disables the limit. Intended to be called
// once during wiring, before the listeners start serving.
func (s *Service) SetMaxObjectSize(n int64) {
	if n < 0 {
		n = 0
	}
	s.maxObjectSize.Store(n)
}

// MaxObjectSize returns the configured maximum object size in bytes (0 =
// unlimited). Transports that write bytes outside PutObject — e.g. the S3
// multipart part upload — read it to enforce the same ceiling per part.
func (s *Service) MaxObjectSize() int64 {
	return s.maxObjectSize.Load()
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
		// Cross-account gate. checkTokenAction above answers what the token is
		// scoped to; this answers whether its account may reach this bucket at
		// all. A token with "*" and no BucketScope passes the former for every
		// bucket in the store (PND-0185).
		//
		// Only for an authenticated caller: a nil token here is the anonymous
		// read of a public-read bucket, which the transport already gated.
		if err := auth.AuthorizeBucketAccess(token, bucket, identity.Action, objectKey, identity.SourceIP); err != nil {
			return ErrAccessDenied
		}
	}

	if len(bucket.PolicyJSON) == 0 {
		return nil
	}

	policy, err := auth.ParsePolicy(bucket.PolicyJSON)
	if err != nil {
		s.log.Warn("malformed bucket policy — failing closed",
			"bucket", bucket.Name, "err", err)
		return ErrPolicyDenied
	}

	// Deny is evaluated last, on purpose: it outranks ownership and any allow
	// statement that granted access above.
	if auth.EvaluatePolicyDeny(policy, identity.TokenID, identity.Action, objectKey, identity.SourceIP) {
		return ErrPolicyDenied
	}
	return nil
}

// checkTokenAction mirrors auth.Authorize but returns objops.ErrAccessDenied so
// callers can uniformly compare. We don't call auth.AuthorizeWithPolicy here
// because this function needs to run before policy evaluation to preserve
// deny-overlay semantics regardless.
func checkTokenAction(token *meta.Token, action, bucketName, objectKey string) error {
	if !slices.Contains(token.AllowedActions, action) && !slices.Contains(token.AllowedActions, "*") {
		return ErrAccessDenied
	}
	if len(token.BucketScope) > 0 && !slices.Contains(token.BucketScope, bucketName) {
		return ErrAccessDenied
	}
	if len(token.PrefixScope) > 0 && objectKey != "" {
		if !slices.ContainsFunc(token.PrefixScope, func(p string) bool {
			return strings.HasPrefix(objectKey, p)
		}) {
			return ErrAccessDenied
		}
	}
	return nil
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

	// Checksum verifies what the client declared about the bytes it is
	// sending. The transport builds it (see NewChecksumVerifier) because the
	// declaration arrives in transport-specific headers, and a malformed one
	// has to be refused before the body is read at all.
	//
	// nil means the client declared nothing — which is what the native
	// protocol always passes, since it carries no client digest.
	Checksum *ChecksumVerifier

	// SkipETag skips computing the MD5 ETag for this upload when true.
	// ChecksumSHA256 is always computed regardless — this only drops the
	// second, S3-only hash. Only honored when Checksum is nil: a caller that
	// declared a checksum to verify keeps getting MD5 computed in case that
	// verification needs it, since correctness of a check the caller
	// explicitly asked for outranks the optimization.
	//
	// The S3 HTTP handler never sets this — S3 clients expect a real ETag.
	// It exists for the native protocol, which never promised S3 ETag
	// semantics and, for a caller that doesn't use the ETag field at all,
	// pays for a hash (MD5, no hardware acceleration on most CPUs) that costs
	// more than the SHA-256 jay computes anyway for its own integrity check.
	SkipETag bool
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
// An upload that is over the size ceiling, or whose bytes do not hash to the
// digest the client declared (opts.Checksum), is refused before the store
// renames the temp file into place: nothing is written and no metadata is
// committed. Answering 200 to a client that asked jay to verify its bytes, and
// verifying nothing, is the defect this path exists to prevent.
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

	// SkipETag drops the MD5 pass entirely (pool Get/Reset/Sum all cost
	// something) when nothing needs it: only the S3 handler's ETag response
	// field and Checksum's own MD5 verification (Content-MD5) ever consume
	// it, and the second one only applies when the caller actually declared
	// a checksum to verify.
	computeMD5 := !opts.SkipETag || opts.Checksum != nil
	var md5Hash hash.Hash
	if computeMD5 {
		md5Hash = md5Pool.Get().(hash.Hash)
		md5Hash.Reset()
		defer md5Pool.Put(md5Hash)
	}

	var src io.Reader = emptyReader{}
	if body != nil {
		src = body
	}

	// Cap the body at max+1 bytes: if the store ends up writing more than max,
	// the client sent an over-sized object. Reading one extra byte is what lets
	// us distinguish "exactly at the limit" from "over the limit".
	maxSize := s.maxObjectSize.Load()
	if maxSize > 0 {
		src = io.LimitReader(src, maxSize+1)
	}

	// Every hasher sees the same single pass: the store's SHA-256, the ETag's
	// MD5 (when computed), and whatever else the client asked to have
	// checked. The body is never buffered and never read twice.
	teeSrc := src
	if md5Hash != nil {
		teeSrc = io.TeeReader(src, md5Hash)
	}
	teeBody := opts.Checksum.Wrap(teeSrc)

	// The two ways an upload can be refused after its bytes have been read —
	// too big, or a digest that does not match what the client declared — both
	// run here, between the fsync and the rename. A refusal therefore leaves no
	// file under buckets/ and no metadata, rather than writing an object and
	// deleting it afterwards.
	var seenSize int64
	verify := func(sha256Hex string, size int64) error {
		seenSize = size
		if maxSize > 0 && size > maxSize {
			return ErrObjectTooLarge
		}
		var md5Hex string
		if md5Hash != nil {
			md5Hex = hex.EncodeToString(md5Hash.Sum(nil))
		}
		return opts.Checksum.Verify(sha256Hex, md5Hex)
	}

	checksum, size, locationRef, err := s.store.WriteObjectVerified(bucket.ID, objectID, teeBody, verify)
	if err != nil {
		switch {
		case errors.Is(err, ErrObjectTooLarge):
			s.log.Warn("objops: object exceeds max size",
				"bucket", bucketName, "key", key, "size", seenSize, "max", maxSize)
		case errors.Is(err, ErrBadDigest), errors.Is(err, ErrInvalidDigest):
			s.log.Warn("objops: client checksum mismatch, nothing written",
				"err", err, "bucket", bucketName, "key", key)
		default:
			s.log.Error("objops: write object", "err", err, "bucket", bucketName, "key", key)
		}
		return nil, err
	}

	var etag string
	if md5Hash != nil {
		etag = hex.EncodeToString(md5Hash.Sum(nil))
	}
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
