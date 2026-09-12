package objops

import (
	"context"
	"errors"
	"io"
	"os"
	"time"
	"uuid"

	"github.com/ivangsm/jay/meta"
)

// ErrInvalidRange means the requested byte range does not intersect the object.
// Mirrors HTTP 416: the object exists, the request is well-formed, and there
// is nothing to serve for it.
var ErrInvalidRange = errors.New("objops: requested range not satisfiable")

// CopySide names which end of a copy an error is about, so a transport can
// point its response at the right resource: a missing SOURCE bucket and a
// missing DESTINATION bucket are both ErrBucketNotFound.
type CopySide string

// The two ends of a copy.
const (
	CopySource      CopySide = "source"
	CopyDestination CopySide = "destination"
)

// CopyError wraps an objops sentinel with the side of the copy it applies to.
// errors.Is still matches the sentinel; errors.As yields the side.
type CopyError struct {
	Side CopySide
	Err  error
}

func (e *CopyError) Error() string { return string(e.Side) + ": " + e.Err.Error() }
func (e *CopyError) Unwrap() error { return e.Err }

// SideOfCopyError returns which end of the copy err refers to, or "" when err
// is not side-specific (a write failure on the destination, a nil error).
func SideOfCopyError(err error) CopySide {
	if ce, ok := errors.AsType[*CopyError](err); ok {
		return ce.Side
	}
	return ""
}

// CopyOptions carry the per-request extras of a server-side copy.
type CopyOptions struct {
	// Digester, when non-nil, hashes the bytes in the same pass that writes
	// them so the caller can report a digest the client asked for. It is
	// built by the transport because the request for it arrives in
	// transport-specific headers. nil computes nothing beyond the SHA-256
	// the store always produces.
	Digester *ChecksumVerifier

	// BeforeCommit runs after the bytes are on disk and before the metadata
	// is committed, with the SHA-256 the store computed. Returning an error
	// refuses the copy: the freshly written file is removed and nothing is
	// committed, so a refusal never has to undo a bbolt write or resurrect
	// the previous version the overwrite would have replaced. The S3 handler
	// uses it to demand the digest the client asked for exists before it
	// promises one in the response.
	BeforeCommit func(sha256Hex string) error
}

// CopyObject writes a new object at dst from the bytes of src, without the
// bytes leaving the server. Content type and user metadata are carried over
// from the source; the ETag is too, since the bytes are identical.
//
// Authorization runs on both sides before anything is read: object:get on the
// source and object:put on the destination, each through the same
// token → cross-account → bucket-policy chain every other operation uses.
// A token denied object:get on the source cannot exfiltrate it into a bucket
// it controls, which is the reason the copy lives here and not in a handler.
//
// identity.Action is ignored: the two sides need two different actions, and
// this function sets them itself.
func (s *Service) CopyObject(
	_ context.Context,
	token *meta.Token,
	srcBucket, srcKey, dstBucket, dstKey string,
	opts CopyOptions,
	identity Identity,
) (*meta.Object, error) {
	srcBkt, srcObj, err := s.lookupBucketAndObject(srcBucket, srcKey)
	if err != nil {
		return nil, &CopyError{Side: CopySource, Err: err}
	}
	getID := identity
	getID.Action = meta.ActionObjectGet
	if err := s.authorize(srcBkt, getID, token, srcKey); err != nil {
		return nil, &CopyError{Side: CopySource, Err: err}
	}

	dstBkt, err := s.resolveBucket(dstBucket)
	if err != nil {
		return nil, &CopyError{Side: CopyDestination, Err: err}
	}
	putID := identity
	putID.Action = meta.ActionObjectPut
	if err := s.authorize(dstBkt, putID, token, dstKey); err != nil {
		return nil, &CopyError{Side: CopyDestination, Err: err}
	}

	srcFile, err := s.store.ReadObject(srcObj.LocationRef)
	if err != nil {
		// Metadata without a backing file (GC race, manual removal): the
		// object is missing, not the server broken.
		if errors.Is(err, os.ErrNotExist) {
			s.log.Warn("objops: copy source file missing for existing metadata",
				"bucket", srcBucket, "key", srcKey, "location", srcObj.LocationRef)
			return nil, &CopyError{Side: CopySource, Err: ErrObjectNotFound}
		}
		s.log.Error("objops: copy read source", "err", err, "location", srcObj.LocationRef)
		return nil, err
	}
	defer func() { _ = srcFile.Close() }()

	objectID := uuid.New().String()
	// Digester.Wrap is a no-op on nil and otherwise hashes in the SAME pass
	// that writes the bytes: nothing is buffered and nothing is read twice.
	checksum, size, locationRef, err := s.store.WriteObject(dstBkt.ID, objectID, opts.Digester.Wrap(srcFile))
	if err != nil {
		s.log.Error("objops: copy write destination", "err", err, "bucket", dstBucket, "key", dstKey)
		return nil, err
	}

	if opts.BeforeCommit != nil {
		if err := opts.BeforeCommit(checksum); err != nil {
			s.store.Cleanup(locationRef)
			return nil, err
		}
	}

	obj := &meta.Object{
		BucketID:        dstBkt.ID,
		Key:             dstKey,
		ObjectID:        objectID,
		State:           "active",
		SizeBytes:       size,
		ContentType:     srcObj.ContentType,
		ETag:            srcObj.ETag,
		ChecksumSHA256:  checksum,
		LocationRef:     locationRef,
		CreatedAt:       time.Now().UTC(),
		MetadataHeaders: srcObj.MetadataHeaders,
	}

	prev, err := s.db.PutObjectMeta(obj)
	if err != nil {
		// Metadata commit failed — don't leave an orphaned physical file.
		s.store.Cleanup(locationRef)
		s.log.Error("objops: copy put object meta", "err", err, "bucket", dstBucket, "key", dstKey)
		return nil, err
	}

	if prev != nil && prev.LocationRef != locationRef {
		if err := s.store.DeleteObject(prev.LocationRef); err != nil {
			s.log.Warn("objops: gc previous object", "err", err, "location", prev.LocationRef)
		}
	}

	return obj, nil
}

// ResolveRange clamps a caller's (offset, length) against an object's size and
// reports ErrInvalidRange when nothing of the object falls inside it.
//
// length <= 0 means "to the end". An offset at or past the end is
// unsatisfiable, and so is any range on an empty object — the same two rules
// the HTTP Range parser applies, so both transports refuse the same requests.
func ResolveRange(offset, length, size int64) (start, n int64, err error) {
	if offset < 0 || size == 0 || offset >= size {
		return 0, 0, ErrInvalidRange
	}
	remaining := size - offset
	if length <= 0 || length > remaining {
		length = remaining
	}
	return offset, length, nil
}

// OpenObjectRange opens the physical file of an authorized object positioned at
// start, ready for the caller to copy exactly n bytes. The (start, n) pair must
// come from ResolveRange; the caller owns closing the file.
//
// Like OpenObjectFile it skips authorization — the caller already holds an
// authorized *meta.Object — and must not be exposed to untrusted input.
func (s *Service) OpenObjectRange(obj *meta.Object, start int64) (*os.File, error) {
	f, err := s.store.ReadObject(obj.LocationRef)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
