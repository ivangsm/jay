package objops

import (
	"errors"
	"fmt"
	"uuid"

	"github.com/ivangsm/jay/meta"
)

// ErrInvalidBucketName is returned by CreateBucket for a name
// meta.ValidBucketName refuses.
var ErrInvalidBucketName = errors.New("objops: invalid bucket name")

// CreateBucket validates the name, commits the bucket record owned by
// ownerAccountID (private, active) and creates its directory. A directory that
// cannot be created is logged and does not fail the call — the same contract
// the S3 handler had: metadata is committed and the store creates directories
// on first write.
//
// It does not authorize anything. The caller has already decided that this
// caller may create this bucket for this owner: the S3 handler through the
// token, the admin API through the admin token.
func (s *Service) CreateBucket(name, ownerAccountID string) (*meta.Bucket, error) {
	if !meta.ValidBucketName(name) {
		return nil, ErrInvalidBucketName
	}

	bucket := &meta.Bucket{
		ID:             uuid.New().String(),
		Name:           name,
		OwnerAccountID: ownerAccountID,
		Visibility:     meta.VisibilityPrivate,
		Status:         "active",
	}
	if err := s.db.CreateBucket(bucket); err != nil {
		return nil, err
	}

	if err := s.store.EnsureBucketDir(bucket.ID); err != nil {
		s.log.Error("create bucket dir", "err", err, "bucket", name)
		// Best effort: metadata is already committed.
	}
	return bucket, nil
}

// DeleteBucket removes an empty bucket's record and then, best-effort, its
// directory. It returns the bucket that was removed.
//
// A missing bucket is reported as ErrBucketNotFound (which also wraps
// meta.ErrBucketNotFound) and a bucket that still holds objects — quarantined
// ones included — as meta.ErrBucketNotEmpty, with the bucket left untouched.
// Like CreateBucket it does not authorize.
func (s *Service) DeleteBucket(name string) (*meta.Bucket, error) {
	bucket, err := s.db.GetBucket(name)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			return nil, fmt.Errorf("%w: %w", ErrBucketNotFound, err)
		}
		return nil, err
	}

	if err := s.db.DeleteBucket(name); err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			// Deleted between the read above and the write: the caller's
			// answer changed, not jay.
			return nil, fmt.Errorf("%w: %w", ErrBucketNotFound, err)
		}
		return nil, err
	}

	// Metadata is already deleted; a directory left behind is garbage, not a
	// failed delete.
	if err := s.store.RemoveBucketDir(bucket.ID); err != nil {
		s.log.Error("remove bucket dir", "err", err, "bucket", name)
	}
	return bucket, nil
}
