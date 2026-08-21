package meta

import (
	"cmp"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ivangsm/jay/internal/jsonx"
	bolt "go.etcd.io/bbolt"
)

const MaxMultipartParts = 10000

var (
	bucketMultipart      = []byte("multipart")
	ErrUploadNotFound    = errors.New("upload not found")
	ErrUploadNotActive   = errors.New("upload is not active")
	ErrInvalidPartNumber = errors.New("part number must be between 1 and 10000")
	ErrTooManyParts      = errors.New("upload exceeds maximum number of parts (10000)")
)

// CreateMultipartUpload starts a new multipart upload.
//
// The multipart bbolt bucket is created once by bootstrap() at Open time, so
// this path only opens a single write transaction (previously it opened an
// extra one per create just to CreateBucketIfNotExists).
func (db *DB) CreateMultipartUpload(upload *MultipartUpload) error {
	if upload.CreatedAt.IsZero() {
		upload.CreatedAt = time.Now().UTC()
	}
	if upload.State == "" {
		upload.State = "initiated"
	}

	return db.bolt.Update(func(tx *bolt.Tx) error {
		// Defensive: bootstrap() creates this bucket, but a DB handle built
		// outside Open() (e.g. a hand-rolled test fixture) may not have it.
		if tx.Bucket(bucketMultipart) == nil {
			if _, err := tx.CreateBucketIfNotExists(bucketMultipart); err != nil {
				return fmt.Errorf("meta: create multipart bucket: %w", err)
			}
		}
		return putRecordTx(tx, bucketMultipart, []byte(upload.UploadID), upload)
	})
}

// GetMultipartUpload retrieves a multipart upload by ID.
func (db *DB) GetMultipartUpload(uploadID string) (*MultipartUpload, error) {
	return db.getRecord[MultipartUpload](bucketMultipart, uploadID, ErrUploadNotFound)
}

// AddMultipartPart adds or replaces a part in a multipart upload.
func (db *DB) AddMultipartPart(uploadID string, part MultipartPart) error {
	if part.PartNumber < 1 || part.PartNumber > MaxMultipartParts {
		return ErrInvalidPartNumber
	}

	return db.updateRecord(bucketMultipart, uploadID, ErrUploadNotFound, func(upload *MultipartUpload) error {
		if upload.State != "initiated" {
			return ErrUploadNotActive
		}

		// Replace existing part with same number, or append
		if i := slices.IndexFunc(upload.Parts, func(p MultipartPart) bool {
			return p.PartNumber == part.PartNumber
		}); i >= 0 {
			upload.Parts[i] = part
		} else {
			if len(upload.Parts) >= MaxMultipartParts {
				return ErrTooManyParts
			}
			upload.Parts = append(upload.Parts, part)
		}

		// Keep parts sorted
		slices.SortFunc(upload.Parts, func(a, b MultipartPart) int {
			return cmp.Compare(a.PartNumber, b.PartNumber)
		})
		return nil
	})
}

// CompleteMultipartUpload validates the requested parts and returns the sorted
// part set without mutating upload state. Callers must assemble and commit the
// final object before marking/deleting the upload, so failed assembly remains
// retryable.
func (db *DB) CompleteMultipartUpload(uploadID string, partNumbers []int) (*MultipartUpload, error) {
	upload, err := db.getRecord[MultipartUpload](bucketMultipart, uploadID, ErrUploadNotFound)
	if err != nil {
		return nil, err
	}
	if upload.State != "initiated" {
		return nil, ErrUploadNotActive
	}

	// Validate part numbers are in valid range
	for _, pn := range partNumbers {
		if pn < 1 || pn > MaxMultipartParts {
			return nil, fmt.Errorf("invalid part number %d", pn)
		}
	}

	// Validate all requested parts exist
	stored := make(map[int]bool, len(upload.Parts))
	for _, p := range upload.Parts {
		stored[p.PartNumber] = true
	}
	requested := make(map[int]bool, len(partNumbers))
	for _, pn := range partNumbers {
		if !stored[pn] {
			return nil, fmt.Errorf("part %d not found", pn)
		}
		requested[pn] = true
	}

	// Filter to only requested parts, sorted
	var finalParts []MultipartPart
	for _, p := range upload.Parts {
		if requested[p.PartNumber] {
			finalParts = append(finalParts, p)
		}
	}
	slices.SortFunc(finalParts, func(a, b MultipartPart) int {
		return cmp.Compare(a.PartNumber, b.PartNumber)
	})

	upload.Parts = finalParts
	return upload, nil
}

// MarkMultipartUploadCompleted marks a still-active multipart upload as
// completed after the final object has been durably committed.
func (db *DB) MarkMultipartUploadCompleted(uploadID string) error {
	return db.updateRecord(bucketMultipart, uploadID, ErrUploadNotFound, func(upload *MultipartUpload) error {
		if upload.State != "initiated" {
			return ErrUploadNotActive
		}
		upload.State = "completed"
		return nil
	})
}

// AbortMultipartUpload marks the upload as aborted.
//
// Only an upload still in the "initiated" state can be aborted. Aborting a
// completed upload used to overwrite its record with state "aborted" and let
// the caller delete the part files of an upload whose object had already been
// committed; it now returns ErrUploadNotActive, which transports map to the
// S3 NoSuchUpload semantics (the upload no longer exists as an active one).
func (db *DB) AbortMultipartUpload(uploadID string) (*MultipartUpload, error) {
	var aborted *MultipartUpload
	err := db.updateRecord(bucketMultipart, uploadID, ErrUploadNotFound, func(upload *MultipartUpload) error {
		if upload.State != "initiated" {
			return ErrUploadNotActive
		}
		upload.State = "aborted"
		aborted = upload
		return nil
	})
	if err != nil {
		return nil, err
	}
	return aborted, nil
}

// ListMultipartUploads returns active uploads for a bucket.
func (db *DB) ListMultipartUploads(bucketID string) ([]MultipartUpload, error) {
	return db.listRecords(bucketMultipart, func(u *MultipartUpload) bool {
		return u.BucketID == bucketID && u.State == "initiated"
	})
}

// CleanupExpiredUploads removes uploads older than maxAge.
func (db *DB) CleanupExpiredUploads(maxAge time.Duration) ([]MultipartUpload, error) {
	cutoff := time.Now().Add(-maxAge)
	var expired []MultipartUpload

	err := db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketMultipart)
		if bk == nil {
			return nil
		}
		var toDelete [][]byte
		if err := bk.ForEach(func(k, v []byte) error {
			var u MultipartUpload
			if err := jsonv2.Unmarshal(v, &u, jsonx.Wire); err != nil {
				db.reportDecodeFailure(bucketMultipart, string(k), err)
				return nil
			}
			if u.State == "initiated" && u.CreatedAt.Before(cutoff) {
				expired = append(expired, u)
				toDelete = append(toDelete, append([]byte{}, k...))
			}
			// Also clean up completed/aborted uploads older than cutoff
			if (u.State == "completed" || u.State == "aborted") && u.CreatedAt.Before(cutoff) {
				toDelete = append(toDelete, append([]byte{}, k...))
			}
			return nil
		}); err != nil {
			return fmt.Errorf("scan multipart uploads: %w", err)
		}
		for _, k := range toDelete {
			if err := bk.Delete(k); err != nil {
				return fmt.Errorf("delete expired upload: %w", err)
			}
		}
		return nil
	})
	return expired, err
}

// DeleteMultipartUpload removes a completed/aborted upload record.
func (db *DB) DeleteMultipartUpload(uploadID string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketMultipart)
		if bk == nil {
			return nil
		}
		return bk.Delete([]byte(uploadID))
	})
}
