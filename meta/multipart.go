package meta

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

const MaxMultipartParts = 10000

var (
	bucketMultipart    = []byte("multipart")
	ErrUploadNotFound  = errors.New("upload not found")
	ErrUploadNotActive = errors.New("upload is not active")
	ErrInvalidPartNumber = errors.New("part number must be between 1 and 10000")
	ErrTooManyParts    = errors.New("upload exceeds maximum number of parts (10000)")
)

// ensureMultipartBucket creates the multipart bbolt bucket if needed.
func (db *DB) ensureMultipartBucket() error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketMultipart)
		return err
	})
}

// CreateMultipartUpload starts a new multipart upload.
func (db *DB) CreateMultipartUpload(upload *MultipartUpload) error {
	db.ensureMultipartBucket()

	if upload.CreatedAt.IsZero() {
		upload.CreatedAt = time.Now().UTC()
	}
	if upload.State == "" {
		upload.State = "initiated"
	}

	data, err := json.Marshal(upload)
	if err != nil {
		return fmt.Errorf("meta: marshal upload: %w", err)
	}

	return db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMultipart).Put([]byte(upload.UploadID), data)
	})
}

// GetMultipartUpload retrieves a multipart upload by ID.
func (db *DB) GetMultipartUpload(uploadID string) (*MultipartUpload, error) {
	var upload MultipartUpload
	err := db.bolt.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketMultipart)
		if bk == nil {
			return ErrUploadNotFound
		}
		data := bk.Get([]byte(uploadID))
		if data == nil {
			return ErrUploadNotFound
		}
		return json.Unmarshal(data, &upload)
	})
	if err != nil {
		return nil, err
	}
	return &upload, nil
}

// AddMultipartPart adds or replaces a part in a multipart upload.
func (db *DB) AddMultipartPart(uploadID string, part MultipartPart) error {
	if part.PartNumber < 1 || part.PartNumber > MaxMultipartParts {
		return ErrInvalidPartNumber
	}

	return db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketMultipart)
		if bk == nil {
			return ErrUploadNotFound
		}
		data := bk.Get([]byte(uploadID))
		if data == nil {
			return ErrUploadNotFound
		}
		var upload MultipartUpload
		if err := json.Unmarshal(data, &upload); err != nil {
			return err
		}
		if upload.State != "initiated" {
			return ErrUploadNotActive
		}

		// Replace existing part with same number, or append
		found := false
		for i, p := range upload.Parts {
			if p.PartNumber == part.PartNumber {
				upload.Parts[i] = part
				found = true
				break
			}
		}
		if !found {
			if len(upload.Parts) >= MaxMultipartParts {
				return ErrTooManyParts
			}
			upload.Parts = append(upload.Parts, part)
		}

		// Keep parts sorted
		sort.Slice(upload.Parts, func(i, j int) bool {
			return upload.Parts[i].PartNumber < upload.Parts[j].PartNumber
		})

		updated, err := json.Marshal(&upload)
		if err != nil {
			return err
		}
		return bk.Put([]byte(uploadID), updated)
	})
}

// CompleteMultipartUpload marks the upload as completed and returns the sorted parts.
func (db *DB) CompleteMultipartUpload(uploadID string, partNumbers []int) (*MultipartUpload, error) {
	var upload MultipartUpload
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketMultipart)
		if bk == nil {
			return ErrUploadNotFound
		}
		data := bk.Get([]byte(uploadID))
		if data == nil {
			return ErrUploadNotFound
		}
		if err := json.Unmarshal(data, &upload); err != nil {
			return err
		}
		if upload.State != "initiated" {
			return ErrUploadNotActive
		}

		// Validate part numbers are in valid range
		for _, pn := range partNumbers {
			if pn < 1 || pn > MaxMultipartParts {
				return fmt.Errorf("invalid part number %d", pn)
			}
		}

		// Validate all requested parts exist
		partMap := make(map[int]bool)
		for _, p := range upload.Parts {
			partMap[p.PartNumber] = true
		}
		for _, pn := range partNumbers {
			if !partMap[pn] {
				return fmt.Errorf("part %d not found", pn)
			}
		}

		// Filter to only requested parts, sorted
		var finalParts []MultipartPart
		requestedSet := make(map[int]bool)
		for _, pn := range partNumbers {
			requestedSet[pn] = true
		}
		for _, p := range upload.Parts {
			if requestedSet[p.PartNumber] {
				finalParts = append(finalParts, p)
			}
		}
		sort.Slice(finalParts, func(i, j int) bool {
			return finalParts[i].PartNumber < finalParts[j].PartNumber
		})

		upload.Parts = finalParts
		upload.State = "completed"

		updated, err := json.Marshal(&upload)
		if err != nil {
			return err
		}
		return bk.Put([]byte(uploadID), updated)
	})
	if err != nil {
		return nil, err
	}
	return &upload, nil
}

// AbortMultipartUpload marks the upload as aborted.
func (db *DB) AbortMultipartUpload(uploadID string) (*MultipartUpload, error) {
	var upload MultipartUpload
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketMultipart)
		if bk == nil {
			return ErrUploadNotFound
		}
		data := bk.Get([]byte(uploadID))
		if data == nil {
			return ErrUploadNotFound
		}
		if err := json.Unmarshal(data, &upload); err != nil {
			return err
		}

		upload.State = "aborted"
		updated, err := json.Marshal(&upload)
		if err != nil {
			return err
		}
		return bk.Put([]byte(uploadID), updated)
	})
	if err != nil {
		return nil, err
	}
	return &upload, nil
}

// ListMultipartUploads returns active uploads for a bucket.
func (db *DB) ListMultipartUploads(bucketID string) ([]MultipartUpload, error) {
	var uploads []MultipartUpload
	err := db.bolt.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketMultipart)
		if bk == nil {
			return nil
		}
		return bk.ForEach(func(k, v []byte) error {
			var u MultipartUpload
			if err := json.Unmarshal(v, &u); err != nil {
				return nil
			}
			if u.BucketID == bucketID && u.State == "initiated" {
				uploads = append(uploads, u)
			}
			return nil
		})
	})
	return uploads, err
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
		bk.ForEach(func(k, v []byte) error {
			var u MultipartUpload
			if err := json.Unmarshal(v, &u); err != nil {
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
		})
		for _, k := range toDelete {
			bk.Delete(k)
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
