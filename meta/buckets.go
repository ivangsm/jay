package meta

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// MaxBucketsPerAccount is the maximum number of buckets a single account may own.
const MaxBucketsPerAccount = 1000

var (
	ErrBucketExists        = errors.New("bucket already exists")
	ErrBucketNotFound      = errors.New("bucket not found")
	ErrBucketNotEmpty      = errors.New("bucket is not empty")
	ErrBucketLimitExceeded = errors.New("account bucket limit exceeded")
)

// CreateBucket creates a new bucket. Returns ErrBucketExists if the name is taken.
func (db *DB) CreateBucket(b *Bucket) error {
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now().UTC()
	}
	if b.Status == "" {
		b.Status = "active"
	}
	if b.Visibility == "" {
		b.Visibility = "private"
	}

	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("meta: marshal bucket: %w", err)
	}

	return db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketBuckets)
		if bk.Get([]byte(b.Name)) != nil {
			return ErrBucketExists
		}

		// Enforce per-account bucket limit.
		if b.OwnerAccountID != "" {
			count := 0
			if err := bk.ForEach(func(k, v []byte) error {
				var existing Bucket
				if err := json.Unmarshal(v, &existing); err != nil {
					return nil // skip corrupt entries
				}
				if existing.OwnerAccountID == b.OwnerAccountID {
					count++
				}
				return nil
			}); err != nil {
				return err
			}
			if count >= MaxBucketsPerAccount {
				return ErrBucketLimitExceeded
			}
		}

		if err := bk.Put([]byte(b.Name), data); err != nil {
			return err
		}
		// Reverse index
		byID := tx.Bucket(bucketBucketsID)
		if err := byID.Put([]byte(b.ID), []byte(b.Name)); err != nil {
			return err
		}
		// Create the per-bucket objects bbolt bucket
		if _, err := tx.CreateBucketIfNotExists(objectsBucketName(b.ID)); err != nil {
			return fmt.Errorf("meta: create obj bucket: %w", err)
		}
		return nil
	})
}

// GetBucket retrieves a bucket by name.
func (db *DB) GetBucket(name string) (*Bucket, error) {
	var b Bucket
	err := db.bolt.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketBuckets).Get([]byte(name))
		if data == nil {
			return ErrBucketNotFound
		}
		return json.Unmarshal(data, &b)
	})
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// GetBucketByID retrieves a bucket by its ID.
func (db *DB) GetBucketByID(id string) (*Bucket, error) {
	var b Bucket
	err := db.bolt.View(func(tx *bolt.Tx) error {
		name := tx.Bucket(bucketBucketsID).Get([]byte(id))
		if name == nil {
			return ErrBucketNotFound
		}
		data := tx.Bucket(bucketBuckets).Get(name)
		if data == nil {
			return ErrBucketNotFound
		}
		return json.Unmarshal(data, &b)
	})
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// DeleteBucket removes a bucket by name. Fails if objects exist in it.
func (db *DB) DeleteBucket(name string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketBuckets)
		data := bk.Get([]byte(name))
		if data == nil {
			return ErrBucketNotFound
		}
		var b Bucket
		if err := json.Unmarshal(data, &b); err != nil {
			return err
		}

		// Check if bucket has objects
		objBucket := tx.Bucket(objectsBucketName(b.ID))
		if objBucket != nil {
			c := objBucket.Cursor()
			k, _ := c.First()
			if k != nil {
				return ErrBucketNotEmpty
			}
		}

		if err := bk.Delete([]byte(name)); err != nil {
			return err
		}
		tx.Bucket(bucketBucketsID).Delete([]byte(b.ID))
		if objBucket != nil {
			tx.DeleteBucket(objectsBucketName(b.ID))
		}
		return nil
	})
}

// ListBuckets returns all buckets, optionally filtered by owner account.
func (db *DB) ListBuckets(ownerAccountID string) ([]Bucket, error) {
	var buckets []Bucket
	err := db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketBuckets).ForEach(func(k, v []byte) error {
			var b Bucket
			if err := json.Unmarshal(v, &b); err != nil {
				return err
			}
			if ownerAccountID == "" || b.OwnerAccountID == ownerAccountID {
				buckets = append(buckets, b)
			}
			return nil
		})
	})
	return buckets, err
}

// UpdateBucketPolicy updates the policy JSON for a bucket.
func (db *DB) UpdateBucketPolicy(name string, policy json.RawMessage) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketBuckets)
		data := bk.Get([]byte(name))
		if data == nil {
			return ErrBucketNotFound
		}
		var b Bucket
		if err := json.Unmarshal(data, &b); err != nil {
			return err
		}
		b.PolicyJSON = policy
		updated, err := json.Marshal(&b)
		if err != nil {
			return err
		}
		return bk.Put([]byte(name), updated)
	})
}
