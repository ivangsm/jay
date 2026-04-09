package meta

import (
	"encoding/binary"
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

// bucketStatsEntry is the 16-byte layout of a maintained counter:
//   big-endian int64 count || big-endian int64 total_size
const bucketStatsEntrySize = 16

func encodeBucketStatsEntry(count, totalSize int64) []byte {
	var buf [bucketStatsEntrySize]byte
	binary.BigEndian.PutUint64(buf[0:8], uint64(count))
	binary.BigEndian.PutUint64(buf[8:16], uint64(totalSize))
	return buf[:]
}

func decodeBucketStatsEntry(b []byte) (count, totalSize int64, ok bool) {
	if len(b) != bucketStatsEntrySize {
		return 0, 0, false
	}
	count = int64(binary.BigEndian.Uint64(b[0:8]))
	totalSize = int64(binary.BigEndian.Uint64(b[8:16]))
	return count, totalSize, true
}

// addBucketStat atomically applies a delta to the maintained bucket_stats
// counter for bucketID within the given write transaction. It lazily creates
// a zero entry if none exists.
func addBucketStat(tx *bolt.Tx, bucketID string, dCount, dSize int64) error {
	sys := tx.Bucket(bucketSys)
	if sys == nil {
		return fmt.Errorf("meta: sys bucket missing")
	}
	stats := sys.Bucket(sysBucketStats)
	if stats == nil {
		return fmt.Errorf("meta: sys/bucket_stats bucket missing")
	}
	key := []byte(bucketID)
	var count, totalSize int64
	if existing := stats.Get(key); existing != nil {
		c, s, ok := decodeBucketStatsEntry(existing)
		if ok {
			count, totalSize = c, s
		}
	}
	count += dCount
	totalSize += dSize
	if count < 0 {
		count = 0
	}
	if totalSize < 0 {
		totalSize = 0
	}
	if err := stats.Put(key, encodeBucketStatsEntry(count, totalSize)); err != nil {
		return fmt.Errorf("meta: update bucket_stats: %w", err)
	}
	return nil
}

// accountBucketCountGet reads the current per-account bucket count inside tx.
// Missing entry lazy-inits to 0.
func accountBucketCountGet(tx *bolt.Tx, accountID string) int64 {
	sys := tx.Bucket(bucketSys)
	if sys == nil {
		return 0
	}
	bk := sys.Bucket(sysAccountBucketCount)
	if bk == nil {
		return 0
	}
	raw := bk.Get([]byte(accountID))
	if len(raw) != 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(raw))
}

// accountBucketCountAdd atomically adjusts the per-account bucket count.
// It refuses to go below 0 (skipping the write rather than clamping noisily).
func accountBucketCountAdd(tx *bolt.Tx, accountID string, delta int64) error {
	sys := tx.Bucket(bucketSys)
	if sys == nil {
		return fmt.Errorf("meta: sys bucket missing")
	}
	bk := sys.Bucket(sysAccountBucketCount)
	if bk == nil {
		return fmt.Errorf("meta: sys/account_bucket_count bucket missing")
	}
	key := []byte(accountID)
	var current int64
	if raw := bk.Get(key); len(raw) == 8 {
		current = int64(binary.BigEndian.Uint64(raw))
	}
	next := current + delta
	if next < 0 {
		return nil
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(next))
	if err := bk.Put(key, buf[:]); err != nil {
		return fmt.Errorf("meta: update account_bucket_count: %w", err)
	}
	return nil
}

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

		// Enforce per-account bucket limit using the maintained counter.
		if b.OwnerAccountID != "" {
			current := accountBucketCountGet(tx, b.OwnerAccountID)
			if current >= MaxBucketsPerAccount {
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
		// Initialize the stats counter to (0, 0) so RebuildAllBucketStatsIfMissing
		// will not clobber it later.
		sys := tx.Bucket(bucketSys).Bucket(sysBucketStats)
		if sys.Get([]byte(b.ID)) == nil {
			if err := sys.Put([]byte(b.ID), encodeBucketStatsEntry(0, 0)); err != nil {
				return fmt.Errorf("meta: init bucket_stats: %w", err)
			}
		}
		// Increment per-account bucket count.
		if b.OwnerAccountID != "" {
			if err := accountBucketCountAdd(tx, b.OwnerAccountID, 1); err != nil {
				return err
			}
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
		if err := tx.Bucket(bucketBucketsID).Delete([]byte(b.ID)); err != nil {
			return err
		}
		if objBucket != nil {
			if err := tx.DeleteBucket(objectsBucketName(b.ID)); err != nil {
				return err
			}
		}
		// Drop the maintained stats entry.
		if stats := tx.Bucket(bucketSys).Bucket(sysBucketStats); stats != nil {
			if err := stats.Delete([]byte(b.ID)); err != nil {
				return fmt.Errorf("meta: delete bucket_stats: %w", err)
			}
		}
		// Decrement per-account bucket count.
		if b.OwnerAccountID != "" {
			if err := accountBucketCountAdd(tx, b.OwnerAccountID, -1); err != nil {
				return err
			}
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

// BucketStats returns the count and total size of active objects in a bucket
// by reading the maintained counter in O(1). A missing entry returns (0, 0, nil).
func (db *DB) BucketStats(bucketID string) (count int64, totalSize int64, err error) {
	err = db.bolt.View(func(tx *bolt.Tx) error {
		sys := tx.Bucket(bucketSys)
		if sys == nil {
			return nil
		}
		stats := sys.Bucket(sysBucketStats)
		if stats == nil {
			return nil
		}
		raw := stats.Get([]byte(bucketID))
		if raw == nil {
			return nil
		}
		c, s, ok := decodeBucketStatsEntry(raw)
		if !ok {
			return fmt.Errorf("meta: corrupt bucket_stats entry for %q", bucketID)
		}
		count = c
		totalSize = s
		return nil
	})
	return count, totalSize, err
}

// RebuildBucketStats walks obj:<bucketID> and recomputes the maintained
// counter from active object records.
func (db *DB) RebuildBucketStats(bucketID string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		var count, totalSize int64
		objBk := tx.Bucket(objectsBucketName(bucketID))
		if objBk != nil {
			if err := objBk.ForEach(func(k, v []byte) error {
				var obj Object
				if err := json.Unmarshal(v, &obj); err != nil {
					return nil // skip corrupt entries
				}
				if obj.State != "active" {
					return nil
				}
				count++
				totalSize += obj.SizeBytes
				return nil
			}); err != nil {
				return fmt.Errorf("meta: rebuild bucket_stats walk: %w", err)
			}
		}
		stats := tx.Bucket(bucketSys).Bucket(sysBucketStats)
		if stats == nil {
			return fmt.Errorf("meta: sys/bucket_stats bucket missing")
		}
		if err := stats.Put([]byte(bucketID), encodeBucketStatsEntry(count, totalSize)); err != nil {
			return fmt.Errorf("meta: write bucket_stats: %w", err)
		}
		return nil
	})
}

// RebuildAllBucketStatsIfMissing iterates every bucket and rebuilds the
// maintained stats entry only for those whose counter is absent. Existing
// entries (including zero-valued ones) are left untouched.
func (db *DB) RebuildAllBucketStatsIfMissing() error {
	var missing []string
	err := db.bolt.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketBuckets)
		if bk == nil {
			return nil
		}
		stats := tx.Bucket(bucketSys).Bucket(sysBucketStats)
		if stats == nil {
			return fmt.Errorf("meta: sys/bucket_stats bucket missing")
		}
		return bk.ForEach(func(k, v []byte) error {
			var b Bucket
			if err := json.Unmarshal(v, &b); err != nil {
				return nil
			}
			if stats.Get([]byte(b.ID)) == nil {
				missing = append(missing, b.ID)
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	for _, id := range missing {
		if err := db.RebuildBucketStats(id); err != nil {
			return err
		}
	}
	return nil
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
