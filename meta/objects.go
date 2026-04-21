package meta

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrObjectNotFound = errors.New("object not found")
)

// deletionHooks holds per-DB deletion callbacks. Stored in a package-level
// sync.Map to avoid mutating the DB struct definition (owned elsewhere).
// The callback fires after a successful DeleteObjectMeta commit and is used
// by the maintenance GC to wake immediately instead of polling.
var deletionHooks sync.Map // key: *DB, value: func()

// SetDeletionHook registers a callback invoked after a successful
// DeleteObjectMeta commit. Safe to call with nil to clear. Single callback
// per DB instance — a second call overwrites.
func (db *DB) SetDeletionHook(fn func()) {
	if fn == nil {
		deletionHooks.Delete(db)
		return
	}
	deletionHooks.Store(db, fn)
}

func (db *DB) fireDeletionHook() {
	v, ok := deletionHooks.Load(db)
	if !ok {
		return
	}
	if fn, ok := v.(func()); ok && fn != nil {
		fn()
	}
}

// PutObjectMeta creates or updates object metadata within a bbolt write transaction.
// Returns the previous object (if overwriting) for GC of the old physical file.
func (db *DB) PutObjectMeta(obj *Object) (*Object, error) {
	if obj.CreatedAt.IsZero() {
		obj.CreatedAt = time.Now().UTC()
	}
	obj.UpdatedAt = time.Now().UTC()
	if obj.State == "" {
		obj.State = "active"
	}

	data, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("meta: marshal object: %w", err)
	}

	var prev *Object
	err = db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(objectsBucketName(obj.BucketID))
		if bk == nil {
			return ErrBucketNotFound
		}
		// Compute stats delta based on the previous record state.
		var dCount, dSize int64
		if existing := bk.Get([]byte(obj.Key)); existing != nil {
			var old Object
			if err := json.Unmarshal(existing, &old); err == nil {
				if old.State == "active" {
					prev = &old
					if obj.State == "active" {
						// Overwrite active→active: object count unchanged.
						dSize = obj.SizeBytes - old.SizeBytes
					} else {
						// Overwriting active with non-active is unusual but we handle it.
						dCount = -1
						dSize = -old.SizeBytes
					}
				} else {
					// Previous record was not active.
					if obj.State == "active" {
						dCount = 1
						dSize = obj.SizeBytes
					}
				}
			}
		} else {
			if obj.State == "active" {
				dCount = 1
				dSize = obj.SizeBytes
			}
		}
		if err := bk.Put([]byte(obj.Key), data); err != nil {
			return err
		}
		if dCount != 0 || dSize != 0 {
			if err := addBucketStat(tx, obj.BucketID, dCount, dSize); err != nil {
				return err
			}
		}
		return nil
	})
	return prev, err
}

// GetObjectMeta retrieves object metadata by bucket ID and key.
func (db *DB) GetObjectMeta(bucketID, key string) (*Object, error) {
	var obj Object
	err := db.bolt.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(objectsBucketName(bucketID))
		if bk == nil {
			return ErrBucketNotFound
		}
		data := bk.Get([]byte(key))
		if data == nil {
			return ErrObjectNotFound
		}
		return json.Unmarshal(data, &obj)
	})
	if err != nil {
		return nil, err
	}
	if obj.State != "active" {
		return nil, ErrObjectNotFound
	}
	return &obj, nil
}

// DeleteObjectMeta marks an object as deleted and returns it for physical GC.
func (db *DB) DeleteObjectMeta(bucketID, key string) (*Object, error) {
	var obj Object
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(objectsBucketName(bucketID))
		if bk == nil {
			return ErrBucketNotFound
		}
		data := bk.Get([]byte(key))
		if data == nil {
			return ErrObjectNotFound
		}
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		if obj.State != "active" {
			return ErrObjectNotFound
		}
		// Remove the key entirely so DeleteBucket's empty check works
		if err := bk.Delete([]byte(key)); err != nil {
			return err
		}
		return addBucketStat(tx, bucketID, -1, -obj.SizeBytes)
	})
	if err != nil {
		return nil, err
	}
	// Fire the deletion hook outside the bbolt tx so consumers (GC) can
	// wake without blocking the transaction.
	db.fireDeletionHook()
	return &obj, nil
}

// ListObjectsResult holds the result of a ListObjects call.
type ListObjectsResult struct {
	Objects        []Object
	CommonPrefixes []string
	IsTruncated    bool
	NextStartAfter string
}

// ListObjects lists objects in a bucket with prefix, delimiter, pagination support.
// Pagination is applied inside the cursor loop: iteration stops as soon as
// maxKeys is reached, so cost is bounded by maxKeys rather than by the bucket
// size. Preserves IsTruncated and NextStartAfter semantics expected by callers.
func (db *DB) ListObjects(bucketID, prefix, delimiter, startAfter string, maxKeys int) (*ListObjectsResult, error) {
	if maxKeys <= 0 {
		maxKeys = 1000
	}

	result := &ListObjectsResult{}
	prefixSet := make(map[string]bool)
	count := 0

	err := db.bolt.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(objectsBucketName(bucketID))
		if bk == nil {
			return ErrBucketNotFound
		}

		c := bk.Cursor()
		var k, v []byte
		seekKey := max(startAfter, prefix)
		if seekKey == "" {
			k, v = c.First()
		} else {
			k, v = c.Seek([]byte(seekKey))
			if startAfter != "" && string(k) == startAfter {
				k, v = c.Next()
			}
		}

		for ; k != nil; k, v = c.Next() {
			if prefix != "" && !bytes.HasPrefix(k, []byte(prefix)) {
				break
			}

			key := string(k)

			var obj Object
			if err := json.Unmarshal(v, &obj); err != nil {
				slog.Warn("meta: corrupt object record", "key", key, "err", err)
				continue
			}
			if obj.State != "active" {
				continue
			}

			if delimiter != "" {
				rest := key[len(prefix):]
				idx := strings.Index(rest, delimiter)
				if idx >= 0 {
					cp := prefix + rest[:idx+len(delimiter)]
					if prefixSet[cp] {
						continue
					}
					if count >= maxKeys {
						result.IsTruncated = true
						return nil
					}
					prefixSet[cp] = true
					result.CommonPrefixes = append(result.CommonPrefixes, cp)
					count++
					continue
				}
			}

			if count >= maxKeys {
				result.IsTruncated = true
				return nil
			}

			// Copy fields we expose; Object itself is value-type and safe to
			// retain after the tx closes (no unsafe references into bbolt pages).
			result.Objects = append(result.Objects, obj)
			result.NextStartAfter = key
			count++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// QuarantineObject marks an object as quarantined in metadata.
func (db *DB) QuarantineObject(bucketID, key string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(objectsBucketName(bucketID))
		if bk == nil {
			return ErrBucketNotFound
		}
		data := bk.Get([]byte(key))
		if data == nil {
			return ErrObjectNotFound
		}
		var obj Object
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		wasActive := obj.State == "active"
		prevSize := obj.SizeBytes
		obj.State = "quarantined"
		obj.UpdatedAt = time.Now().UTC()
		updated, err := json.Marshal(&obj)
		if err != nil {
			return err
		}
		if err := bk.Put([]byte(key), updated); err != nil {
			return err
		}
		if wasActive {
			if err := addBucketStat(tx, bucketID, -1, -prevSize); err != nil {
				return err
			}
		}
		return nil
	})
}

// ForEachObject iterates all objects in a bucket (all states) and calls fn for each.
func (db *DB) ForEachObject(bucketID string, fn func(Object) error) error {
	return db.bolt.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(objectsBucketName(bucketID))
		if bk == nil {
			return nil
		}
		return bk.ForEach(func(k, v []byte) error {
			var obj Object
			if err := json.Unmarshal(v, &obj); err != nil {
				slog.Warn("meta: corrupt object record", "key", string(k), "err", err)
				return nil
			}
			return fn(obj)
		})
	})
}

// GetObjectMetaAny retrieves object metadata regardless of state.
func (db *DB) GetObjectMetaAny(bucketID, key string) (*Object, error) {
	var obj Object
	err := db.bolt.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(objectsBucketName(bucketID))
		if bk == nil {
			return ErrBucketNotFound
		}
		data := bk.Get([]byte(key))
		if data == nil {
			return ErrObjectNotFound
		}
		return json.Unmarshal(data, &obj)
	})
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

// RestoreObject sets a quarantined object's state back to "active".
func (db *DB) RestoreObject(bucketID, key string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(objectsBucketName(bucketID))
		if bk == nil {
			return ErrBucketNotFound
		}
		data := bk.Get([]byte(key))
		if data == nil {
			return ErrObjectNotFound
		}
		var obj Object
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		wasActive := obj.State == "active"
		obj.State = "active"
		obj.UpdatedAt = time.Now().UTC()
		updated, err := json.Marshal(&obj)
		if err != nil {
			return err
		}
		if err := bk.Put([]byte(key), updated); err != nil {
			return err
		}
		if !wasActive {
			if err := addBucketStat(tx, bucketID, 1, obj.SizeBytes); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteObjectMetaAny removes object metadata regardless of state.
func (db *DB) DeleteObjectMetaAny(bucketID, key string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(objectsBucketName(bucketID))
		if bk == nil {
			return ErrBucketNotFound
		}
		data := bk.Get([]byte(key))
		if data == nil {
			return ErrObjectNotFound
		}
		return bk.Delete([]byte(key))
	})
}

// ForEachObjectFrom iterates objects starting from startKey (exclusive), up to limit.
// Returns the key of the last object visited (for resumption) and any error.
func (db *DB) ForEachObjectFrom(bucketID, startKey string, limit int, fn func(Object) error) (lastKey string, err error) {
	err = db.bolt.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(objectsBucketName(bucketID))
		if bk == nil {
			return nil
		}

		c := bk.Cursor()
		var k, v []byte
		if startKey == "" {
			k, v = c.First()
		} else {
			k, v = c.Seek([]byte(startKey))
			// Skip the exact match so iteration is exclusive of startKey.
			if k != nil && string(k) == startKey {
				k, v = c.Next()
			}
		}

		count := 0
		for ; k != nil && count < limit; k, v = c.Next() {
			var obj Object
			if err := json.Unmarshal(v, &obj); err != nil {
				slog.Warn("meta: corrupt object record", "key", string(k), "err", err)
				continue
			}
			lastKey = string(k)
			if err := fn(obj); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	return lastKey, err
}
