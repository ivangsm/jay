package meta

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrObjectNotFound = errors.New("object not found")
)

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
		// Check for existing object (overwrite case)
		existing := bk.Get([]byte(obj.Key))
		if existing != nil {
			var old Object
			if err := json.Unmarshal(existing, &old); err == nil && old.State == "active" {
				prev = &old
			}
		}
		return bk.Put([]byte(obj.Key), data)
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
		return bk.Delete([]byte(key))
	})
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

// ListObjectsResult holds the result of a ListObjects call.
type ListObjectsResult struct {
	Objects       []Object
	CommonPrefixes []string
	IsTruncated   bool
	NextStartAfter string
}

// ListObjects lists objects in a bucket with prefix, delimiter, pagination support.
func (db *DB) ListObjects(bucketID, prefix, delimiter, startAfter string, maxKeys int) (*ListObjectsResult, error) {
	if maxKeys <= 0 {
		maxKeys = 1000
	}

	result := &ListObjectsResult{}
	prefixSet := make(map[string]bool)

	err := db.bolt.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(objectsBucketName(bucketID))
		if bk == nil {
			return ErrBucketNotFound
		}

		c := bk.Cursor()
		// Determine start position
		var k, v []byte
		seekKey := prefix
		if startAfter > seekKey {
			seekKey = startAfter
		}
		if seekKey == "" {
			k, v = c.First()
		} else {
			k, v = c.Seek([]byte(seekKey))
			// If we're using startAfter, skip the exact match
			if startAfter != "" && string(k) == startAfter {
				k, v = c.Next()
			}
		}

		count := 0
		for ; k != nil; k, v = c.Next() {
			key := string(k)

			// Stop if we've gone past the prefix
			if prefix != "" && !bytes.HasPrefix(k, []byte(prefix)) {
				break
			}

			var obj Object
			if err := json.Unmarshal(v, &obj); err != nil {
				continue
			}
			if obj.State != "active" {
				continue
			}

			// Handle delimiter (virtual directories)
			if delimiter != "" {
				rest := key[len(prefix):]
				idx := indexOf(rest, delimiter)
				if idx >= 0 {
					cp := prefix + rest[:idx+len(delimiter)]
					if !prefixSet[cp] {
						if count >= maxKeys {
							result.IsTruncated = true
							break
						}
						prefixSet[cp] = true
						result.CommonPrefixes = append(result.CommonPrefixes, cp)
						count++
					}
					continue
				}
			}

			if count >= maxKeys {
				result.IsTruncated = true
				break
			}

			result.Objects = append(result.Objects, obj)
			result.NextStartAfter = key
			count++
		}
		return nil
	})

	return result, err
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
		obj.State = "quarantined"
		obj.UpdatedAt = time.Now().UTC()
		updated, err := json.Marshal(&obj)
		if err != nil {
			return err
		}
		return bk.Put([]byte(key), updated)
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
				return nil // skip corrupt entries
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
		obj.State = "active"
		obj.UpdatedAt = time.Now().UTC()
		updated, err := json.Marshal(&obj)
		if err != nil {
			return err
		}
		return bk.Put([]byte(key), updated)
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
				continue // skip corrupt entries
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

func indexOf(s, sep string) int {
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			return i
		}
	}
	return -1
}
