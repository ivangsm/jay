package meta

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ivangsm/jay/internal/jsonx"
	bolt "go.etcd.io/bbolt"
)

// ErrObjectNotFound is returned when a key has no record. Distinguishing it from
// a read failure is what lets the API answer 404 rather than 500.
var ErrObjectNotFound = errors.New("object not found")

// SetDeletionHook registers a callback invoked after a successful
// DeleteObjectMeta commit. It is used by the maintenance GC to wake
// immediately instead of polling. Safe to call with nil to clear. Single
// callback per DB instance — a second call overwrites. Invocations are
// serialized via hookMu, like the token-invalidate hook.
func (db *DB) SetDeletionHook(fn func()) {
	db.hookMu.Lock()
	db.deletionHook = fn
	db.hookMu.Unlock()
}

// fireDeletionHook invokes the registered hook (if any).
// Callers MUST only call this after a successful bbolt commit.
func (db *DB) fireDeletionHook() {
	db.hookMu.RLock()
	fn := db.deletionHook
	db.hookMu.RUnlock()
	if fn != nil {
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

	data, err := encodeObject(obj)
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
			if err := decodeObject(existing, &old); err == nil {
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

// GetBucketAndObject resolves a bucket by name and fetches an active object by
// key in a single bbolt View transaction. Returns ErrBucketNotFound if the
// bucket is missing and ErrObjectNotFound if the object is missing or not in
// the "active" state. When the bucket exists but the object does not, the
// bucket pointer is still returned alongside ErrObjectNotFound so callers can
// authorize without issuing a second view transaction.
func (db *DB) GetBucketAndObject(bucketName, key string) (*Bucket, *Object, error) {
	var (
		bucket   Bucket
		obj      Object
		foundObj bool
	)
	err := db.bolt.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketBuckets).Get([]byte(bucketName))
		if data == nil {
			return ErrBucketNotFound
		}
		if err := jsonv2.Unmarshal(data, &bucket, jsonx.Wire); err != nil {
			return err
		}
		bk := tx.Bucket(objectsBucketName(bucket.ID))
		if bk == nil {
			return nil
		}
		raw := bk.Get([]byte(key))
		if raw == nil {
			return nil
		}
		if err := decodeObject(raw, &obj); err != nil {
			return err
		}
		foundObj = true
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if !foundObj || obj.State != "active" {
		return &bucket, nil, ErrObjectNotFound
	}
	return &bucket, &obj, nil
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
		return decodeObject(data, &obj)
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
		if err := decodeObject(data, &obj); err != nil {
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
//
// Iteration is split into short read transactions (batchSize keys each) so that
// long listings do not starve bbolt writers (bbolt allows a single writer and
// blocks it for the entire lifetime of any overlapping read tx). Between
// batches the read tx is released, giving writers a chance to commit; the next
// batch resumes from the last key seen.
//
// Externally observable semantics (returned object set, CommonPrefixes,
// IsTruncated, delimiter handling, prefix matching, maxKeys cap) are preserved
// bit-identical to the previous single-tx implementation.
//
// NextStartAfter is the last key fully consumed by the page — that is, the last
// key that either produced an object, produced a CommonPrefix, or was folded
// into a CommonPrefix already emitted in this page (as well as records skipped
// because they were corrupt or not active). It is NOT necessarily the key of the
// last object returned. This is what makes delimiter pagination terminate:
// startAfter is exclusive, so the next page resumes strictly after the last key
// this page looked at, which guarantees monotonic progress even when a page ends
// on (or consists entirely of) CommonPrefixes. Because members of an already
// emitted CommonPrefix are consumed before the maxKeys check, a prefix group is
// never split across pages, so no CommonPrefix can be emitted twice.
//
// Real S3 uses an opaque NextContinuationToken; a plain "last key seen" cursor
// is sufficient here and keeps the token human-readable and compatible with
// start-after.
// defaultMaxKeys is the page size S3 uses when a client does not ask for one.
const defaultMaxKeys = 1000

// listBatchSize is how many records are pulled out of bbolt per read
// transaction. Deliberately small: the records are processed outside the
// transaction so writers can interleave, and a long-lived read tx blocks the
// writer's mmap remap and pins freelist pages.
const listBatchSize = 100

// kvPair is a copy of one key/value pair taken out of a bbolt transaction, so
// it stays valid after that transaction is released.
type kvPair struct {
	key []byte
	val []byte
}

// listCursor tracks a listing's position across batches.
//
// The two positions differ, and the difference is the whole reason this is a
// struct: `resumeAt` advances past EVERY key seen, including ones the page
// skipped, so the scan always makes forward progress. `lastConsumed` only
// advances past keys the page actually accounted for, and becomes
// NextStartAfter — so the key that triggered truncation is served on the next
// page instead of being silently dropped.
type listCursor struct {
	resumeAt     string
	lastConsumed string
	firstBatch   bool
	exhausted    bool
}

// ListObjects returns one page of a bucket's objects, rolling keys up into
// common prefixes when a delimiter is given.
//
// The listing is paged internally: bbolt is read in small batches and each batch
// is processed after its transaction closes, so a large listing never holds a
// read transaction open long enough to stall writers.
func (db *DB) ListObjects(bucketID, prefix, delimiter, startAfter string, maxKeys int) (*ListObjectsResult, error) {
	if maxKeys <= 0 {
		maxKeys = defaultMaxKeys
	}

	result := &ListObjectsResult{}
	seenPrefixes := make(map[string]bool)
	cursor := listCursor{firstBatch: true}
	count := 0

	for !cursor.exhausted {
		batch, err := db.readListBatch(bucketID, prefix, startAfter, &cursor)
		if err != nil {
			return nil, err
		}
		cursor.firstBatch = false
		if len(batch) == 0 {
			break
		}

		truncated := db.consumeListBatch(batch, listPage{
			prefix:       prefix,
			delimiter:    delimiter,
			maxKeys:      maxKeys,
			result:       result,
			seenPrefixes: seenPrefixes,
			cursor:       &cursor,
			count:        &count,
		})
		if truncated {
			break
		}
	}

	result.NextStartAfter = cursor.lastConsumed
	return result, nil
}

// readListBatch pulls the next batch of raw records out of bbolt.
//
// It marks the cursor exhausted as soon as it walks past the prefix or off the
// end of the bucket — from that point no later batch can match.
func (db *DB) readListBatch(bucketID, prefix, startAfter string, cursor *listCursor) ([]kvPair, error) {
	batch := make([]kvPair, 0, listBatchSize)

	err := db.bolt.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(objectsBucketName(bucketID))
		if bk == nil {
			return ErrBucketNotFound
		}

		c := bk.Cursor()
		var k, v []byte
		if cursor.firstBatch {
			// startAfter is exclusive, prefix is inclusive; seeking to the
			// larger of the two lands on the first key either could allow.
			seekKey := max(startAfter, prefix)
			if seekKey == "" {
				k, v = c.First()
			} else {
				k, v = c.Seek([]byte(seekKey))
				if startAfter != "" && k != nil && string(k) == startAfter {
					k, v = c.Next()
				}
			}
		} else {
			// Resume strictly after the last key processed. Seek lands on
			// >= resumeAt, so an exact hit has to be stepped past.
			k, v = c.Seek([]byte(cursor.resumeAt))
			if k != nil && string(k) == cursor.resumeAt {
				k, v = c.Next()
			}
		}

		for ; k != nil && len(batch) < listBatchSize; k, v = c.Next() {
			if prefix != "" && !bytes.HasPrefix(k, []byte(prefix)) {
				cursor.exhausted = true
				return nil
			}
			batch = append(batch, kvPair{
				key: append([]byte(nil), k...),
				val: append([]byte(nil), v...),
			})
		}
		if k == nil {
			cursor.exhausted = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return batch, nil
}

// listPage is the mutable state one batch contributes to.
type listPage struct {
	prefix       string
	delimiter    string
	maxKeys      int
	result       *ListObjectsResult
	seenPrefixes map[string]bool
	cursor       *listCursor
	count        *int
}

// consumeListBatch folds one batch into the page, and reports whether the page
// filled up.
//
// Runs OUTSIDE the bbolt transaction so writers can interleave.
func (db *DB) consumeListBatch(batch []kvPair, page listPage) (truncated bool) {
	for _, p := range batch {
		key := string(p.key)
		// The resume cursor advances even for records this page skips —
		// corrupt, not active, or already rolled up — so the scan cannot stall
		// on a record it will never emit.
		page.cursor.resumeAt = key

		var obj Object
		if err := decodeObject(p.val, &obj); err != nil {
			// A corrupt record is logged and stepped over rather than failing
			// the listing: one unreadable object must not make a whole bucket
			// unlistable.
			slog.Warn("meta: corrupt object record", "key", key, "err", err)
			page.cursor.lastConsumed = key
			continue
		}
		if obj.State != "active" {
			page.cursor.lastConsumed = key
			continue
		}

		if page.delimiter != "" {
			rolled, full := page.rollUpCommonPrefix(key)
			if full {
				page.result.IsTruncated = true
				return true
			}
			if rolled {
				continue
			}
		}

		if *page.count >= page.maxKeys {
			page.result.IsTruncated = true
			return true
		}

		// Object is a value type, so it stays valid after the tx closed.
		page.result.Objects = append(page.result.Objects, obj)
		*page.count++
		page.cursor.lastConsumed = key
	}
	return false
}

// rollUpCommonPrefix folds a key into a CommonPrefix when the delimiter says it
// belongs to one.
//
// Reports whether the key was rolled up, and whether the page is now full. A key
// that lands in a prefix already emitted counts as consumed but does NOT count
// against maxKeys: the prefix is the entry, not each key beneath it.
func (p listPage) rollUpCommonPrefix(key string) (rolled, full bool) {
	rest := key[len(p.prefix):]
	idx := strings.Index(rest, p.delimiter)
	if idx < 0 {
		return false, false
	}

	commonPrefix := p.prefix + rest[:idx+len(p.delimiter)]
	if p.seenPrefixes[commonPrefix] {
		p.cursor.lastConsumed = key
		return true, false
	}
	if *p.count >= p.maxKeys {
		return false, true
	}

	p.seenPrefixes[commonPrefix] = true
	p.result.CommonPrefixes = append(p.result.CommonPrefixes, commonPrefix)
	*p.count++
	p.cursor.lastConsumed = key
	return true, false
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
		if err := decodeObject(data, &obj); err != nil {
			return err
		}
		wasActive := obj.State == "active"
		prevSize := obj.SizeBytes
		obj.State = "quarantined"
		obj.UpdatedAt = time.Now().UTC()
		updated, err := encodeObject(&obj)
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
			if err := decodeObject(v, &obj); err != nil {
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
		return decodeObject(data, &obj)
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
		if err := decodeObject(data, &obj); err != nil {
			return err
		}
		wasActive := obj.State == "active"
		obj.State = "active"
		obj.UpdatedAt = time.Now().UTC()
		updated, err := encodeObject(&obj)
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
			if err := decodeObject(v, &obj); err != nil {
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
