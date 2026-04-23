package meta

import (
	bolt "go.etcd.io/bbolt"
)

// MigrateLegacyObject rewrites a single object record from the legacy JSON
// format to the current binary envelope. Returns true if the record was
// actually rewritten, false if it was already in binary format, missing, or
// the bucket no longer exists.
//
// Designed to be called from the scrubber after a healthy checksum verify so
// we only persist re-encoded values for records we have just validated. A
// single write transaction per object keeps bbolt writer contention low; at
// the scrub throttle rates (default 10% / 6h) total migration finishes in a
// handful of cycles without a dedicated batch job.
//
// Does not touch bucket statistics — the record's logical content is
// unchanged, only its on-disk envelope.
func (db *DB) MigrateLegacyObject(bucketID, key string) (bool, error) {
	var migrated bool
	err := db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(objectsBucketName(bucketID))
		if bk == nil {
			return nil
		}
		raw := bk.Get([]byte(key))
		if len(raw) == 0 {
			return nil
		}
		if raw[0] == formatGob {
			return nil
		}
		var obj Object
		if err := decodeObject(raw, &obj); err != nil {
			return err
		}
		encoded, err := encodeObject(&obj)
		if err != nil {
			return err
		}
		if err := bk.Put([]byte(key), encoded); err != nil {
			return err
		}
		migrated = true
		return nil
	})
	return migrated, err
}
