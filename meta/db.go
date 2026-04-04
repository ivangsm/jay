package meta

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketAccounts  = []byte("accounts")
	bucketBuckets   = []byte("buckets")
	bucketBucketsID = []byte("buckets_by_id")
	bucketTokens    = []byte("tokens")
	bucketSys       = []byte("sys")
)

func objectsBucketName(bucketID string) []byte {
	return []byte("obj:" + bucketID)
}

// DB wraps a bbolt database for Jay metadata.
type DB struct {
	bolt *bolt.DB
	path string
}

// Open opens or creates the bbolt database at the given path.
// It creates the parent directory if needed and bootstraps top-level buckets.
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("meta: create dir: %w", err)
	}

	b, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("meta: open db: %w", err)
	}

	db := &DB{bolt: b, path: path}
	if err := db.bootstrap(); err != nil {
		b.Close()
		return nil, err
	}
	return db, nil
}

// Close closes the underlying bbolt database.
func (db *DB) Close() error {
	return db.bolt.Close()
}

// Path returns the filesystem path of the database file.
func (db *DB) Path() string {
	return db.path
}

func (db *DB) bootstrap() error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketAccounts, bucketBuckets, bucketBucketsID, bucketTokens, bucketSys} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("meta: create bucket %s: %w", name, err)
			}
		}
		sys := tx.Bucket(bucketSys)
		if sys.Get([]byte("version")) == nil {
			if err := sys.Put([]byte("version"), []byte("1")); err != nil {
				return err
			}
			if err := sys.Put([]byte("initialized_at"), []byte(time.Now().UTC().Format(time.RFC3339))); err != nil {
				return err
			}
		}
		return nil
	})
}
