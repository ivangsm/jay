package meta

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketAccounts  = []byte("accounts")
	bucketBuckets   = []byte("buckets")
	bucketBucketsID = []byte("buckets_by_id")
	bucketTokens    = []byte("tokens")
	bucketSys       = []byte("sys")

	// Nested buckets under bucketSys.
	sysBucketStats         = []byte("bucket_stats")
	sysAccountBucketCount  = []byte("account_bucket_count")
)

func objectsBucketName(bucketID string) []byte {
	return []byte("obj:" + bucketID)
}

// DB wraps a bbolt database for Jay metadata.
type DB struct {
	bolt *bolt.DB
	path string

	kekMu  sync.RWMutex
	kekSet bool
	kek    [32]byte
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
		_ = b.Close()
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

// Backup writes a consistent hot copy of the bbolt database to w using the
// existing handle. It runs inside a read transaction, so callers do not need
// to (and must not) open a second bolt handle on the same file.
func (db *DB) Backup(w io.Writer) error {
	return db.bolt.View(func(tx *bolt.Tx) error {
		if _, err := tx.WriteTo(w); err != nil {
			return fmt.Errorf("meta: backup: %w", err)
		}
		return nil
	})
}

func (db *DB) bootstrap() error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bucketAccounts, bucketBuckets, bucketBucketsID, bucketTokens, bucketSys} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("meta: create bucket %s: %w", name, err)
			}
		}
		sys := tx.Bucket(bucketSys)
		if _, err := sys.CreateBucketIfNotExists(sysBucketStats); err != nil {
			return fmt.Errorf("meta: create sys/bucket_stats: %w", err)
		}
		if _, err := sys.CreateBucketIfNotExists(sysAccountBucketCount); err != nil {
			return fmt.Errorf("meta: create sys/account_bucket_count: %w", err)
		}
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
