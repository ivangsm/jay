// Package maintenance holds jay's background jobs: integrity scrubbing, garbage
// collection, verified metadata snapshots and the metrics they feed.
//
// All of them are best-effort and none may block serving traffic — but they
// report what they could not do rather than failing quietly.
//
// The snapshot job covers the metadata database and nothing else; see
// SnapshotCovers and SnapshotOmits for the exact scope and why it is spelled
// out rather than implied.
package maintenance

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/ivangsm/jay/meta"
)

// What the hourly snapshot does and does not contain, written down once so the
// log line, the readiness payload and the documentation cannot drift apart.
//
// This is the whole point of the pair: jay snapshots metadata and nothing else.
// Object bytes have no copy anywhere — no replication, no sync-out, no remote
// target — and jay has no object versioning either, so a PUT over an existing
// key destroys the previous bytes for good. Calling that "the backup" without
// qualification is a durability guarantee jay does not have, and an operator
// who believes it finds out during a restore, which is the worst possible
// moment.
//
// The recovery path for object bytes is external and documented in the
// backup-and-restore guide: copy buckets/ with an ordinary file-level tool,
// restore it BEFORE the metadata snapshot, and let startup recovery reconcile.
const (
	// SnapshotCovers names what a snapshot file actually holds.
	SnapshotCovers = "meta/jay.db (bbolt): accounts, buckets, object records, tokens, multipart state"

	// SnapshotOmits names what it does not, in the terms an operator uses.
	SnapshotOmits = "object bytes under buckets/ — jay keeps no copy of them; back that directory up separately"
)

// BackupManager snapshots the bbolt metadata database. It does not copy object
// bytes: see SnapshotCovers and SnapshotOmits.
type BackupManager struct {
	db        *meta.DB
	backupDir string
	log       *slog.Logger
}

// NewBackupManager creates a backup manager.
func NewBackupManager(db *meta.DB, backupDir, dataDir string, log *slog.Logger) *BackupManager {
	if _, err := EnsureBackupDir(dataDir, backupDir); err != nil {
		log.Error("create backup dir", "err", err, "path", backupDir)
	}
	return &BackupManager{db: db, backupDir: backupDir, log: log}
}

// EnsureBackupDir creates the snapshot directory and reports whether it ends up
// on the same filesystem as dataDir.
//
// Both answers come from one function because they are one decision. A snapshot
// written next to the database it is protecting survives a `rm -rf` of the
// wrong path and nothing else: the disk failure, the full volume and the lost
// instance all take the original and the copy together. The default
// (<data_dir>/backups) is exactly that case, so the caller warns about it at
// startup and the readiness probe reports it.
func EnsureBackupDir(dataDir, backupDir string) (sameFilesystem bool, err error) {
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return false, fmt.Errorf("backup: create dir %s: %w", backupDir, err)
	}
	return SameFilesystem(dataDir, backupDir)
}

// SameFilesystem reports whether two existing paths live on the same
// filesystem, comparing the device ID the kernel reports for each.
//
// It answers the question a mount point answers, not the one a path prefix
// answers: <data_dir>/backups with a separate volume mounted over it is a
// different filesystem despite being inside the data directory, and a bind
// mount elsewhere on the same disk is the same filesystem despite looking
// separate. A string comparison gets both of those backwards.
func SameFilesystem(a, b string) (bool, error) {
	devA, err := deviceOf(a)
	if err != nil {
		return false, err
	}
	devB, err := deviceOf(b)
	if err != nil {
		return false, err
	}
	return devA == devB, nil
}

// deviceOf returns the device ID of the filesystem holding path. The uint64
// conversion is what makes the comparison portable: syscall.Stat_t.Dev is
// uint64 on Linux and int32 on darwin, and both sides of the comparison go
// through the same conversion.
func deviceOf(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return uint64(st.Dev), nil
}

// Run creates a consistent snapshot of the bbolt database and verifies it.
// It uses the shared meta.DB handle's Backup method which runs inside a
// read transaction — no second bolt handle is opened. A snapshot that fails
// verification is deleted and reported as an error: a backup that cannot be
// restored is worse than no backup, because it silently satisfies retention.
//
// The snapshot holds metadata only. See SnapshotCovers and SnapshotOmits.
func (bm *BackupManager) Run() (string, error) {
	ts := time.Now().UTC().Format("20060102T150405Z")
	backupPath := filepath.Join(bm.backupDir, fmt.Sprintf("jay-%s.db", ts))

	f, err := os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("backup: create file: %w", err)
	}

	if err := bm.db.Backup(f); err != nil {
		_ = f.Close()
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("backup: write snapshot: %w", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("backup: fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("backup: close: %w", err)
	}

	result, err := bm.verifyAndCleanup(backupPath)
	if err != nil {
		return "", err
	}

	// The two scope fields are not decoration. "backup completed and verified"
	// on its own reads as a durability guarantee over everything jay stores,
	// and the object_records count sitting next to "no object bytes" is what
	// tells an operator which half of their data this line is about.
	bm.log.Info("metadata snapshot completed and verified",
		"path", backupPath,
		"object_records", result.ObjectCount,
		"covers", SnapshotCovers,
		"omits", SnapshotOmits,
	)
	return backupPath, nil
}

// verifyAndCleanup runs Verify on a freshly written backup. On failure the
// corrupt file is removed so it can never be mistaken for a restorable
// snapshot, and the error is both logged and returned.
func (bm *BackupManager) verifyAndCleanup(backupPath string) (*BackupVerifyResult, error) {
	result, err := bm.Verify(backupPath)
	if err != nil {
		bm.log.Error("metadata snapshot verification failed, removing corrupt snapshot",
			"path", backupPath, "err", err)
		if rmErr := os.Remove(backupPath); rmErr != nil {
			bm.log.Error("failed to remove corrupt snapshot", "path", backupPath, "err", rmErr)
		}
		return nil, fmt.Errorf("backup: verify: %w", err)
	}
	return result, nil
}

// Verify opens a backup file and checks that the required bbolt buckets exist
// and returns basic counts for validation.
//
// What it proves: the file opens as a bbolt database, the five required buckets
// are present, and the records inside can be walked. That is enough to reject a
// truncated or half-written snapshot, which is what it is for.
//
// What it does NOT prove, and cannot: that any of the ObjectCount records has
// bytes behind it. A snapshot is a copy of the metadata file and has no view of
// the filesystem. ObjectCount is a count of records, not of recoverable
// objects — restoring this file over an empty buckets/ directory yields an
// installation where startup recovery quarantines every one of them.
func (bm *BackupManager) Verify(backupPath string) (*BackupVerifyResult, error) {
	db, err := bolt.Open(backupPath, 0o600, &bolt.Options{
		ReadOnly: true,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("verify: open: %w", err)
	}
	defer func() { _ = db.Close() }()

	result := &BackupVerifyResult{}

	err = db.View(func(tx *bolt.Tx) error {
		// Check required buckets exist
		for _, name := range []string{"accounts", "buckets", "buckets_by_id", "tokens", "sys"} {
			if tx.Bucket([]byte(name)) == nil {
				return fmt.Errorf("verify: missing bucket %q", name)
			}
		}

		// Count buckets
		bk := tx.Bucket([]byte("buckets"))
		if err := bk.ForEach(func(k, v []byte) error {
			result.BucketCount++
			return nil
		}); err != nil {
			return fmt.Errorf("verify: count buckets: %w", err)
		}

		// Count tokens
		tk := tx.Bucket([]byte("tokens"))
		if err := tk.ForEach(func(k, v []byte) error {
			result.TokenCount++
			return nil
		}); err != nil {
			return fmt.Errorf("verify: count tokens: %w", err)
		}

		// Count objects across all obj: buckets
		if err := tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			if len(name) > 4 && string(name[:4]) == "obj:" {
				if err := b.ForEach(func(k, v []byte) error {
					result.ObjectCount++
					return nil
				}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("verify: count objects: %w", err)
		}

		// Check version
		sys := tx.Bucket([]byte("sys"))
		if v := sys.Get([]byte("version")); v != nil {
			result.Version = string(v)
		}

		return nil
	})

	return result, err
}

// BackupVerifyResult contains the results of verifying a backup.
type BackupVerifyResult struct {
	Version     string
	BucketCount int
	// ObjectCount is how many object RECORDS the snapshot holds. It says
	// nothing about how many of them still have bytes on disk — see Verify.
	ObjectCount int
	TokenCount  int
}

// Prune removes backups older than the given retention period, keeping at least minKeep.
func (bm *BackupManager) Prune(retention time.Duration, minKeep int) (int, error) {
	entries, err := os.ReadDir(bm.backupDir)
	if err != nil {
		return 0, fmt.Errorf("prune: read dir: %w", err)
	}

	type backupFile struct {
		path    string
		modTime time.Time
	}

	var backups []backupFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, backupFile{
			path:    filepath.Join(bm.backupDir, e.Name()),
			modTime: info.ModTime(),
		})
	}

	if len(backups) <= minKeep {
		return 0, nil
	}

	cutoff := time.Now().Add(-retention)
	removed := 0
	// Keep at least minKeep most recent
	removable := len(backups) - minKeep
	for _, b := range backups {
		if removable <= 0 {
			break
		}
		if b.modTime.Before(cutoff) {
			if err := os.Remove(b.path); err == nil {
				removed++
				removable--
				bm.log.Info("pruned backup", "path", b.path)
			}
		}
	}

	return removed, nil
}
