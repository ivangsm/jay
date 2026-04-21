package maintenance

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/ivangsm/jay/meta"
)

// BackupManager handles consistent backups of the bbolt database.
type BackupManager struct {
	db        *meta.DB
	backupDir string
	log       *slog.Logger
}

// NewBackupManager creates a backup manager.
func NewBackupManager(db *meta.DB, backupDir string, log *slog.Logger) *BackupManager {
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		log.Error("create backup dir", "err", err, "path", backupDir)
	}
	return &BackupManager{db: db, backupDir: backupDir, log: log}
}

// Run creates a consistent snapshot of the bbolt database.
// It uses the shared meta.DB handle's Backup method which runs inside a
// read transaction — no second bolt handle is opened.
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

	bm.log.Info("backup completed", "path", backupPath)
	return backupPath, nil
}

// Verify opens a backup file and checks that the required bbolt buckets exist
// and returns basic counts for validation.
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

// BackupToWriter writes a consistent bbolt snapshot to the given writer.
// Useful for streaming backups over HTTP.
func (bm *BackupManager) BackupToWriter(w io.Writer) error {
	return bm.db.Backup(w)
}
