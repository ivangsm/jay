package maintenance

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// BackupManager handles consistent backups of the bbolt database.
type BackupManager struct {
	dbPath    string
	backupDir string
	log       *slog.Logger
}

// NewBackupManager creates a backup manager.
func NewBackupManager(dbPath, backupDir string, log *slog.Logger) *BackupManager {
	os.MkdirAll(backupDir, 0o755)
	return &BackupManager{dbPath: dbPath, backupDir: backupDir, log: log}
}

// Run creates a consistent snapshot of the bbolt database.
// It opens the DB in read-only mode and uses bbolt's View transaction
// to get a consistent snapshot, then writes it to a timestamped file.
func (bm *BackupManager) Run() (string, error) {
	db, err := bolt.Open(bm.dbPath, 0o600, &bolt.Options{
		ReadOnly: true,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		return "", fmt.Errorf("backup: open db: %w", err)
	}
	defer db.Close()

	ts := time.Now().UTC().Format("20060102T150405Z")
	backupPath := filepath.Join(bm.backupDir, fmt.Sprintf("jay-%s.db", ts))

	f, err := os.Create(backupPath)
	if err != nil {
		return "", fmt.Errorf("backup: create file: %w", err)
	}

	err = db.View(func(tx *bolt.Tx) error {
		_, err := tx.WriteTo(f)
		return err
	})
	if err != nil {
		f.Close()
		os.Remove(backupPath)
		return "", fmt.Errorf("backup: write snapshot: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
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
	defer db.Close()

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
		bk.ForEach(func(k, v []byte) error {
			result.BucketCount++
			return nil
		})

		// Count tokens
		tk := tx.Bucket([]byte("tokens"))
		tk.ForEach(func(k, v []byte) error {
			result.TokenCount++
			return nil
		})

		// Count objects across all obj: buckets
		tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			if len(name) > 4 && string(name[:4]) == "obj:" {
				b.ForEach(func(k, v []byte) error {
					result.ObjectCount++
					return nil
				})
			}
			return nil
		})

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
	db, err := bolt.Open(bm.dbPath, 0o600, &bolt.Options{
		ReadOnly: true,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("backup: open db: %w", err)
	}
	defer db.Close()

	return db.View(func(tx *bolt.Tx) error {
		_, err := tx.WriteTo(w)
		return err
	})
}
