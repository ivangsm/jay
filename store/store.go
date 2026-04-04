package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ivangsm/jay/meta"
)

// Store manages physical object files on the filesystem.
type Store struct {
	dataDir string
}

// New creates a Store and ensures the required directory structure exists.
func New(dataDir string) (*Store, error) {
	for _, sub := range []string{"buckets", "quarantine", "tmp", "meta", "backups"} {
		if err := os.MkdirAll(filepath.Join(dataDir, sub), 0o755); err != nil {
			return nil, fmt.Errorf("store: create %s: %w", sub, err)
		}
	}
	return &Store{dataDir: dataDir}, nil
}

// ObjectPath returns the relative location_ref for a given bucket and object ID.
// Uses two-level hash directory: <bucket-id>/objects/<id[0:2]>/<id[2:4]>/<id>
func ObjectPath(bucketID, objectID string) string {
	return filepath.Join("buckets", bucketID, "objects", objectID[:2], objectID[2:4], objectID)
}

// AbsPath returns the absolute path for a location_ref.
func (s *Store) AbsPath(locationRef string) string {
	return filepath.Join(s.dataDir, locationRef)
}

// WriteObject streams body to a temp file, computes SHA-256, then atomically
// moves it to its final location. Returns checksum, size, and locationRef.
//
// The sequence ensures durability:
//  1. Write to temp file
//  2. fsync temp file
//  3. Rename to final path
//  4. fsync parent directory
func (s *Store) WriteObject(bucketID, objectID string, body io.Reader) (checksum string, size int64, locationRef string, err error) {
	// Create temp file in same filesystem for atomic rename
	tmpFile, err := os.CreateTemp(filepath.Join(s.dataDir, "tmp"), "jay-upload-*")
	if err != nil {
		return "", 0, "", fmt.Errorf("store: create temp: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Cleanup on error
	defer func() {
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
		}
	}()

	// Stream body through SHA-256 hasher
	h := sha256.New()
	tee := io.TeeReader(body, h)
	size, err = io.Copy(tmpFile, tee)
	if err != nil {
		return "", 0, "", fmt.Errorf("store: write temp: %w", err)
	}

	// fsync the temp file
	if err = tmpFile.Sync(); err != nil {
		return "", 0, "", fmt.Errorf("store: fsync temp: %w", err)
	}
	if err = tmpFile.Close(); err != nil {
		return "", 0, "", fmt.Errorf("store: close temp: %w", err)
	}

	checksum = hex.EncodeToString(h.Sum(nil))
	locationRef = ObjectPath(bucketID, objectID)
	finalPath := s.AbsPath(locationRef)

	// Ensure parent directory exists
	parentDir := filepath.Dir(finalPath)
	if err = os.MkdirAll(parentDir, 0o755); err != nil {
		return "", 0, "", fmt.Errorf("store: mkdir: %w", err)
	}

	// Atomic rename
	if err = os.Rename(tmpPath, finalPath); err != nil {
		return "", 0, "", fmt.Errorf("store: rename: %w", err)
	}

	// fsync parent directory to make the rename durable
	if err = fsyncDir(parentDir); err != nil {
		return "", 0, "", fmt.Errorf("store: fsync dir: %w", err)
	}

	return checksum, size, locationRef, nil
}

// ReadObject opens the file at locationRef for reading. Caller must close it.
func (s *Store) ReadObject(locationRef string) (*os.File, error) {
	f, err := os.Open(s.AbsPath(locationRef))
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	return f, nil
}

// DeleteObject removes the physical file at locationRef.
func (s *Store) DeleteObject(locationRef string) error {
	if err := os.Remove(s.AbsPath(locationRef)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("store: delete: %w", err)
	}
	return nil
}

// Quarantine moves a file from its location to the quarantine directory.
func (s *Store) Quarantine(locationRef string) error {
	src := s.AbsPath(locationRef)
	dst := filepath.Join(s.dataDir, "quarantine", filepath.Base(locationRef))
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("store: quarantine: %w", err)
	}
	return nil
}

// CleanTmp removes all files in the tmp directory.
func (s *Store) CleanTmp() (int, error) {
	tmpDir := filepath.Join(s.dataDir, "tmp")
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return 0, fmt.Errorf("store: read tmp: %w", err)
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(tmpDir, e.Name())); err != nil {
			return count, fmt.Errorf("store: clean tmp: %w", err)
		}
		count++
	}
	return count, nil
}

// EnsureBucketDir creates the objects directory for a bucket.
func (s *Store) EnsureBucketDir(bucketID string) error {
	dir := filepath.Join(s.dataDir, "buckets", bucketID, "objects")
	return os.MkdirAll(dir, 0o755)
}

// RemoveBucketDir removes the bucket's directory tree. Only call after confirming no objects remain.
func (s *Store) RemoveBucketDir(bucketID string) error {
	dir := filepath.Join(s.dataDir, "buckets", bucketID)
	return os.RemoveAll(dir)
}

// VerifyChecksum reads the file at locationRef and returns whether its SHA-256 matches expected.
func (s *Store) VerifyChecksum(locationRef, expected string) (bool, string, error) {
	f, err := os.Open(s.AbsPath(locationRef))
	if err != nil {
		return false, "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, "", err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	return actual == expected, actual, nil
}

// ListBucketFiles walks the bucket's objects directory and returns all object file paths (relative).
func (s *Store) ListBucketFiles(bucketID string) ([]string, error) {
	root := filepath.Join(s.dataDir, "buckets", bucketID, "objects")
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			rel, _ := filepath.Rel(s.dataDir, path)
			files = append(files, rel)
		}
		return nil
	})
	if os.IsNotExist(err) {
		return nil, nil
	}
	return files, err
}

// DataDir returns the root data directory.
func (s *Store) DataDir() string {
	return s.dataDir
}

// objectExists checks if a physical object file exists at the location ref within this store.
func (s *Store) ObjectExists(obj *meta.Object) bool {
	_, err := os.Stat(s.AbsPath(obj.LocationRef))
	return err == nil
}

func fsyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
