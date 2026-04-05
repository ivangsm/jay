package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/ivangsm/jay/meta"
)

// errInvalidLocationRef is returned when a location ref contains path traversal
// sequences, null bytes, or resolves outside the data directory.
var errInvalidLocationRef = fmt.Errorf("store: invalid location ref")

// validateLocationRef checks that locationRef is safe to use as a sub-path
// under s.dataDir. It rejects null bytes, ".." components, and any path that
// would escape the data directory after cleaning.
func (s *Store) validateLocationRef(locationRef string) error {
	if strings.ContainsRune(locationRef, 0) {
		return errInvalidLocationRef
	}
	if strings.Contains(locationRef, "..") {
		return errInvalidLocationRef
	}
	cleaned := filepath.Join(s.dataDir, filepath.Clean(locationRef))
	if !strings.HasPrefix(cleaned, filepath.Clean(s.dataDir)+string(filepath.Separator)) {
		return errInvalidLocationRef
	}
	return nil
}

// SafePath validates locationRef and returns the absolute path. It should be
// used instead of AbsPath whenever locationRef originates from untrusted or
// externally-stored input.
func (s *Store) SafePath(locationRef string) (string, error) {
	if err := s.validateLocationRef(locationRef); err != nil {
		return "", err
	}
	return filepath.Join(s.dataDir, locationRef), nil
}

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
// Deprecated: AbsPath does not validate the locationRef. Use SafePath for
// untrusted input to prevent path traversal attacks.
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
	// Create temp file in same filesystem for atomic rename.
	// The .writing suffix signals to GC that this file is actively being written.
	tmpFile, err := os.CreateTemp(filepath.Join(s.dataDir, "tmp"), "jay-upload-*.writing")
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

	// Remove .writing suffix to signal that the write is complete and the file
	// is ready for rename. This makes the file eligible for GC cleanup if the
	// final rename below fails and the temp file becomes orphaned.
	readyPath := strings.TrimSuffix(tmpPath, ".writing")
	if err = os.Rename(tmpPath, readyPath); err != nil {
		return "", 0, "", fmt.Errorf("store: mark temp ready: %w", err)
	}
	tmpPath = readyPath

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
	p, err := s.SafePath(locationRef)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	return f, nil
}

// DeleteObject removes the physical file at locationRef.
func (s *Store) DeleteObject(locationRef string) error {
	p, err := s.SafePath(locationRef)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("store: delete: %w", err)
	}
	return nil
}

// Quarantine moves a file from its location to the quarantine directory.
func (s *Store) Quarantine(locationRef string) error {
	src, err := s.SafePath(locationRef)
	if err != nil {
		return err
	}
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

// EnsureBucketDir creates the objects directory for a bucket and fsyncs the
// parent to ensure the directory entry is durable.
func (s *Store) EnsureBucketDir(bucketID string) error {
	dir := filepath.Join(s.dataDir, "buckets", bucketID, "objects")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return fsyncDir(filepath.Join(s.dataDir, "buckets", bucketID))
}

// RemoveBucketDir removes the bucket's directory tree. Only call after confirming no objects remain.
func (s *Store) RemoveBucketDir(bucketID string) error {
	dir := filepath.Join(s.dataDir, "buckets", bucketID)
	return os.RemoveAll(dir)
}

// VerifyChecksum reads the file at locationRef and returns whether its SHA-256 matches expected.
func (s *Store) VerifyChecksum(locationRef, expected string) (bool, string, error) {
	p, err := s.SafePath(locationRef)
	if err != nil {
		return false, "", err
	}
	f, err := os.Open(p)
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

// Cleanup safely removes the file at locationRef, logging but not propagating
// errors. It is intended for best-effort cleanup when a subsequent operation
// (e.g. metadata commit) fails after a successful write.
func (s *Store) Cleanup(locationRef string) {
	if err := s.DeleteObject(locationRef); err != nil {
		slog.Warn("store: cleanup failed", "location", locationRef, "err", err)
	}
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

// fsyncDir fsyncs a directory to ensure rename/unlink operations are durable.
// Note: On macOS, directory fsync is a no-op. Full durability guarantees
// only apply on Linux with ext4/xfs filesystems.
func fsyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
