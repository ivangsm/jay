package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// PartPath returns the relative path for a multipart part.
func PartPath(uploadID string, partNumber int) string {
	return filepath.Join("multipart", uploadID, fmt.Sprintf("part-%05d", partNumber))
}

// WritePart writes a multipart part to disk with fsync.
// Returns the SHA-256 checksum, size, and location ref.
func (s *Store) WritePart(uploadID string, partNumber int, body io.Reader) (checksum string, size int64, locationRef string, err error) {
	locationRef = PartPath(uploadID, partNumber)
	finalPath := s.AbsPath(locationRef)

	if err = os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		return "", 0, "", fmt.Errorf("store: mkdir part: %w", err)
	}

	tmpFile, err := os.CreateTemp(filepath.Join(s.dataDir, "tmp"), "jay-part-*")
	if err != nil {
		return "", 0, "", fmt.Errorf("store: create temp part: %w", err)
	}
	tmpPath := tmpFile.Name()

	defer func() {
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	tee := io.TeeReader(body, h)
	size, err = io.Copy(tmpFile, tee)
	if err != nil {
		return "", 0, "", fmt.Errorf("store: write part: %w", err)
	}

	if err = tmpFile.Sync(); err != nil {
		return "", 0, "", fmt.Errorf("store: fsync part: %w", err)
	}
	if err = tmpFile.Close(); err != nil {
		return "", 0, "", fmt.Errorf("store: close part: %w", err)
	}

	checksum = hex.EncodeToString(h.Sum(nil))

	if err = os.Rename(tmpPath, finalPath); err != nil {
		return "", 0, "", fmt.Errorf("store: rename part: %w", err)
	}

	if err = fsyncDir(filepath.Dir(finalPath)); err != nil {
		return "", 0, "", fmt.Errorf("store: fsync part dir: %w", err)
	}

	return checksum, size, locationRef, nil
}

// AssembleParts concatenates parts into a final object file.
// Returns the SHA-256 checksum, total size, and location ref of the assembled object.
func (s *Store) AssembleParts(bucketID, objectID string, partLocations []string) (checksum string, size int64, locationRef string, err error) {
	tmpFile, err := os.CreateTemp(filepath.Join(s.dataDir, "tmp"), "jay-assemble-*")
	if err != nil {
		return "", 0, "", fmt.Errorf("store: create assemble temp: %w", err)
	}
	tmpPath := tmpFile.Name()

	defer func() {
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	w := io.MultiWriter(tmpFile, h)

	for _, loc := range partLocations {
		f, ferr := os.Open(s.AbsPath(loc))
		if ferr != nil {
			err = fmt.Errorf("store: open part %s: %w", loc, ferr)
			return
		}
		n, cerr := io.Copy(w, f)
		f.Close()
		if cerr != nil {
			err = fmt.Errorf("store: copy part %s: %w", loc, cerr)
			return
		}
		size += n
	}

	if err = tmpFile.Sync(); err != nil {
		return "", 0, "", fmt.Errorf("store: fsync assembled: %w", err)
	}
	if err = tmpFile.Close(); err != nil {
		return "", 0, "", fmt.Errorf("store: close assembled: %w", err)
	}

	checksum = hex.EncodeToString(h.Sum(nil))
	locationRef = ObjectPath(bucketID, objectID)
	finalPath := s.AbsPath(locationRef)

	if err = os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		return "", 0, "", fmt.Errorf("store: mkdir assembled: %w", err)
	}

	if err = os.Rename(tmpPath, finalPath); err != nil {
		return "", 0, "", fmt.Errorf("store: rename assembled: %w", err)
	}

	if err = fsyncDir(filepath.Dir(finalPath)); err != nil {
		return "", 0, "", fmt.Errorf("store: fsync assembled dir: %w", err)
	}

	return checksum, size, locationRef, nil
}

// CleanupUploadParts removes all part files for an upload.
func (s *Store) CleanupUploadParts(uploadID string) error {
	dir := filepath.Join(s.dataDir, "multipart", uploadID)
	return os.RemoveAll(dir)
}
