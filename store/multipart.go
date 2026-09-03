// Package store owns object bytes on disk.
//
// Every write is atomic — temp file, fsync, rename, fsync the directory — and
// carries a SHA-256 checksum, which is what lets the scrubber tell silent
// corruption from a healthy object. Metadata lives in package meta and refers to
// files here only by LocationRef.
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
//
// Equivalent to WritePartVerified with no verifier.
func (s *Store) WritePart(uploadID string, partNumber int, body io.Reader) (checksum string, size int64, locationRef string, err error) {
	return s.WritePartVerified(uploadID, partNumber, body, nil)
}

// WritePartVerified behaves like WritePart but calls verify (when non-nil)
// between the fsync and the rename. See WriteVerifier.
//
// Aborting before the rename matters more here than it does for a whole object:
// the part path is derived from the part number, so a re-upload of part N lands
// on the file part N already occupies. Refusing after the rename would have
// destroyed the previously accepted part while its metadata still pointed at it.
func (s *Store) WritePartVerified(uploadID string, partNumber int, body io.Reader, verify WriteVerifier) (checksum string, size int64, locationRef string, err error) {
	locationRef = PartPath(uploadID, partNumber)
	finalPath, err := s.SafePath(locationRef)
	if err != nil {
		return "", 0, "", err
	}

	if err = os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		return "", 0, "", fmt.Errorf("store: mkdir part: %w", err)
	}

	// The .writing suffix signals to GC that this file is actively being written.
	tmpFile, err := os.CreateTemp(filepath.Join(s.dataDir, "tmp"), "jay-part-*.writing")
	if err != nil {
		return "", 0, "", fmt.Errorf("store: create temp part: %w", err)
	}
	tmpPath := tmpFile.Name()

	defer func() {
		if err != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	tee := io.TeeReader(body, h)
	size, err = io.Copy(tmpFile, tee)
	if err != nil {
		return "", 0, "", fmt.Errorf("store: write part: %w", err)
	}

	if err = tmpFile.Sync(); err != nil {
		s.reportFsyncErr(err)
		return "", 0, "", fmt.Errorf("store: fsync part: %w", err)
	}
	if err = tmpFile.Close(); err != nil {
		return "", 0, "", fmt.Errorf("store: close part: %w", err)
	}

	checksum = hex.EncodeToString(h.Sum(nil))

	// Refuse before the rename: the final part path may already hold a part
	// that was accepted, and this one has not earned the right to replace it.
	if verify != nil {
		if err = verify(checksum, size); err != nil {
			return "", 0, "", err
		}
	}

	// Atomic rename directly from the .writing temp to the final part path.
	if err = os.Rename(tmpPath, finalPath); err != nil {
		return "", 0, "", fmt.Errorf("store: rename part: %w", err)
	}
	tmpPath = finalPath

	if err = fsyncDir(filepath.Dir(finalPath)); err != nil {
		s.reportFsyncErr(err)
		return "", 0, "", fmt.Errorf("store: fsync part dir: %w", err)
	}

	return checksum, size, locationRef, nil
}

// AssembleParts concatenates parts into a final object file and returns its
// SHA-256 checksum, total size and location ref.
//
// The results are named because the cleanup defer reads `err` to decide whether
// to remove the half-written temp file: on any failure the partial assembly is
// deleted rather than left behind for the GC to guess at.
func (s *Store) AssembleParts(bucketID, objectID string, partLocations []string) (checksum string, size int64, locationRef string, err error) {
	// The .writing suffix signals to GC that this file is actively being written.
	tmpFile, err := os.CreateTemp(filepath.Join(s.dataDir, "tmp"), "jay-assemble-*.writing")
	if err != nil {
		return "", 0, "", fmt.Errorf("store: create assemble temp: %w", err)
	}
	tmpPath := tmpFile.Name()

	defer func() {
		if err != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	w := io.MultiWriter(tmpFile, h)

	for _, loc := range partLocations {
		partPath, verr := s.SafePath(loc)
		if verr != nil {
			err = fmt.Errorf("store: invalid part location %s: %w", loc, verr)
			return "", 0, "", err
		}
		f, ferr := os.Open(partPath)
		if ferr != nil {
			err = fmt.Errorf("store: open part %s: %w", loc, ferr)
			return "", 0, "", err
		}
		n, cerr := io.Copy(w, f)
		_ = f.Close()
		if cerr != nil {
			err = fmt.Errorf("store: copy part %s: %w", loc, cerr)
			return "", 0, "", err
		}
		size += n
	}

	if err = tmpFile.Sync(); err != nil {
		s.reportFsyncErr(err)
		return "", 0, "", fmt.Errorf("store: fsync assembled: %w", err)
	}
	if err = tmpFile.Close(); err != nil {
		return "", 0, "", fmt.Errorf("store: close assembled: %w", err)
	}

	checksum = hex.EncodeToString(h.Sum(nil))
	locationRef = ObjectPath(bucketID, objectID)
	finalPath, err := s.SafePath(locationRef)
	if err != nil {
		return "", 0, "", err
	}

	if err = os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		return "", 0, "", fmt.Errorf("store: mkdir assembled: %w", err)
	}

	// Atomic rename directly from the .writing temp to the final object path.
	if err = os.Rename(tmpPath, finalPath); err != nil {
		return "", 0, "", fmt.Errorf("store: rename assembled: %w", err)
	}
	tmpPath = finalPath

	if err = fsyncDir(filepath.Dir(finalPath)); err != nil {
		s.reportFsyncErr(err)
		return "", 0, "", fmt.Errorf("store: fsync assembled dir: %w", err)
	}

	return checksum, size, locationRef, nil
}

// CleanupUploadParts removes all part files for an upload.
func (s *Store) CleanupUploadParts(uploadID string) error {
	dir := filepath.Join(s.dataDir, "multipart", uploadID)
	return os.RemoveAll(dir)
}
