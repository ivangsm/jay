package maintenance

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

// multipartMaxAge is how long a multipart upload may stay inactive before its
// bbolt record and on-disk parts are reclaimed by the GC.
const multipartMaxAge = 24 * time.Hour

// GC performs garbage collection of orphaned files.
type GC struct {
	dataDir  string
	db       *meta.DB
	st       *store.Store
	log      *slog.Logger
	interval time.Duration
	quit     chan struct{}
	running  atomic.Bool

	// passes counts completed sweeps. It is the only observable that tells
	// "the loop ran and found nothing" apart from "the loop did not run", which
	// is exactly what the scheduling tests need to be able to assert.
	passes atomic.Int64

	// deleted is signalled (non-blocking send) by NotifyDeletion whenever an
	// object is deleted. The GC loop listens on this to run an immediate pass
	// instead of waiting the full interval.
	deleted chan struct{}

	FilesCollected atomic.Int64
}

// NewGC creates a garbage collector.
func NewGC(dataDir string, db *meta.DB, st *store.Store, log *slog.Logger, interval time.Duration) *GC {
	return &GC{
		dataDir:  dataDir,
		db:       db,
		st:       st,
		log:      log,
		interval: interval,
		quit:     make(chan struct{}),
		deleted:  make(chan struct{}, 1),
	}
}

// Start begins the periodic GC loop.
func (gc *GC) Start() {
	if !gc.running.CompareAndSwap(false, true) {
		return
	}
	go gc.loop()
}

// Stop signals the GC to stop.
func (gc *GC) Stop() {
	if gc.running.CompareAndSwap(true, false) {
		close(gc.quit)
	}
}

// Passes returns how many GC passes have completed since the process started.
func (gc *GC) Passes() int64 { return gc.passes.Load() }

// NotifyDeletion signals the GC that an object has been deleted. The GC loop
// is woken and performs an immediate pass. Non-blocking: if a prior signal is
// still pending, the new signal is coalesced into it.
func (gc *GC) NotifyDeletion() {
	select {
	case gc.deleted <- struct{}{}:
	default:
	}
}

func (gc *GC) loop() {
	// First run after a short delay
	timer := time.NewTimer(1 * time.Minute)
	defer timer.Stop()

	for {
		select {
		case <-gc.quit:
			return
		case <-timer.C:
			gc.RunOnce()
			timer.Reset(gc.interval)
		case <-gc.deleted:
			// Since Go 1.23 a Timer's channel is unbuffered: Stop() already
			// guarantees no stale value is left waiting, so the manual drain
			// that used to be here was a no-op.
			timer.Stop()
			gc.RunOnce()
			timer.Reset(gc.interval)
		}
	}
}

// RunOnce performs a single GC pass.
// It cleans up:
// 1. Old temp files (older than 1 hour)
// 2. Expired multipart uploads (bbolt record + on-disk parts)
// 3. Orphaned multipart part directories with no bbolt record
// 4. Empty bucket object directories
func (gc *GC) RunOnce() {
	defer gc.passes.Add(1)
	gc.cleanOldTempFiles()
	gc.cleanupExpiredUploads()
	gc.sweepOrphanMultipartDirs()
	gc.cleanEmptyDirs()
}

// cleanupExpiredUploads reclaims multipart uploads abandoned for longer than
// multipartMaxAge: the bbolt record is deleted and the on-disk parts under
// <dataDir>/multipart/<uploadID>/ are removed. Without this, an initiated
// upload that never completes leaks its parts and its record forever.
func (gc *GC) cleanupExpiredUploads() {
	expired, err := gc.db.CleanupExpiredUploads(multipartMaxAge)
	if err != nil {
		gc.log.Error("gc: cleanup expired multipart uploads", "err", err)
		return
	}
	if len(expired) == 0 {
		return
	}
	for _, u := range expired {
		if err := gc.st.CleanupUploadParts(u.UploadID); err != nil {
			// Best-effort: a leftover dir is picked up by
			// sweepOrphanMultipartDirs on a later pass.
			gc.log.Error("gc: remove multipart parts", "upload_id", u.UploadID, "err", err)
		}
	}
	gc.log.Info("gc: reclaimed expired multipart uploads", "count", len(expired))
}

// sweepOrphanMultipartDirs removes part directories under
// <dataDir>/multipart/ whose upload has no bbolt record and whose mtime is
// older than multipartMaxAge. This covers records deleted while the
// best-effort part cleanup failed (completed/aborted uploads pruned by
// CleanupExpiredUploads included). The age guard avoids racing an upload
// whose record is being created concurrently.
func (gc *GC) sweepOrphanMultipartDirs() {
	mpDir := filepath.Join(gc.dataDir, "multipart")
	entries, err := os.ReadDir(mpDir)
	if err != nil {
		// Directory may simply not exist yet (no multipart upload ever ran).
		return
	}

	cutoff := time.Now().Add(-multipartMaxAge)
	removed := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		if _, err := gc.db.GetMultipartUpload(e.Name()); !errors.Is(err, meta.ErrUploadNotFound) {
			// Record still exists (or a transient read error) — leave the
			// parts alone; cleanupExpiredUploads owns registered uploads.
			continue
		}
		if err := os.RemoveAll(filepath.Join(mpDir, e.Name())); err != nil {
			gc.log.Error("gc: remove orphan multipart dir", "upload_id", e.Name(), "err", err)
			continue
		}
		removed++
	}
	if removed > 0 {
		gc.log.Info("gc: removed orphan multipart part dirs", "count", removed)
	}
}

func (gc *GC) cleanOldTempFiles() {
	tmpDir := filepath.Join(gc.dataDir, "tmp")
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return
	}

	now := time.Now()
	// Completed temp files (no .writing suffix) are eligible after 1 hour.
	completedCutoff := now.Add(-1 * time.Hour)
	// Files still marked .writing are only deleted after 24 hours, as they
	// may belong to a slow but active upload. After 24 hours they are
	// considered truly abandoned.
	writingCutoff := now.Add(-24 * time.Hour)

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}

		name := e.Name()
		isWriting := strings.HasSuffix(name, ".writing")

		var cutoff time.Time
		if isWriting {
			cutoff = writingCutoff
		} else {
			cutoff = completedCutoff
		}

		if info.ModTime().Before(cutoff) {
			path := filepath.Join(tmpDir, name)
			if err := os.Remove(path); err == nil {
				gc.FilesCollected.Add(1)
				gc.log.Info("gc: removed stale temp file",
					"file", name,
					"age", now.Sub(info.ModTime()).Round(time.Second))
			}
		}
	}
}

func (gc *GC) cleanEmptyDirs() {
	// Empty objects/ subdirs are left in place: the bucket may still exist in
	// metadata and new objects may be written. Only bucket deletion (via API)
	// removes these directories. Removing them here would cause errors when the
	// store attempts to write objects to a bucket that still exists in meta.
}
