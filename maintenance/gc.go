package maintenance

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// GC performs garbage collection of orphaned files.
type GC struct {
	dataDir  string
	log      *slog.Logger
	interval time.Duration
	quit     chan struct{}
	running  atomic.Bool

	FilesCollected atomic.Int64
}

// NewGC creates a garbage collector.
func NewGC(dataDir string, log *slog.Logger, interval time.Duration) *GC {
	return &GC{
		dataDir:  dataDir,
		log:      log,
		interval: interval,
		quit:     make(chan struct{}),
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
		}
	}
}

// RunOnce performs a single GC pass.
// It cleans up:
// 1. Old temp files (older than 1 hour)
// 2. Empty bucket object directories
func (gc *GC) RunOnce() {
	gc.cleanOldTempFiles()
	gc.cleanEmptyDirs()
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
	// TODO: implement empty-bucket-dir GC.
	// Currently a no-op: an empty objects/ subdir does not imply the bucket is
	// gone — it may still exist in metadata — so we leave these directories
	// alone until we have a cross-check against the metadata DB.
}
