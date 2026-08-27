package main

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"net/http"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ivangsm/jay/meta"
)

// dbPingTimeout bounds the readiness bbolt check. A View on bbolt is normally
// microseconds; anything that takes longer than this means the database is
// wedged (stuck mmap remap, hung write transaction holding the meta lock) and
// the instance must stop receiving traffic.
const dbPingTimeout = 2 * time.Second

// HealthChecker provides liveness and readiness probes.
type HealthChecker struct {
	ready atomic.Bool
	db    *meta.DB

	// dataDir is the filesystem whose free space is checked for readiness.
	dataDir string
	// minFreeBytes is the readiness threshold for free space on the dataDir
	// filesystem. 0 (or negative) disables the check.
	minFreeBytes int64
}

// NewHealthChecker creates a new HealthChecker (not ready by default).
func NewHealthChecker(db *meta.DB, dataDir string, minFreeBytes int64) *HealthChecker {
	return &HealthChecker{db: db, dataDir: dataDir, minFreeBytes: minFreeBytes}
}

// SetReady marks the service as ready to accept traffic.
func (hc *HealthChecker) SetReady(v bool) {
	hc.ready.Store(v)
}

// LivenessHandler always returns 200 — the process is alive.
func (hc *HealthChecker) LivenessHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// A write failure is no longer actionable here: the headers are already out
	// and the prober will mark the check failed on its own. There is also no
	// logger at this point.
	_ = jsonv2.MarshalWrite(w, map[string]string{"status": "alive"})
}

// ReadinessHandler returns 200 if ready, 503 with a specific reason if not.
// Beyond the startup flag it verifies that bbolt still answers a read
// transaction and that the data filesystem has free space — a full disk or a
// hung database must take the instance out of rotation, not keep serving 200.
func (hc *HealthChecker) ReadinessHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if reason := hc.readinessProblem(); reason != "" {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = jsonv2.MarshalWrite(w, map[string]string{"status": "not_ready", "reason": reason})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = jsonv2.MarshalWrite(w, map[string]string{"status": "ready"})
}

// readinessProblem returns "" when the service is ready to accept traffic, or
// a human-readable reason otherwise.
func (hc *HealthChecker) readinessProblem() string {
	if !hc.ready.Load() {
		return "recovery in progress"
	}
	if err := hc.pingDB(dbPingTimeout); err != nil {
		return "metadata db check failed: " + err.Error()
	}
	if err := hc.checkFreeSpace(); err != nil {
		return err.Error()
	}
	return ""
}

// pingDB runs a cheap read transaction against bbolt bounded by a deadline.
// meta.DB does not expose the raw bolt handle, so BucketStats — an O(1) View
// over the maintained stats counter — doubles as a no-op ping. bbolt has no
// context support, hence the goroutine+channel timeout; the buffered channel
// lets a late-returning View finish without leaking the goroutine forever.
func (hc *HealthChecker) pingDB(timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		_, _, err := hc.db.BucketStats("_readiness_ping")
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("read transaction timed out after %s", timeout)
	}
}

// checkFreeSpace fails when the filesystem backing dataDir has less than
// minFreeBytes available to unprivileged writes. bbolt appends pages and the
// store writes temp files on every upload; running the disk to zero corrupts
// neither but turns every write into an error — better to shed traffic first.
func (hc *HealthChecker) checkFreeSpace() error {
	if hc.minFreeBytes <= 0 {
		return nil
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(hc.dataDir, &st); err != nil {
		return fmt.Errorf("statfs %s: %w", hc.dataDir, err)
	}
	// Bavail/Bsize have different widths across darwin/linux; convert both.
	free := uint64(st.Bavail) * uint64(st.Bsize)
	if free < uint64(hc.minFreeBytes) {
		return fmt.Errorf("low disk space on %s: %d bytes free, need at least %d", hc.dataDir, free, hc.minFreeBytes)
	}
	return nil
}
