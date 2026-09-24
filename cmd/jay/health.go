package main

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"net/http"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ivangsm/jay/maintenance"
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

	// durability is what this instance actually protects, reported on every
	// readiness response. It is fixed at construction, so the handler needs no
	// synchronisation.
	durability Durability
}

// Durability is the readiness probe's answer to "what of my data does this
// instance have a recovery path for". It is on the probe, not only in the
// documentation, because the probe is where an operator looks during an
// incident. Every field is a statement jay can back up: metadata has an hourly
// verified snapshot, object bytes have nothing.
type Durability struct {
	// MetadataBackup describes the hourly snapshot in one line.
	MetadataBackup string `json:"metadata_backup"`
	// ObjectBytesBackup is deliberately a sentence and not a boolean: a
	// `false` in a health payload gets read as "not enabled yet".
	ObjectBytesBackup string `json:"object_bytes_backup"`
	// MetadataBackupDir is where the snapshots land.
	MetadataBackupDir string `json:"metadata_backup_dir"`
	// SharesDataFilesystem is true when those snapshots sit on the same
	// filesystem as the database they protect — the default, and the case where
	// one disk failure takes both.
	SharesDataFilesystem bool `json:"metadata_backup_shares_data_filesystem"`
	// Problem, when non-empty, says the check above could not be run. In that
	// case SharesDataFilesystem holds the conservative answer (true), not a
	// measured one: an unanswerable question about whether a backup is isolated
	// must not come back as the reassuring answer.
	Problem string `json:"metadata_backup_dir_problem,omitempty"`
}

// NewHealthChecker creates a new HealthChecker (not ready by default).
func NewHealthChecker(db *meta.DB, dataDir string, minFreeBytes int64, durability Durability) *HealthChecker {
	return &HealthChecker{
		db:           db,
		dataDir:      dataDir,
		minFreeBytes: minFreeBytes,
		durability:   durability,
	}
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

// readinessResponse is the readiness payload. Reason is present only on a 503;
// Durability is present always, because the question it answers ("is my data
// recoverable") does not become relevant only once something is broken.
type readinessResponse struct {
	Status     string     `json:"status"`
	Reason     string     `json:"reason,omitempty"`
	Durability Durability `json:"durability"`
}

// ReadinessHandler returns 200 if ready, 503 with a specific reason if not.
// Beyond the startup flag it verifies that bbolt still answers a read
// transaction and that the data filesystem has free space — a full disk or a
// hung database must take the instance out of rotation, not keep serving 200.
//
// The durability block never changes the status code. Object bytes having no
// backup is a property of jay's design, not a fault of this instance: failing
// readiness over it would take a perfectly healthy server out of the pool
// forever. It is reported, not enforced.
func (hc *HealthChecker) ReadinessHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if reason := hc.readinessProblem(); reason != "" {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = jsonv2.MarshalWrite(w, readinessResponse{
			Status: "not_ready", Reason: reason, Durability: hc.durability,
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = jsonv2.MarshalWrite(w, readinessResponse{Status: "ready", Durability: hc.durability})
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
	free, err := hc.freeBytes()
	if err != nil {
		return err
	}
	if free < uint64(hc.minFreeBytes) {
		return fmt.Errorf("low disk space on %s: %d bytes free, need at least %d", hc.dataDir, free, hc.minFreeBytes)
	}
	return nil
}

// freeBytes is the space on the dataDir filesystem available to unprivileged
// writes — the space jay can actually use.
func (hc *HealthChecker) freeBytes() (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(hc.dataDir, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", hc.dataDir, err)
	}
	// Bavail/Bsize have different widths across darwin/linux; convert both.
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

// MetricFamilies exposes the two readiness checks as Prometheus gauges, run
// fresh on every scrape: one statfs and one bbolt read transaction, the same
// work a readiness probe does, bounded by the same timeout. Nothing is cached,
// so a scrape never reports a disk or a database that has since changed.
//
// A check that cannot produce a reading leaves its gauge out rather than
// exporting a number that would lie. That is why the bbolt check comes as a
// pair: jay_metadata_db_up says whether the read transaction completed, and
// the latency is exported only when it did — a transaction that errors out
// instantly is not a fast database.
func (hc *HealthChecker) MetricFamilies() []maintenance.MetricFamily {
	start := time.Now()
	pingErr := hc.pingDB(dbPingTimeout)
	elapsed := time.Since(start)

	up := 0.0
	if pingErr == nil {
		up = 1
	}
	families := []maintenance.MetricFamily{
		maintenance.Gauge("jay_metadata_db_up",
			"1 when a read transaction on the metadata database (bbolt) completed within the readiness timeout during this scrape, 0 when it did not.",
			up),
	}
	if pingErr == nil {
		families = append(families, maintenance.Gauge("jay_metadata_db_ping_seconds",
			"How long that read transaction took. Absent when it failed.",
			elapsed.Seconds()))
	}
	if free, err := hc.freeBytes(); err == nil {
		families = append(families, maintenance.Gauge("jay_data_dir_free_bytes",
			"Bytes available to jay on the filesystem holding JAY_DATA_DIR. Readiness fails below JAY_MIN_FREE_BYTES. Absent when the filesystem cannot be read.",
			float64(free)))
	}
	return families
}
