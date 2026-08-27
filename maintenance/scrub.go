package maintenance

import (
	"log/slog"
	"maps"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
	"golang.org/x/time/rate"
)

// ScrubResult contains the results of a scrub run.
type ScrubResult struct {
	Checked     int
	Healthy     int
	Quarantined int
	Missing     int
	Errors      int
	// Migrated counts healthy records whose on-disk envelope was rewritten
	// from the legacy JSON format to the current binary codec during this
	// pass. Non-fatal: migration errors are logged and counted as Errors
	// rather than failing the scrub.
	Migrated int
}

// ScrubCoverage reports incremental scrub progress.
type ScrubCoverage struct {
	TotalChecked int64  `json:"total_checked"`
	LastFullScan string `json:"last_full_scan,omitempty"`
	InProgress   bool   `json:"in_progress"`
}

// Scrubber performs periodic integrity checks on stored objects.
type Scrubber struct {
	db       *meta.DB
	store    *store.Store
	log      *slog.Logger
	interval time.Duration
	quit     chan struct{}
	running  atomic.Bool

	// bytesLimiter throttles scrub read bandwidth to avoid starving
	// production reads. nil = unlimited.
	bytesLimiter *rate.Limiter

	// metrics is an optional sink for ChecksumFailures / ObjectsQuarantined.
	// Set via SetMetrics before Start; nil = no metrics recorded.
	metrics *Metrics

	mu           sync.Mutex
	lastKey      map[string]string // bucketID -> last checked key
	totalChecked int64
	lastFullScan time.Time
	maxPerRun    int
}

// NewScrubber creates a new scrubber.
// scrubBytesPerSec bounds checksum-read bandwidth; <=0 disables the limiter.
// maxPerRun bounds how many objects per bucket are inspected on each tick;
// <=0 falls back to 100.
func NewScrubber(db *meta.DB, st *store.Store, log *slog.Logger, interval time.Duration, scrubBytesPerSec int64, maxPerRun int) *Scrubber {
	if maxPerRun <= 0 {
		maxPerRun = 100
	}
	var limiter *rate.Limiter
	if scrubBytesPerSec > 0 {
		// Burst of 50 MiB gives headroom for a single large object read.
		burst := max(scrubBytesPerSec, int64(50<<20))
		limiter = rate.NewLimiter(rate.Limit(scrubBytesPerSec), int(burst))
	}
	return &Scrubber{
		db:           db,
		store:        st,
		log:          log,
		interval:     interval,
		bytesLimiter: limiter,
		quit:         make(chan struct{}),
		lastKey:      make(map[string]string),
		maxPerRun:    maxPerRun,
	}
}

// SetMetrics attaches a metrics sink to the scrubber. Nil-safe (nil simply
// disables metric recording). Call before Start; the field is read from
// scrub goroutines without synchronization, so it must not be swapped while
// the scrubber is running.
func (s *Scrubber) SetMetrics(m *Metrics) {
	s.metrics = m
}

// recordChecksumFailure increments the checksum-failure counter if a metrics
// sink is attached.
func (s *Scrubber) recordChecksumFailure() {
	if s.metrics != nil {
		s.metrics.ChecksumFailures.Add(1)
	}
}

// recordQuarantine increments the quarantine counter if a metrics sink is
// attached.
func (s *Scrubber) recordQuarantine() {
	if s.metrics != nil {
		s.metrics.ObjectsQuarantined.Add(1)
	}
}

// Start begins the periodic scrub loop in the background.
func (s *Scrubber) Start() {
	if !s.running.CompareAndSwap(false, true) {
		return
	}
	go s.loop()
}

// Stop signals the scrubber to stop and waits for it.
func (s *Scrubber) Stop() {
	if s.running.CompareAndSwap(true, false) {
		close(s.quit)
	}
}

func (s *Scrubber) loop() {
	// Run first scrub after a short delay
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-s.quit:
			return
		case <-timer.C:
			result := s.RunIncremental(s.maxPerRun)
			s.log.Info("incremental scrub completed",
				"checked", result.Checked,
				"healthy", result.Healthy,
				"quarantined", result.Quarantined,
				"missing", result.Missing,
				"errors", result.Errors,
				"migrated", result.Migrated,
			)
			timer.Reset(s.interval)
		}
	}
}

// RunIncremental checks up to maxPerRun objects per bucket, starting from
// where the last run left off. When a bucket is fully scanned the cursor
// wraps around. Once all buckets wrap, lastFullScan is updated.
// Buckets are processed in parallel using a bounded worker pool.
// bucketScrubResult is what scrubbing one bucket produced, before the results
// of all buckets are folded together under the lock.
type bucketScrubResult struct {
	partial     ScrubResult
	bucketID    string
	lastVisited string
	wrapped     bool
	iterErr     bool
}

// quarantineAction is an object the scrub decided to pull out of service, and
// why: a checksum mismatch also quarantines the file on disk, a missing file has
// no file left to quarantine.
type quarantineAction struct {
	key         string
	locationRef string
	isMismatch  bool
}

// RunIncremental scrubs up to maxPerRun objects per bucket, resuming each bucket
// from where the previous run left off.
//
// Coverage is therefore `maxPerRun × buckets` per tick, not a percentage: how
// long a full pass takes depends on the largest bucket. When every bucket has
// wrapped around, last_full_scan is stamped.
//
// Buckets are scrubbed in parallel, bounded by NumCPU. The semaphore is taken by
// the dispatching loop rather than inside each goroutine, so the loop itself
// blocks and there are never more than NumCPU buckets in flight.
func (s *Scrubber) RunIncremental(maxPerRun int) ScrubResult {
	var result ScrubResult

	buckets, err := s.db.ListBuckets("")
	if err != nil {
		s.log.Error("incremental scrub: list buckets", "err", err)
		result.Errors++
		return result
	}

	// Snapshot the resume cursors once under a single lock, so dispatching the
	// goroutines below does not serialise on s.mu.
	s.mu.Lock()
	startKeys := make(map[string]string, len(s.lastKey))
	maps.Copy(startKeys, s.lastKey)
	s.mu.Unlock()

	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup
	results := make([]bucketScrubResult, len(buckets))

dispatch:
	for i, bucket := range buckets {
		select {
		case <-s.quit:
			break dispatch
		default:
		}

		idx, b, start := i, bucket, startKeys[bucket.ID]
		sem <- struct{}{}

		wg.Go(func() {
			defer func() { <-sem }()
			results[idx] = s.scrubBucket(b, start, maxPerRun)
		})
	}
	wg.Wait()

	return s.foldResults(results, len(buckets))
}

// scrubBucket scrubs one bucket's next window of objects.
func (s *Scrubber) scrubBucket(b meta.Bucket, start string, maxPerRun int) bucketScrubResult {
	br := bucketScrubResult{bucketID: b.ID}

	// The View transaction ONLY collects candidates. ObjectExists and
	// VerifyChecksumRateLimited touch the disk — the latter deliberately
	// throttled — and a long-lived bbolt read tx blocks the writer's mmap remap
	// and pins freelist pages, stalling writes and growing the DB file for the
	// whole scrub. The Object values handed to the callback are decoded copies,
	// so they stay valid after the tx closes.
	var candidates []meta.Object
	lastVisited, iterErr := s.db.ForEachObjectFrom(b.ID, start, maxPerRun, func(obj meta.Object) error {
		if obj.State == "active" {
			candidates = append(candidates, obj)
		}
		return nil
	})

	toQuarantine, toMigrate := s.verifyCandidates(b, candidates, &br.partial)

	// Both of these run OUTSIDE the View transaction: they take write
	// transactions, and overlapping them with the read would deadlock.
	s.applyQuarantines(b, toQuarantine)
	s.migrateHealthy(b, toMigrate, &br.partial)

	if iterErr != nil {
		s.log.Error("incremental scrub: iterate objects", "err", iterErr, "bucket", b.Name)
		br.iterErr = true
	}

	br.lastVisited = lastVisited
	// An empty cursor means the bucket ran out of objects: it wrapped around.
	br.wrapped = lastVisited == ""
	return br
}

// verifyCandidates checks each candidate against the bytes on disk and sorts the
// findings into what to quarantine and what is healthy enough to migrate.
//
// Every mismatch or missing file is re-checked against the CURRENT record before
// being condemned: the metadata can change while the disk is being read, and
// without that re-check a freshly overwritten object would be quarantined on the
// strength of stale evidence.
func (s *Scrubber) verifyCandidates(
	b meta.Bucket, candidates []meta.Object, partial *ScrubResult,
) (toQuarantine []quarantineAction, toMigrate []string) {
	stillCurrent := func(obj *meta.Object) bool {
		cur, err := s.db.GetObjectMetaAny(b.ID, obj.Key)
		if err != nil {
			return false
		}
		return cur.State == "active" && cur.LocationRef == obj.LocationRef
	}

	for i := range candidates {
		obj := &candidates[i]
		partial.Checked++

		if !s.store.ObjectExists(obj) {
			if !stillCurrent(obj) {
				s.log.Info("scrub: object changed during verification, skipping",
					"bucket", b.Name, "key", obj.Key, "location", obj.LocationRef)
				continue
			}
			s.log.Warn("scrub: missing file", "bucket", b.Name, "key", obj.Key, "location", obj.LocationRef)
			toQuarantine = append(toQuarantine, quarantineAction{key: obj.Key, locationRef: obj.LocationRef})
			partial.Missing++
			continue
		}

		match, actual, verifyErr := s.store.VerifyChecksumRateLimited(obj.LocationRef, obj.ChecksumSHA256, s.bytesLimiter)
		if verifyErr != nil {
			s.log.Error("scrub: verify checksum", "err", verifyErr, "bucket", b.Name, "key", obj.Key)
			partial.Errors++
			continue
		}

		if !match {
			if !stillCurrent(obj) {
				s.log.Info("scrub: object changed during verification, skipping",
					"bucket", b.Name, "key", obj.Key, "location", obj.LocationRef)
				continue
			}
			s.log.Error("scrub: checksum mismatch",
				"bucket", b.Name, "key", obj.Key,
				"expected", obj.ChecksumSHA256, "actual", actual, "location", obj.LocationRef,
			)
			s.recordChecksumFailure()
			toQuarantine = append(toQuarantine, quarantineAction{key: obj.Key, locationRef: obj.LocationRef, isMismatch: true})
			partial.Quarantined++
			continue
		}

		partial.Healthy++
		// Healthy records get the JSON→binary envelope rewrite piggybacked on
		// the scrub, so legacy records migrate in place without a dedicated
		// batch job. MigrateLegacyObject is a no-op for records already in the
		// binary format, so being generous here costs nothing.
		toMigrate = append(toMigrate, obj.Key)
	}
	return toQuarantine, toMigrate
}

// applyQuarantines pulls the condemned objects out of service.
//
// A checksum mismatch quarantines the file on disk as well as the record: the
// bytes are evidence, and deleting them would destroy the only copy of whatever
// corruption happened.
func (s *Scrubber) applyQuarantines(b meta.Bucket, actions []quarantineAction) {
	for _, qa := range actions {
		if err := s.db.QuarantineObject(b.ID, qa.key); err != nil {
			s.log.Error("incremental scrub: quarantine meta", "err", err, "bucket", b.Name, "key", qa.key)
		} else {
			s.recordQuarantine()
		}
		if qa.isMismatch {
			if err := s.store.Quarantine(qa.locationRef); err != nil {
				s.log.Error("incremental scrub: quarantine file", "err", err, "location", qa.locationRef)
			}
		}
	}
}

// migrateHealthy rewrites legacy-JSON records to the binary envelope, one write
// transaction each.
//
// Healthy records only, so re-encoded bytes are never persisted for an object
// that was just quarantined.
func (s *Scrubber) migrateHealthy(b meta.Bucket, keys []string, partial *ScrubResult) {
	for _, key := range keys {
		migrated, err := s.db.MigrateLegacyObject(b.ID, key)
		if err != nil {
			s.log.Error("incremental scrub: migrate legacy", "err", err, "bucket", b.Name, "key", key)
			partial.Errors++
			continue
		}
		if migrated {
			partial.Migrated++
		}
	}
}

// foldResults sums the per-bucket results and advances the resume cursors.
//
// A bucket that wrapped around has its cursor reset to the start; when EVERY
// bucket wrapped in the same run, the full-scan timestamp is stamped — that is
// the only moment jay can honestly claim to have verified everything it holds.
func (s *Scrubber) foldResults(results []bucketScrubResult, bucketCount int) ScrubResult {
	var result ScrubResult
	allWrapped := true

	s.mu.Lock()
	for _, br := range results {
		result.Checked += br.partial.Checked
		result.Healthy += br.partial.Healthy
		result.Quarantined += br.partial.Quarantined
		result.Missing += br.partial.Missing
		result.Errors += br.partial.Errors
		result.Migrated += br.partial.Migrated
		s.totalChecked += int64(br.partial.Checked)

		switch {
		case br.iterErr:
			result.Errors++ // the iteration failure itself
		case br.bucketID == "":
			// Unused slot: dispatch stopped early on shutdown.
		case br.wrapped:
			s.lastKey[br.bucketID] = ""
		default:
			s.lastKey[br.bucketID] = br.lastVisited
			allWrapped = false
		}
	}
	s.mu.Unlock()

	if allWrapped && bucketCount > 0 {
		s.mu.Lock()
		s.lastFullScan = time.Now().UTC()
		s.mu.Unlock()
	}
	return result
}

// Coverage returns incremental scrub progress information.
func (s *Scrubber) Coverage() ScrubCoverage {
	s.mu.Lock()
	defer s.mu.Unlock()

	cov := ScrubCoverage{
		TotalChecked: s.totalChecked,
		InProgress:   s.running.Load(),
	}
	if !s.lastFullScan.IsZero() {
		cov.LastFullScan = s.lastFullScan.Format(time.RFC3339)
	}
	return cov
}
