package maintenance

import (
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

// ScrubResult contains the results of a scrub run.
type ScrubResult struct {
	Checked      int
	Healthy      int
	Quarantined  int
	Missing      int
	Errors       int
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
	sampleRate float64 // 0.0-1.0, fraction of objects to check per run
	quit     chan struct{}
	running  atomic.Bool

	mu           sync.Mutex
	lastKey      map[string]string // bucketID -> last checked key
	totalChecked int64
	lastFullScan time.Time
	maxPerRun    int
}

// NewScrubber creates a new scrubber.
// sampleRate controls what fraction of objects are checked per run (1.0 = full scan).
func NewScrubber(db *meta.DB, st *store.Store, log *slog.Logger, interval time.Duration, sampleRate float64) *Scrubber {
	if sampleRate <= 0 || sampleRate > 1.0 {
		sampleRate = 0.1 // default 10% per run
	}
	return &Scrubber{
		db:         db,
		store:      st,
		log:        log,
		interval:   interval,
		sampleRate: sampleRate,
		quit:       make(chan struct{}),
		lastKey:    make(map[string]string),
		maxPerRun:  100,
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
			)
			timer.Reset(s.interval)
		}
	}
}

// RunOnce performs a single scrub pass.
func (s *Scrubber) RunOnce() ScrubResult {
	var result ScrubResult

	buckets, err := s.db.ListBuckets("")
	if err != nil {
		s.log.Error("scrub: list buckets", "err", err)
		result.Errors++
		return result
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for _, bucket := range buckets {
		s.db.ForEachObject(bucket.ID, func(obj meta.Object) error {
			if obj.State != "active" {
				return nil
			}

			// Sample based on rate
			if rng.Float64() > s.sampleRate {
				return nil
			}

			result.Checked++

			// Check physical file exists
			if !s.store.ObjectExists(&obj) {
				s.log.Warn("scrub: missing file",
					"bucket", bucket.Name,
					"key", obj.Key,
					"location", obj.LocationRef,
				)
				s.db.QuarantineObject(bucket.ID, obj.Key)
				result.Missing++
				return nil
			}

			// Verify checksum
			match, actual, err := s.store.VerifyChecksum(obj.LocationRef, obj.ChecksumSHA256)
			if err != nil {
				s.log.Error("scrub: verify checksum",
					"err", err,
					"bucket", bucket.Name,
					"key", obj.Key,
				)
				result.Errors++
				return nil
			}

			if !match {
				s.log.Error("scrub: checksum mismatch",
					"bucket", bucket.Name,
					"key", obj.Key,
					"expected", obj.ChecksumSHA256,
					"actual", actual,
					"location", obj.LocationRef,
				)
				s.db.QuarantineObject(bucket.ID, obj.Key)
				s.store.Quarantine(obj.LocationRef)
				result.Quarantined++
				return nil
			}

			result.Healthy++
			return nil
		})

		// Check for shutdown between buckets
		select {
		case <-s.quit:
			return result
		default:
		}
	}

	return result
}

// RunIncremental checks up to maxPerRun objects per bucket, starting from
// where the last run left off. When a bucket is fully scanned the cursor
// wraps around. Once all buckets wrap, lastFullScan is updated.
func (s *Scrubber) RunIncremental(maxPerRun int) ScrubResult {
	var result ScrubResult

	buckets, err := s.db.ListBuckets("")
	if err != nil {
		s.log.Error("incremental scrub: list buckets", "err", err)
		result.Errors++
		return result
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	allWrapped := true

	for _, bucket := range buckets {
		startKey := s.lastKey[bucket.ID]

		lastVisited, err := s.db.ForEachObjectFrom(bucket.ID, startKey, maxPerRun, func(obj meta.Object) error {
			if obj.State != "active" {
				return nil
			}

			result.Checked++
			s.totalChecked++

			if !s.store.ObjectExists(&obj) {
				s.log.Warn("scrub: missing file",
					"bucket", bucket.Name,
					"key", obj.Key,
					"location", obj.LocationRef,
				)
				s.db.QuarantineObject(bucket.ID, obj.Key)
				result.Missing++
				return nil
			}

			match, actual, verifyErr := s.store.VerifyChecksum(obj.LocationRef, obj.ChecksumSHA256)
			if verifyErr != nil {
				s.log.Error("scrub: verify checksum",
					"err", verifyErr,
					"bucket", bucket.Name,
					"key", obj.Key,
				)
				result.Errors++
				return nil
			}

			if !match {
				s.log.Error("scrub: checksum mismatch",
					"bucket", bucket.Name,
					"key", obj.Key,
					"expected", obj.ChecksumSHA256,
					"actual", actual,
					"location", obj.LocationRef,
				)
				s.db.QuarantineObject(bucket.ID, obj.Key)
				s.store.Quarantine(obj.LocationRef)
				result.Quarantined++
				return nil
			}

			result.Healthy++
			return nil
		})

		if err != nil {
			s.log.Error("incremental scrub: iterate objects",
				"err", err,
				"bucket", bucket.Name,
			)
			result.Errors++
			continue
		}

		if lastVisited == "" {
			// No more objects from startKey onward — wrap to beginning.
			s.lastKey[bucket.ID] = ""
		} else {
			s.lastKey[bucket.ID] = lastVisited
			allWrapped = false
		}

		select {
		case <-s.quit:
			return result
		default:
		}
	}

	if allWrapped && len(buckets) > 0 {
		s.lastFullScan = time.Now().UTC()
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
