package maintenance

import (
	"log/slog"
	"math/rand"
	"runtime"
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
		type quarantineAction struct {
			key         string
			locationRef string
			isMismatch  bool // true = checksum mismatch, false = missing file
		}
		var toQuarantine []quarantineAction

		if err := s.db.ForEachObject(bucket.ID, func(obj meta.Object) error {
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
				toQuarantine = append(toQuarantine, quarantineAction{key: obj.Key, locationRef: obj.LocationRef, isMismatch: false})
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
				toQuarantine = append(toQuarantine, quarantineAction{key: obj.Key, locationRef: obj.LocationRef, isMismatch: true})
				result.Quarantined++
				return nil
			}

			result.Healthy++
			return nil
		}); err != nil {
			s.log.Error("scrub: iterate objects", "err", err, "bucket", bucket.Name)
			result.Errors++
		}

		// Quarantine outside the View transaction to avoid deadlock.
		for _, qa := range toQuarantine {
			if err := s.db.QuarantineObject(bucket.ID, qa.key); err != nil {
				s.log.Error("scrub: quarantine meta", "err", err, "bucket", bucket.Name, "key", qa.key)
			}
			if qa.isMismatch {
				if err := s.store.Quarantine(qa.locationRef); err != nil {
					s.log.Error("scrub: quarantine file", "err", err, "location", qa.locationRef)
				}
			}
		}

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
// Buckets are processed in parallel using a bounded worker pool.
func (s *Scrubber) RunIncremental(maxPerRun int) ScrubResult {
	var result ScrubResult

	buckets, err := s.db.ListBuckets("")
	if err != nil {
		s.log.Error("incremental scrub: list buckets", "err", err)
		result.Errors++
		return result
	}

	type bucketResult struct {
		partial     ScrubResult
		bucketID    string
		lastVisited string
		wrapped     bool
		iterErr     bool
	}

	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup
	results := make([]bucketResult, len(buckets))

	for i, bucket := range buckets {
		// Check for shutdown before launching a new goroutine.
		select {
		case <-s.quit:
			break
		default:
		}

		s.mu.Lock()
		startKey := s.lastKey[bucket.ID]
		s.mu.Unlock()

		wg.Add(1)
		sem <- struct{}{} // acquire semaphore slot

		go func(idx int, b meta.Bucket, start string) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore slot

			br := bucketResult{bucketID: b.ID}

			type quarantineAction struct {
				key         string
				locationRef string
				isMismatch  bool
			}
			var toQuarantine []quarantineAction

			lastVisited, iterErr := s.db.ForEachObjectFrom(b.ID, start, maxPerRun, func(obj meta.Object) error {
				if obj.State != "active" {
					return nil
				}

				br.partial.Checked++

				if !s.store.ObjectExists(&obj) {
					s.log.Warn("scrub: missing file",
						"bucket", b.Name,
						"key", obj.Key,
						"location", obj.LocationRef,
					)
					toQuarantine = append(toQuarantine, quarantineAction{key: obj.Key, locationRef: obj.LocationRef, isMismatch: false})
					br.partial.Missing++
					return nil
				}

				match, actual, verifyErr := s.store.VerifyChecksum(obj.LocationRef, obj.ChecksumSHA256)
				if verifyErr != nil {
					s.log.Error("scrub: verify checksum",
						"err", verifyErr,
						"bucket", b.Name,
						"key", obj.Key,
					)
					br.partial.Errors++
					return nil
				}

				if !match {
					s.log.Error("scrub: checksum mismatch",
						"bucket", b.Name,
						"key", obj.Key,
						"expected", obj.ChecksumSHA256,
						"actual", actual,
						"location", obj.LocationRef,
					)
					toQuarantine = append(toQuarantine, quarantineAction{key: obj.Key, locationRef: obj.LocationRef, isMismatch: true})
					br.partial.Quarantined++
					return nil
				}

				br.partial.Healthy++
				return nil
			})

			// Quarantine outside the View transaction to avoid deadlock.
			for _, qa := range toQuarantine {
				if qerr := s.db.QuarantineObject(b.ID, qa.key); qerr != nil {
					s.log.Error("incremental scrub: quarantine meta", "err", qerr, "bucket", b.Name, "key", qa.key)
				}
				if qa.isMismatch {
					if qerr := s.store.Quarantine(qa.locationRef); qerr != nil {
						s.log.Error("incremental scrub: quarantine file", "err", qerr, "location", qa.locationRef)
					}
				}
			}

			if iterErr != nil {
				s.log.Error("incremental scrub: iterate objects",
					"err", iterErr,
					"bucket", b.Name,
				)
				br.iterErr = true
			}

			br.lastVisited = lastVisited
			if lastVisited == "" {
				br.wrapped = true
			}

			results[idx] = br
		}(i, bucket, startKey)
	}

	wg.Wait()

	// Aggregate results and update shared state under the lock.
	allWrapped := true
	s.mu.Lock()
	for _, br := range results {
		result.Checked += br.partial.Checked
		result.Healthy += br.partial.Healthy
		result.Quarantined += br.partial.Quarantined
		result.Missing += br.partial.Missing
		result.Errors += br.partial.Errors
		s.totalChecked += int64(br.partial.Checked)

		if br.iterErr {
			result.Errors++ // count the iteration error itself
			continue
		}

		if br.bucketID == "" {
			continue // unused slot (early shutdown)
		}

		if br.wrapped {
			s.lastKey[br.bucketID] = ""
		} else {
			s.lastKey[br.bucketID] = br.lastVisited
			allWrapped = false
		}
	}
	s.mu.Unlock()

	if allWrapped && len(buckets) > 0 {
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
