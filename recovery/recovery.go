// Package recovery reconciles metadata against the bytes on disk at startup.
//
// It is what makes jay safe to restart after a crash: metadata pointing at a
// missing file, and files no metadata points at, are both quarantined rather
// than deleted, so an inconsistency is preserved as evidence instead of being
// tidied away.
package recovery

import (
	"log/slog"

	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

// Run executes startup reconciliation before the server accepts traffic.
// It cleans orphaned temp files, detects inconsistencies between metadata
// and physical files, and quarantines anything that doesn't match.
func Run(db *meta.DB, st *store.Store, log *slog.Logger) error {
	return RunWithMetrics(db, st, log, nil)
}

// RunWithMetrics is Run with an optional metrics sink. m may be nil, in which
// case no counters are recorded. Every effective quarantine (metadata entry
// quarantined or orphaned physical file moved aside) increments
// ObjectsQuarantined.
// recoveryTally counts what one reconciliation pass had to fix.
type recoveryTally struct {
	quarantinedMeta  int
	quarantinedFiles int
	orphanedFiles    int
}

// RunWithMetrics reconciles metadata against what is actually on disk, and is
// what makes jay safe to restart after a crash.
//
// Two kinds of inconsistency exist and both are quarantined rather than
// deleted:
//
//   - metadata pointing at a file that is not there — the record is quarantined,
//     because serving it would 500 on every read;
//   - a file with no metadata pointing at it — the file is quarantined, because
//     nothing can reach it and it would otherwise occupy disk forever.
//
// Quarantine, never delete: an inconsistency is evidence of something that went
// wrong, and deleting it destroys the only trace of what.
func RunWithMetrics(db *meta.DB, st *store.Store, log *slog.Logger, m *maintenance.Metrics) error {
	log.Info("recovery: starting reconciliation")

	cleaned, err := st.CleanTmp()
	if err != nil {
		log.Error("recovery: clean tmp", "err", err)
		return err
	}
	if cleaned > 0 {
		log.Warn("recovery: cleaned orphaned temp files", "count", cleaned)
	}

	buckets, err := db.ListBuckets("")
	if err != nil {
		log.Error("recovery: list buckets", "err", err)
		return err
	}

	var tally recoveryTally
	for _, bucket := range buckets {
		reconcileBucket(db, st, log, m, bucket, &tally)
	}

	log.Info("recovery: reconciliation complete",
		"buckets", len(buckets),
		"quarantined_meta", tally.quarantinedMeta,
		"quarantined_files", tally.quarantinedFiles,
		"orphaned_files", tally.orphanedFiles,
		"cleaned_tmp", cleaned,
	)

	return nil
}

// reconcileBucket reconciles one bucket in both directions.
//
// A bucket whose files cannot be listed is skipped rather than failing the whole
// recovery: one unreadable bucket must not stop jay from booting with the rest.
func reconcileBucket(
	db *meta.DB, st *store.Store, log *slog.Logger, m *maintenance.Metrics,
	bucket meta.Bucket, tally *recoveryTally,
) {
	physicalFiles, err := st.ListBucketFiles(bucket.ID)
	if err != nil {
		log.Warn("recovery: list bucket files", "err", err, "bucket", bucket.Name)
		return
	}

	orphanedMeta, knownLocations := findMetadataWithoutFiles(db, st, log, bucket)
	quarantineMetadata(db, log, m, bucket, orphanedMeta, tally)
	quarantineOrphanedFiles(st, log, m, bucket, physicalFiles, knownLocations, tally)
}

// orphanedRecord is an active metadata record whose file is missing.
type orphanedRecord struct {
	key         string
	locationRef string
}

// findMetadataWithoutFiles walks the bucket's records and reports which ones
// have no file behind them, plus the set of locations that ARE accounted for.
//
// It only COLLECTS inside the View transaction. QuarantineObject opens a write
// transaction, and committing one while a view transaction is open on the same
// goroutine can deadlock if the commit has to remap the mmap because the
// database grew.
func findMetadataWithoutFiles(
	db *meta.DB, st *store.Store, log *slog.Logger, bucket meta.Bucket,
) (orphaned []orphanedRecord, knownLocations map[string]bool) {
	knownLocations = make(map[string]bool)

	err := db.ForEachObject(bucket.ID, func(obj meta.Object) error {
		if obj.State != "active" {
			return nil
		}
		knownLocations[obj.LocationRef] = true
		if !st.ObjectExists(&obj) {
			orphaned = append(orphaned, orphanedRecord{key: obj.Key, locationRef: obj.LocationRef})
		}
		return nil
	})
	if err != nil {
		log.Warn("recovery: iterate objects", "err", err, "bucket", bucket.Name)
	}
	return orphaned, knownLocations
}

// quarantineMetadata quarantines records whose file is gone. Runs outside the
// View transaction — see findMetadataWithoutFiles for why.
func quarantineMetadata(
	db *meta.DB, log *slog.Logger, m *maintenance.Metrics,
	bucket meta.Bucket, orphaned []orphanedRecord, tally *recoveryTally,
) {
	for _, rec := range orphaned {
		log.Warn("recovery: metadata without file, quarantining",
			"bucket", bucket.Name, "key", rec.key, "location", rec.locationRef)

		if err := db.QuarantineObject(bucket.ID, rec.key); err != nil {
			log.Error("recovery: quarantine object", "err", err, "key", rec.key)
		} else if m != nil {
			m.ObjectsQuarantined.Add(1)
		}
		tally.quarantinedMeta++
	}
}

// quarantineOrphanedFiles quarantines files that no metadata record points at.
func quarantineOrphanedFiles(
	st *store.Store, log *slog.Logger, m *maintenance.Metrics,
	bucket meta.Bucket, physicalFiles []string, knownLocations map[string]bool, tally *recoveryTally,
) {
	for _, file := range physicalFiles {
		if knownLocations[file] {
			continue
		}

		log.Warn("recovery: orphaned file, quarantining", "bucket", bucket.Name, "file", file)
		if err := st.Quarantine(file); err != nil {
			log.Error("recovery: quarantine file", "err", err, "file", file)
			tally.orphanedFiles++
			continue
		}

		tally.quarantinedFiles++
		if m != nil {
			m.ObjectsQuarantined.Add(1)
		}
	}
}
