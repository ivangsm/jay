package recovery

import (
	"log/slog"

	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

// Run executes startup reconciliation before the server accepts traffic.
// It cleans orphaned temp files, detects inconsistencies between metadata
// and physical files, and quarantines anything that doesn't match.
func Run(db *meta.DB, st *store.Store, log *slog.Logger) error {
	log.Info("recovery: starting reconciliation")

	// 1. Clean temp directory
	cleaned, err := st.CleanTmp()
	if err != nil {
		log.Error("recovery: clean tmp", "err", err)
		return err
	}
	if cleaned > 0 {
		log.Warn("recovery: cleaned orphaned temp files", "count", cleaned)
	}

	// 2. Check all buckets and their objects
	buckets, err := db.ListBuckets("")
	if err != nil {
		log.Error("recovery: list buckets", "err", err)
		return err
	}

	var quarantinedMeta, quarantinedFiles, orphanedFiles int

	for _, bucket := range buckets {
		// Track known physical files for this bucket
		physicalFiles := make(map[string]bool)
		files, err := st.ListBucketFiles(bucket.ID)
		if err != nil {
			log.Warn("recovery: list bucket files", "err", err, "bucket", bucket.Name)
			continue
		}
		for _, f := range files {
			physicalFiles[f] = true
		}

		// Check each metadata entry has a matching physical file
		knownLocations := make(map[string]bool)
		err = db.ForEachObject(bucket.ID, func(obj meta.Object) error {
			if obj.State != "active" {
				return nil
			}
			knownLocations[obj.LocationRef] = true

			if !st.ObjectExists(&obj) {
				log.Warn("recovery: metadata without file, quarantining",
					"bucket", bucket.Name,
					"key", obj.Key,
					"location", obj.LocationRef,
				)
				if err := db.QuarantineObject(bucket.ID, obj.Key); err != nil {
					log.Error("recovery: quarantine object", "err", err, "key", obj.Key)
				}
				quarantinedMeta++
			}
			return nil
		})
		if err != nil {
			log.Warn("recovery: iterate objects", "err", err, "bucket", bucket.Name)
		}

		// Check for physical files without metadata
		for f := range physicalFiles {
			if !knownLocations[f] {
				log.Warn("recovery: orphaned file, quarantining",
					"bucket", bucket.Name,
					"file", f,
				)
				if err := st.Quarantine(f); err != nil {
					log.Error("recovery: quarantine file", "err", err, "file", f)
					orphanedFiles++
				} else {
					quarantinedFiles++
				}
			}
		}
	}

	log.Info("recovery: reconciliation complete",
		"buckets", len(buckets),
		"quarantined_meta", quarantinedMeta,
		"quarantined_files", quarantinedFiles,
		"orphaned_files", orphanedFiles,
		"cleaned_tmp", cleaned,
	)

	return nil
}
