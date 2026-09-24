package maintenance

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

// QuarantineManager provides operations on quarantined objects.
type QuarantineManager struct {
	db    *meta.DB
	store *store.Store
	log   *slog.Logger
}

// QuarantinedObject describes an object that has been quarantined.
type QuarantinedObject struct {
	BucketID         string `json:"bucket_id"`
	BucketName       string `json:"bucket_name"`
	Key              string `json:"key"`
	ObjectID         string `json:"object_id"`
	SizeBytes        int64  `json:"size_bytes"`
	ExpectedChecksum string `json:"expected_checksum"`
	LocationRef      string `json:"location_ref"`
}

// InspectionResult contains details from inspecting a quarantined object.
type InspectionResult struct {
	Object          QuarantinedObject `json:"object"`
	FileExists      bool              `json:"file_exists"`
	CurrentChecksum string            `json:"current_checksum"`
	ChecksumMatch   bool              `json:"checksum_match"`
	FileSize        int64             `json:"file_size"`
}

// NewQuarantineManager creates a new QuarantineManager.
func NewQuarantineManager(db *meta.DB, st *store.Store, log *slog.Logger) *QuarantineManager {
	return &QuarantineManager{db: db, store: st, log: log}
}

// ListQuarantined iterates all buckets and returns objects with state="quarantined".
func (qm *QuarantineManager) ListQuarantined() ([]QuarantinedObject, error) {
	buckets, err := qm.db.ListBuckets("")
	if err != nil {
		return nil, err
	}

	var result []QuarantinedObject
	for _, b := range buckets {
		err := qm.db.ForEachObject(b.ID, func(obj meta.Object) error {
			if obj.State == "quarantined" {
				result = append(result, QuarantinedObject{
					BucketID:         obj.BucketID,
					BucketName:       b.Name,
					Key:              obj.Key,
					ObjectID:         obj.ObjectID,
					SizeBytes:        obj.SizeBytes,
					ExpectedChecksum: obj.ChecksumSHA256,
					LocationRef:      obj.LocationRef,
				})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// Inspect checks file existence and computes the current checksum of a quarantined object.
func (qm *QuarantineManager) Inspect(bucketID, key string) (*InspectionResult, error) {
	obj, err := qm.db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		return nil, err
	}
	return qm.inspectRecord(obj)
}

// inspectRecord is Inspect for a record already read.
func (qm *QuarantineManager) inspectRecord(obj *meta.Object) (*InspectionResult, error) {
	bucket, err := qm.db.GetBucketByID(obj.BucketID)
	if err != nil {
		return nil, err
	}

	qo := QuarantinedObject{
		BucketID:         obj.BucketID,
		BucketName:       bucket.Name,
		Key:              obj.Key,
		ObjectID:         obj.ObjectID,
		SizeBytes:        obj.SizeBytes,
		ExpectedChecksum: obj.ChecksumSHA256,
		LocationRef:      obj.LocationRef,
	}

	result := &InspectionResult{Object: qo}

	absPath, err := qm.store.SafePath(obj.LocationRef)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(absPath)
	if err != nil {
		// File does not exist
		result.FileExists = false
		return result, nil
	}

	result.FileExists = true
	result.FileSize = info.Size()

	f, err := os.Open(absPath)
	if err != nil {
		return result, nil
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return result, nil
	}
	result.CurrentChecksum = hex.EncodeToString(h.Sum(nil))
	result.ChecksumMatch = result.CurrentChecksum == obj.ChecksumSHA256

	return result, nil
}

// Revalidate checks if a quarantined object's checksum now matches and restores it if so.
//
// It only acts on quarantined objects: anything else is
// meta.ErrObjectNotQuarantined, never a "restored". The bytes are hashed
// outside any transaction — that can take as long as the file is large — and
// the restore then happens only if the record is still the quarantined object
// that was hashed (meta.RestoreQuarantinedObject checks both in the same
// transaction that writes).
func (qm *QuarantineManager) Revalidate(bucketID, key string) (bool, error) {
	obj, err := qm.db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		return false, err
	}
	if obj.State != "quarantined" {
		return false, meta.ErrObjectNotQuarantined
	}

	inspection, err := qm.inspectRecord(obj)
	if err != nil {
		return false, err
	}
	if !inspection.FileExists || !inspection.ChecksumMatch {
		return false, nil
	}

	if err := qm.db.RestoreQuarantinedObject(bucketID, key, obj.ObjectID); err != nil {
		return false, err
	}

	qm.log.Info("quarantine: revalidated object",
		"bucket_id", bucketID,
		"key", key,
	)
	return true, nil
}

// Purge deletes both the file and the record of a quarantined object, and
// refuses anything that is not quarantined with meta.ErrObjectNotQuarantined.
//
// The state check, the file removal and the record deletion happen inside one
// bbolt write transaction (meta.DeleteQuarantinedObject, which also explains
// the file-first order). A file that cannot be removed fails the purge and
// leaves the record where it was; only a file that is already gone counts as
// removed.
func (qm *QuarantineManager) Purge(bucketID, key string) error {
	_, err := qm.db.DeleteQuarantinedObject(bucketID, key, func(obj *meta.Object) error {
		return qm.store.DeleteObject(obj.LocationRef)
	})
	if err != nil {
		return err
	}

	qm.log.Info("quarantine: purged object",
		"bucket_id", bucketID,
		"key", key,
	)
	return nil
}

// PurgeFailure is one quarantined object that PurgeAll could not remove.
type PurgeFailure struct {
	BucketID string `json:"bucket_id"`
	Key      string `json:"key"`
	Error    string `json:"error"`
}

// PurgeAllError is what PurgeAll returns when some objects could not be
// purged. The others were: PurgeAll still returns their count.
type PurgeAllError struct {
	Failed []PurgeFailure
}

func (e *PurgeAllError) Error() string {
	return fmt.Sprintf("%d quarantined object(s) could not be purged", len(e.Failed))
}

// PurgeAll purges all quarantined objects and returns the count purged.
//
// It keeps going past a failure — one stuck file should not keep the rest of
// the quarantine in place — but it never reports a partial purge as a whole
// one: if anything failed, the error is a *PurgeAllError naming each object
// and why, alongside the count of the ones that did go.
//
// An object that is no longer quarantined by the time its turn comes
// (revalidated, or purged by someone else) is neither purged nor a failure:
// there is nothing left in quarantine to act on.
func (qm *QuarantineManager) PurgeAll() (int, error) {
	objects, err := qm.ListQuarantined()
	if err != nil {
		return 0, err
	}

	count := 0
	var failed []PurgeFailure
	for _, obj := range objects {
		err := qm.Purge(obj.BucketID, obj.Key)
		switch {
		case err == nil:
			count++
		case errors.Is(err, meta.ErrObjectNotQuarantined), errors.Is(err, meta.ErrObjectNotFound),
			errors.Is(err, meta.ErrBucketNotFound):
			// Left quarantine on its own between the listing and now.
		default:
			qm.log.Error("quarantine: purge failed",
				"bucket_id", obj.BucketID,
				"key", obj.Key,
				"err", err,
			)
			failed = append(failed, PurgeFailure{BucketID: obj.BucketID, Key: obj.Key, Error: err.Error()})
		}
	}
	if len(failed) > 0 {
		return count, &PurgeAllError{Failed: failed}
	}
	return count, nil
}
