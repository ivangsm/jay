package maintenance

import (
	"crypto/sha256"
	"encoding/hex"
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

	bucket, err := qm.db.GetBucketByID(bucketID)
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
func (qm *QuarantineManager) Revalidate(bucketID, key string) (bool, error) {
	inspection, err := qm.Inspect(bucketID, key)
	if err != nil {
		return false, err
	}

	if !inspection.FileExists || !inspection.ChecksumMatch {
		return false, nil
	}

	if err := qm.db.RestoreObject(bucketID, key); err != nil {
		return false, err
	}

	qm.log.Info("quarantine: revalidated object",
		"bucket_id", bucketID,
		"key", key,
	)
	return true, nil
}

// Purge deletes both the metadata and physical file of a quarantined object.
func (qm *QuarantineManager) Purge(bucketID, key string) error {
	obj, err := qm.db.GetObjectMetaAny(bucketID, key)
	if err != nil {
		return err
	}

	// Delete physical file (ignore not-found)
	_ = qm.store.DeleteObject(obj.LocationRef)

	// Delete metadata
	if err := qm.db.DeleteObjectMetaAny(bucketID, key); err != nil {
		return err
	}

	qm.log.Info("quarantine: purged object",
		"bucket_id", bucketID,
		"key", key,
	)
	return nil
}

// PurgeAll purges all quarantined objects and returns the count purged.
func (qm *QuarantineManager) PurgeAll() (int, error) {
	objects, err := qm.ListQuarantined()
	if err != nil {
		return 0, err
	}

	count := 0
	for _, obj := range objects {
		if err := qm.Purge(obj.BucketID, obj.Key); err != nil {
			qm.log.Error("quarantine: purge failed",
				"bucket_id", obj.BucketID,
				"key", obj.Key,
				"err", err,
			)
			continue
		}
		count++
	}
	return count, nil
}
