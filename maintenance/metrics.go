package maintenance

import (
	"sync/atomic"
	"time"
)

// Metrics tracks operational counters for observability.
type Metrics struct {
	startedAt time.Time

	PutObjectTotal    atomic.Int64
	GetObjectTotal    atomic.Int64
	DeleteObjectTotal atomic.Int64
	HeadObjectTotal   atomic.Int64
	ListObjectsTotal  atomic.Int64

	CreateBucketTotal atomic.Int64
	DeleteBucketTotal atomic.Int64

	AuthFailures     atomic.Int64
	ChecksumFailures atomic.Int64
	FsyncFailures    atomic.Int64

	ObjectsQuarantined atomic.Int64

	// MetadataDecodeFailures counts bbolt records that failed to decode and were
	// therefore skipped from a listing. A jay.db that is degrading has to be
	// visible: without this counter the only signal was a listing with rows
	// missing and nothing to say so.
	MetadataDecodeFailures atomic.Int64

	BytesUploaded   atomic.Int64
	BytesDownloaded atomic.Int64
}

// NewMetrics creates a new metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{startedAt: time.Now()}
}

// RecordFsyncFailure increments the fsync failure counter. Nil-safe so
// store hooks can call it unconditionally.
func (m *Metrics) RecordFsyncFailure() {
	if m == nil {
		return
	}
	m.FsyncFailures.Add(1)
}

// RecordMetadataDecodeFailure bumps the unreadable-metadata counter. Nil-safe:
// it is wired into meta.DB.SetDecodeFailureHook, which can be active in fixtures
// that have no metrics.
func (m *Metrics) RecordMetadataDecodeFailure() {
	if m == nil {
		return
	}
	m.MetadataDecodeFailures.Add(1)
}

// Snapshot returns a JSON-serializable snapshot of all metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		UptimeSeconds:      int64(time.Since(m.startedAt).Seconds()),
		PutObjectTotal:     m.PutObjectTotal.Load(),
		GetObjectTotal:     m.GetObjectTotal.Load(),
		DeleteObjectTotal:  m.DeleteObjectTotal.Load(),
		HeadObjectTotal:    m.HeadObjectTotal.Load(),
		ListObjectsTotal:   m.ListObjectsTotal.Load(),
		CreateBucketTotal:  m.CreateBucketTotal.Load(),
		DeleteBucketTotal:  m.DeleteBucketTotal.Load(),
		AuthFailures:       m.AuthFailures.Load(),
		ChecksumFailures:   m.ChecksumFailures.Load(),
		FsyncFailures:      m.FsyncFailures.Load(),
		ObjectsQuarantined: m.ObjectsQuarantined.Load(),

		MetadataDecodeFailures: m.MetadataDecodeFailures.Load(),
		BytesUploaded:          m.BytesUploaded.Load(),
		BytesDownloaded:        m.BytesDownloaded.Load(),
	}
}

// MetricsSnapshot is a JSON-serializable point-in-time copy of metrics.
type MetricsSnapshot struct {
	UptimeSeconds      int64 `json:"uptime_seconds"`
	PutObjectTotal     int64 `json:"put_object_total"`
	GetObjectTotal     int64 `json:"get_object_total"`
	DeleteObjectTotal  int64 `json:"delete_object_total"`
	HeadObjectTotal    int64 `json:"head_object_total"`
	ListObjectsTotal   int64 `json:"list_objects_total"`
	CreateBucketTotal  int64 `json:"create_bucket_total"`
	DeleteBucketTotal  int64 `json:"delete_bucket_total"`
	AuthFailures       int64 `json:"auth_failures"`
	ChecksumFailures   int64 `json:"checksum_failures"`
	FsyncFailures      int64 `json:"fsync_failures"`
	ObjectsQuarantined int64 `json:"objects_quarantined"`

	MetadataDecodeFailures int64 `json:"metadata_decode_failures"`
	BytesUploaded          int64 `json:"bytes_uploaded"`
	BytesDownloaded        int64 `json:"bytes_downloaded"`
}
