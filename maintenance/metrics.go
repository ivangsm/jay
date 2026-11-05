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

	// AuthFailures counts requests the S3 API refused for their credentials.
	AuthFailures atomic.Int64
	// AdminAuthFailures counts requests the admin listener's bearer gate
	// refused — /_jay, pprof and /metrics alike, including those refused
	// because the source address is locked out. It is its own counter rather
	// than a share of AuthFailures because the two mean different things: a
	// few S3 refusals are routine (an expired presigned URL, an anonymous probe
	// of a private bucket), while the admin listener sits on a private network
	// and any refusal there is somebody holding the wrong credential.
	AdminAuthFailures atomic.Int64
	ChecksumFailures  atomic.Int64
	FsyncFailures     atomic.Int64

	ObjectsQuarantined atomic.Int64

	// MetadataDecodeFailures counts bbolt records that failed to decode and were
	// therefore skipped from a listing. A jay.db that is degrading has to be
	// visible: without this counter the only signal was a listing with rows
	// missing and nothing to say so.
	MetadataDecodeFailures atomic.Int64

	// PanicsRecovered counts panics caught by the HTTP middleware or by the
	// native connection handler. Recovering keeps the process alive with state
	// that may be inconsistent, so the number has to be readable from outside:
	// an instance whose counter is climbing is one to take out of the pool, and
	// without it the only evidence is a log line somebody has to go looking for.
	PanicsRecovered atomic.Int64

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

// RecordAdminAuthFailure bumps the admin-surface auth failure counter.
// Nil-safe: the admin handler runs in fixtures with no metrics.
func (m *Metrics) RecordAdminAuthFailure() {
	if m == nil {
		return
	}
	m.AdminAuthFailures.Add(1)
}

// RecordPanicRecovered bumps the recovered-panic counter. Nil-safe: the
// recovery paths that call it run in handlers that may hold no metrics at all
// (fixtures, the client-side harnesses), and a nil check there would be one
// more thing to forget on the one path that must never itself panic.
func (m *Metrics) RecordPanicRecovered() {
	if m == nil {
		return
	}
	m.PanicsRecovered.Add(1)
}

// Snapshot returns a JSON-serializable snapshot of all metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		StartedAt:          m.startedAt,
		UptimeSeconds:      int64(time.Since(m.startedAt).Seconds()),
		PutObjectTotal:     m.PutObjectTotal.Load(),
		GetObjectTotal:     m.GetObjectTotal.Load(),
		DeleteObjectTotal:  m.DeleteObjectTotal.Load(),
		HeadObjectTotal:    m.HeadObjectTotal.Load(),
		ListObjectsTotal:   m.ListObjectsTotal.Load(),
		CreateBucketTotal:  m.CreateBucketTotal.Load(),
		DeleteBucketTotal:  m.DeleteBucketTotal.Load(),
		AuthFailures:       m.AuthFailures.Load(),
		AdminAuthFailures:  m.AdminAuthFailures.Load(),
		ChecksumFailures:   m.ChecksumFailures.Load(),
		FsyncFailures:      m.FsyncFailures.Load(),
		ObjectsQuarantined: m.ObjectsQuarantined.Load(),

		MetadataDecodeFailures: m.MetadataDecodeFailures.Load(),
		PanicsRecovered:        m.PanicsRecovered.Load(),
		BytesUploaded:          m.BytesUploaded.Load(),
		BytesDownloaded:        m.BytesDownloaded.Load(),
	}
}

// MetricsSnapshot is a JSON-serializable point-in-time copy of metrics.
//
// It feeds both exports: GET /_jay/metrics serialises it as JSON, and
// GET /metrics renders it in the Prometheus text format through
// PrometheusFamilies. A counter added here has to be added there too, and a
// test fails until it is.
type MetricsSnapshot struct {
	// StartedAt is when the process started counting. It is not in the JSON,
	// which has always carried uptime_seconds instead; the Prometheus export
	// uses it for jay_start_time_seconds, the form Prometheus expects.
	StartedAt time.Time `json:"-"`

	UptimeSeconds      int64 `json:"uptime_seconds"`
	PutObjectTotal     int64 `json:"put_object_total"`
	GetObjectTotal     int64 `json:"get_object_total"`
	DeleteObjectTotal  int64 `json:"delete_object_total"`
	HeadObjectTotal    int64 `json:"head_object_total"`
	ListObjectsTotal   int64 `json:"list_objects_total"`
	CreateBucketTotal  int64 `json:"create_bucket_total"`
	DeleteBucketTotal  int64 `json:"delete_bucket_total"`
	AuthFailures       int64 `json:"auth_failures"`
	AdminAuthFailures  int64 `json:"admin_auth_failures"`
	ChecksumFailures   int64 `json:"checksum_failures"`
	FsyncFailures      int64 `json:"fsync_failures"`
	ObjectsQuarantined int64 `json:"objects_quarantined"`

	MetadataDecodeFailures int64 `json:"metadata_decode_failures"`
	PanicsRecovered        int64 `json:"panics_recovered"`
	BytesUploaded          int64 `json:"bytes_uploaded"`
	BytesDownloaded        int64 `json:"bytes_downloaded"`
}
