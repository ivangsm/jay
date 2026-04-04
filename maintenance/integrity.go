package maintenance

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand"
	"sync/atomic"
)

// ReadVerifier wraps an io.Reader and computes SHA-256 on the fly.
// After the read completes, call Verify() to check against expected checksum.
type ReadVerifier struct {
	r        io.Reader
	h        io.Writer
	expected string
	buf      []byte
	sum      []byte
	done     bool
}

// NewReadVerifier wraps r and computes checksum during reading.
func NewReadVerifier(r io.Reader, expectedSHA256 string) *ReadVerifier {
	h := sha256.New()
	return &ReadVerifier{
		r:        io.TeeReader(r, h),
		h:        h,
		expected: expectedSHA256,
	}
}

func (rv *ReadVerifier) Read(p []byte) (int, error) {
	n, err := rv.r.Read(p)
	if err == io.EOF {
		rv.done = true
		rv.sum = rv.h.(interface{ Sum([]byte) []byte }).Sum(nil)
	}
	return n, err
}

// Valid returns true if the checksum matches. Only valid after EOF.
func (rv *ReadVerifier) Valid() bool {
	if !rv.done {
		return true // not finished, assume ok
	}
	return hex.EncodeToString(rv.sum) == rv.expected
}

// ActualChecksum returns the computed checksum. Only valid after EOF.
func (rv *ReadVerifier) ActualChecksum() string {
	return hex.EncodeToString(rv.sum)
}

// ReadChecker decides whether to verify reads probabilistically.
type ReadChecker struct {
	rate    float64 // 0.0-1.0
	checked atomic.Int64
	failed  atomic.Int64
}

// NewReadChecker creates a checker with the given verification rate.
// rate=0.05 means ~5% of reads are verified.
func NewReadChecker(rate float64) *ReadChecker {
	if rate < 0 {
		rate = 0
	}
	if rate > 1.0 {
		rate = 1.0
	}
	return &ReadChecker{rate: rate}
}

// ShouldVerify returns true if this read should be verified.
func (rc *ReadChecker) ShouldVerify() bool {
	if rc.rate <= 0 {
		return false
	}
	if rc.rate >= 1.0 {
		return true
	}
	return rand.Float64() < rc.rate
}

// RecordCheck records a verification result.
func (rc *ReadChecker) RecordCheck(valid bool) {
	rc.checked.Add(1)
	if !valid {
		rc.failed.Add(1)
	}
}

// Stats returns total checks and failures.
func (rc *ReadChecker) Stats() (checked, failed int64) {
	return rc.checked.Load(), rc.failed.Load()
}
