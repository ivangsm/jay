package ratelimit

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// minThroughputBurst is the smallest burst a Throughput grants: one buffered
// read of a native connection. A burst below the size of a single read would
// only split that read into more waits, without making the rate any smoother.
const minThroughputBurst = 64 << 10

// Throughput caps bytes per second per key. It is the byte-denominated sibling
// of Limiter and behaves differently on purpose: Limiter refuses a request,
// Throughput delays its bytes. A request has already been admitted by the time
// its body moves, and refusing it halfway would cost more than it saves — so
// the bytes wait instead, and the peer is slowed through TCP's own flow control.
//
// Each key gets one golang.org/x/time/rate limiter, the same type the scrubber
// throttles its reads with. The burst is one second of budget, never less than
// minThroughputBurst, so an idle key starts with a second's worth to spend.
//
// Keys are never evicted. The native server keys by token ID, and token IDs
// are issued by the operator, so the set is bounded by the tokens that exist —
// unlike Limiter, whose HTTP keys include client IPs and have to be swept.
//
// A nil *Throughput is valid and disabled: WaitN returns at once.
type Throughput struct {
	limit rate.Limit
	burst int

	keys sync.Map // key string → *rate.Limiter
}

// NewThroughput returns a cap of bytesPerSec per key, or nil — the disabled
// cap — when bytesPerSec <= 0.
func NewThroughput(bytesPerSec int64) *Throughput {
	if bytesPerSec <= 0 {
		return nil
	}
	return &Throughput{
		limit: rate.Limit(bytesPerSec),
		burst: int(max(bytesPerSec, minThroughputBurst)),
	}
}

// Enabled reports whether WaitN can ever block.
func (t *Throughput) Enabled() bool {
	return t != nil
}

// BytesPerSec is the configured cap, or 0 when disabled.
func (t *Throughput) BytesPerSec() int64 {
	if t == nil {
		return 0
	}
	return int64(t.limit)
}

// WaitN blocks until key may move n more bytes, or ctx is done. n may exceed
// the burst: it is charged a burst at a time, so a large n waits as long as
// the rate says rather than failing the way rate.Limiter.WaitN would.
func (t *Throughput) WaitN(ctx context.Context, key string, n int) error {
	if t == nil || n <= 0 {
		return nil
	}
	lim := t.limiterFor(key)
	for n > 0 {
		chunk := min(n, t.burst)
		if err := lim.WaitN(ctx, chunk); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

func (t *Throughput) limiterFor(key string) *rate.Limiter {
	if v, ok := t.keys.Load(key); ok {
		return v.(*rate.Limiter)
	}
	v, _ := t.keys.LoadOrStore(key, rate.NewLimiter(t.limit, t.burst))
	return v.(*rate.Limiter)
}
