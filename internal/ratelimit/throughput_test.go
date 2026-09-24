package ratelimit

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestNewThroughput_DisabledAtOrBelowZero(t *testing.T) {
	for _, bps := range []int64{0, -1} {
		th := NewThroughput(bps)
		if th.Enabled() || th.BytesPerSec() != 0 {
			t.Fatalf("NewThroughput(%d) must be disabled and report 0", bps)
		}
		// A disabled cap never blocks, whatever it is asked for.
		if err := th.WaitN(context.Background(), "k", 1<<40); err != nil {
			t.Fatalf("disabled WaitN: %v", err)
		}
	}
}

func TestNewThroughput_BurstIsOneSecondWithAFloor(t *testing.T) {
	if got := NewThroughput(10 << 20).burst; got != 10<<20 {
		t.Errorf("burst for 10 MiB/s = %d, want one second of budget (%d)", got, 10<<20)
	}
	if got := NewThroughput(1000).BytesPerSec(); got != 1000 {
		t.Errorf("BytesPerSec = %d, want the configured 1000", got)
	}
	if got := NewThroughput(1000).burst; got != minThroughputBurst {
		t.Errorf("burst for 1000 B/s = %d, want the floor %d", got, minThroughputBurst)
	}
}

// TestThroughput_ChargesTheRate measures on synctest's fake clock: after the
// burst, every further byte costs exactly its share of a second.
func TestThroughput_ChargesTheRate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const bps = 100 << 10
		th := NewThroughput(bps)
		ctx := context.Background()

		start := time.Now()
		if err := th.WaitN(ctx, "tok", bps); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed != 0 {
			t.Fatalf("the first second of budget waited %v, want 0", elapsed)
		}

		start = time.Now()
		if err := th.WaitN(ctx, "tok", 2*bps); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed != 2*time.Second {
			t.Fatalf("two more seconds of bytes waited %v, want 2s", elapsed)
		}
	})
}

// TestThroughput_LargerThanBurst: rate.Limiter.WaitN fails outright when n
// exceeds its burst. A body read larger than one second of budget must wait
// its time, not fail.
func TestThroughput_LargerThanBurst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const bps = 100 << 10
		th := NewThroughput(bps)

		start := time.Now()
		if err := th.WaitN(context.Background(), "tok", 5*bps); err != nil {
			t.Fatalf("n above the burst must be charged in pieces, got %v", err)
		}
		// One second came free with the burst; the other four are waited.
		if elapsed := time.Since(start); elapsed != 4*time.Second {
			t.Fatalf("waited %v, want 4s", elapsed)
		}
	})
}

func TestThroughput_KeysDoNotShareBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const bps = 100 << 10
		th := NewThroughput(bps)
		ctx := context.Background()

		if err := th.WaitN(ctx, "a", bps); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if err := th.WaitN(ctx, "b", bps); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed != 0 {
			t.Fatalf("key b waited %v on key a's spending", elapsed)
		}
	})
}

func TestThroughput_ContextEndsTheWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const bps = 100 << 10
		th := NewThroughput(bps)
		if err := th.WaitN(context.Background(), "tok", bps); err != nil {
			t.Fatal(err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- th.WaitN(ctx, "tok", bps) }()

		synctest.Wait()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("a cancelled wait returned %v, want context.Canceled", err)
		}
	})
}
