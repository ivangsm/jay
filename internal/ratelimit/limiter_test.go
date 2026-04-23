package ratelimit

import (
	"testing"
	"time"
)

// --- New ---

func TestNew_DisabledWhenRateZero(t *testing.T) {
	l := New(Config{Rate: 0})
	if l.Enabled() {
		t.Fatal("expected disabled limiter when Rate=0")
	}
	if !l.Allow("any") {
		t.Fatal("disabled limiter must always allow")
	}
	l.Stop()
}

func TestNew_BurstDefaultsTwiceRate(t *testing.T) {
	l := New(Config{Rate: 100})
	if l.config.Burst != 200 {
		t.Fatalf("expected Burst=200, got %d", l.config.Burst)
	}
	l.Stop()
}

func TestNew_ExplicitBurstKept(t *testing.T) {
	l := New(Config{Rate: 100, Burst: 50})
	if l.config.Burst != 50 {
		t.Fatalf("expected Burst=50, got %d", l.config.Burst)
	}
	l.Stop()
}

func TestNew_LowRateZeroBurstDefaultsToOne(t *testing.T) {
	l := New(Config{Rate: 0.3, Burst: 0})
	if l.config.Burst < 1 {
		t.Fatalf("expected Burst>=1, got %d", l.config.Burst)
	}
	l.Stop()
}

// --- Enabled ---

func TestEnabled_NilLimiter(t *testing.T) {
	var l *Limiter
	if l.Enabled() {
		t.Fatal("nil limiter must not be enabled")
	}
}

func TestEnabled_RateZero(t *testing.T) {
	l := New(Config{Rate: 0})
	if l.Enabled() {
		t.Fatal("Rate=0 must not be enabled")
	}
	l.Stop()
}

func TestEnabled_RatePositive(t *testing.T) {
	l := New(Config{Rate: 1})
	if !l.Enabled() {
		t.Fatal("Rate>0 must be enabled")
	}
	l.Stop()
}

// --- Allow ---

func TestAllow_DisabledAlwaysTrue(t *testing.T) {
	l := New(Config{Rate: 0})
	for range 10 {
		if !l.Allow("k") {
			t.Fatal("disabled limiter must always return true")
		}
	}
	l.Stop()
}

func TestAllow_FirstCallTrue(t *testing.T) {
	l := New(Config{Rate: 10, Burst: 5})
	if !l.Allow("k") {
		t.Fatal("first call on a full bucket must be true")
	}
	l.Stop()
}

func TestAllow_ExhaustBurst(t *testing.T) {
	const burst = 5
	l := New(Config{Rate: 1, Burst: burst})
	for i := range burst {
		if !l.Allow("k") {
			t.Fatalf("call %d within burst should be true", i+1)
		}
	}
	if l.Allow("k") {
		t.Fatal("call after burst exhausted must be false")
	}
	l.Stop()
}

func TestAllow_KeysDoNotInterfere(t *testing.T) {
	const burst = 3
	l := New(Config{Rate: 1, Burst: burst})

	for range burst {
		l.Allow("a")
	}
	if l.Allow("a") {
		t.Fatal("key 'a' should be exhausted")
	}
	if !l.Allow("b") {
		t.Fatal("key 'b' should still have tokens")
	}
	l.Stop()
}

func TestAllow_TokensRefillOverTime(t *testing.T) {
	// 1000 r/s → one token per millisecond; burst=1
	// Two consecutive calls are separated by << 1 ms so the second fails.
	// After sleeping 5 ms the bucket holds 1 token again.
	l := New(Config{Rate: 1000, Burst: 1})

	if !l.Allow("k") {
		t.Fatal("first allow on full bucket must be true")
	}
	if l.Allow("k") {
		t.Fatal("immediate second allow must be false (bucket empty)")
	}

	time.Sleep(5 * time.Millisecond)

	if !l.Allow("k") {
		t.Fatal("allow after 5 ms must be true (tokens refilled)")
	}
	l.Stop()
}

func TestAllow_NilLimiter(t *testing.T) {
	var l *Limiter
	if !l.Allow("k") {
		t.Fatal("nil limiter Allow must return true")
	}
}

// --- RetryAfterSeconds ---

func TestRetryAfterSeconds_Disabled(t *testing.T) {
	l := New(Config{Rate: 0})
	if l.RetryAfterSeconds() != 0 {
		t.Fatal("disabled limiter must return 0")
	}
	l.Stop()
}

func TestRetryAfterSeconds_Rate10(t *testing.T) {
	l := New(Config{Rate: 10})
	if got := l.RetryAfterSeconds(); got != 1 {
		t.Fatalf("expected 1, got %d", got)
	}
	l.Stop()
}

func TestRetryAfterSeconds_RateHalf(t *testing.T) {
	l := New(Config{Rate: 0.5})
	if got := l.RetryAfterSeconds(); got != 2 {
		t.Fatalf("expected 2, got %d", got)
	}
	l.Stop()
}

func TestRetryAfterSeconds_NilLimiter(t *testing.T) {
	var l *Limiter
	if l.RetryAfterSeconds() != 0 {
		t.Fatal("nil limiter must return 0")
	}
}

// --- Stop ---

func TestStop_SafeMultipleTimes(t *testing.T) {
	l := New(Config{Rate: 10})
	l.Stop()
	l.Stop()
}

func TestStop_NilLimiterNoPanic(t *testing.T) {
	var l *Limiter
	l.Stop()
}

func TestStop_DisabledLimiterNoPanic(t *testing.T) {
	l := New(Config{Rate: 0})
	l.Stop()
	l.Stop()
}
