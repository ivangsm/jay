package ratelimit

import (
	"testing"
	"testing/synctest"
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
	// Con testing/synctest el reloj es falso y determinístico: antes esto era
	// un time.Sleep(5 ms) real, o sea una carrera con el planificador que en
	// una máquina cargada podía dormir de más (o de menos) y decidir el
	// resultado. Acá el tiempo avanza exactamente lo que se pide.
	synctest.Test(t, func(t *testing.T) {
		// 1 r/s → un token por segundo; burst=1.
		l := New(Config{Rate: 1, Burst: 1})
		t.Cleanup(l.Stop)

		if !l.Allow("k") {
			t.Fatal("el primer Allow con el bucket lleno tiene que pasar")
		}
		if l.Allow("k") {
			t.Fatal("el segundo Allow inmediato tiene que fallar (bucket vacío)")
		}

		// Justo por debajo del segundo: todavía no hay token entero.
		synctest.Sleep(900 * time.Millisecond)
		if l.Allow("k") {
			t.Fatal("a los 900 ms todavía no hay un token completo")
		}

		// Pasado el segundo, el token se repuso.
		synctest.Sleep(200 * time.Millisecond)
		if !l.Allow("k") {
			t.Fatal("pasado 1 s el token tiene que haberse repuesto")
		}
	})
}

// TestCleanupLoop_EvictsIdleBuckets cubre el loop de limpieza, que hasta ahora
// era intesteable: corre cada 5 min y desaloja los buckets sin uso por más de
// 1 h. Con el reloj falso de synctest se prueba en milisegundos.
func TestCleanupLoop_EvictsIdleBuckets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := New(Config{Rate: 10, Burst: 10})
		t.Cleanup(l.Stop)

		l.Allow("viejo")
		if n := l.bucketCount(); n != 1 {
			t.Fatalf("quiero 1 bucket, tengo %d", n)
		}

		// A los 30 min no se desaloja nada: el umbral de inactividad es 1 h.
		synctest.Sleep(30 * time.Minute)
		synctest.Wait()
		if n := l.bucketCount(); n != 1 {
			t.Fatalf("el bucket se desalojó antes de la hora: quedan %d", n)
		}

		// Pasada la hora de inactividad, el siguiente tick lo barre.
		synctest.Sleep(35 * time.Minute)
		synctest.Wait()
		if n := l.bucketCount(); n != 0 {
			t.Fatalf("el bucket inactivo no se desalojó: quedan %d", n)
		}

		// Y un bucket que se sigue usando sobrevive.
		l.Allow("activo")
		for range 12 {
			synctest.Sleep(10 * time.Minute)
			synctest.Wait()
			l.Allow("activo")
		}
		if n := l.bucketCount(); n != 1 {
			t.Fatalf("el bucket en uso se desalojó: quedan %d", n)
		}
	})
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
