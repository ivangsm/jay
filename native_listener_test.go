package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

// These tests assert the LISTENER, not the Config field. An empty
// JAY_NATIVE_ADDR used to reach defaultConfig() as if it had never been set,
// so the config looked fine while the native protocol came up on :4444 —
// wide open, carrying token secrets in the clear. Asserting cfg.NativeAddr
// alone would have gone green on the way to that.
//
// Every address here is "127.0.0.1:0" and no test dials a fixed port. That is
// deliberate: startDataListeners calls abortStartup — os.Exit(1) — when a
// listener fails to bind, so a test that reserves an ephemeral port and then
// races another process for it does not fail, it kills the whole test binary
// with no test name attached to the failure. The two facts that matter survive
// without a fixed port: whether ListenAndServe was reached at all (its
// shutdown function comes back nil when it was not), and what the server said
// it did.

// syncBuffer collects log output that is written from more than one
// goroutine. startServer logs "server listening" from the goroutine it spawns,
// so a plain bytes.Buffer read by the test is a data race — one the race
// detector reports without naming a failing test, because it fires after the
// test body has moved on.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startDataListenersForTest wires the dependencies startDataListeners needs,
// captures its log, and registers the teardown of whatever came up.
func startDataListenersForTest(t *testing.T, cfg Config) (func() error, *syncBuffer) {
	t.Helper()

	dir := t.TempDir()
	db, err := meta.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetSigningSecret("test-signing-secret-for-listener-tests")
	t.Cleanup(func() { _ = db.Close() })

	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	cfg.DataDir = dir
	// Port 0 lets the OS pick: a failed bind exits the process, so a test must
	// never hand this function an address someone else might hold.
	cfg.ListenAddr = "127.0.0.1:0"

	buf := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// startDataListeners tears the admin listener down if a data listener
	// fails to bind; there is no admin listener here, so it is a no-op.
	noAdmin := func(context.Context) error { return nil }

	shutdownS3, shutdownNative := startDataListeners(
		cfg, db, st, auth.New(db), log, maintenance.NewMetrics(), noAdmin,
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownS3(ctx)
		if shutdownNative != nil {
			_ = shutdownNative()
		}
	})
	return shutdownNative, buf
}

// assertNativeListenerAbsent checks the three statements that together mean no
// native listener exists: no shutdown function (ListenAndServe was never
// reached), no "listening" line, and the positive statement that it was
// switched off.
func assertNativeListenerAbsent(t *testing.T, shutdownNative func() error, logged *syncBuffer) {
	t.Helper()
	if shutdownNative != nil {
		t.Error("a native listener was started with an empty native_addr")
	}
	if strings.Contains(logged.String(), "native server listening") {
		t.Errorf("the native server reported itself listening: %s", logged.String())
	}
	if !strings.Contains(logged.String(), "native server disabled") {
		t.Errorf("nothing said the native server was disabled: %s", logged.String())
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// An empty JAY_NATIVE_ADDR must leave nothing listening.
func TestNativeListener_EmptyEnvVarBindsNothing(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_NATIVE_ADDR", "")

	cfg, err := LoadConfigFromSources("", quietLogger())
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.NativeAddr != "" {
		t.Fatalf("NativeAddr = %q, want empty: the off switch fell back to the default", cfg.NativeAddr)
	}

	shutdownNative, logged := startDataListenersForTest(t, cfg)
	assertNativeListenerAbsent(t, shutdownNative, logged)
}

// The positive control: the same path with an address does bind one, and says
// so. Without it, code that never started the native server at all would
// satisfy every other assertion here.
func TestNativeListener_AddressBinds(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_NATIVE_ADDR", "127.0.0.1:0")

	cfg, err := LoadConfigFromSources("", quietLogger())
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	shutdownNative, logged := startDataListenersForTest(t, cfg)
	if shutdownNative == nil {
		t.Fatal("no native listener was started")
	}
	if !strings.Contains(logged.String(), "native server listening") {
		t.Errorf("the native server did not report itself listening: %s", logged.String())
	}
}

// The YAML door must answer exactly like the environment one, or the defect
// has only moved.
func TestNativeListener_EmptyYAMLValueBindsNothing(t *testing.T) {
	clearJAYEnv(t)

	yamlPath := filepath.Join(t.TempDir(), "jay.yaml")
	if err := os.WriteFile(yamlPath, []byte("native_addr: \"\"\n"), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	cfg, err := LoadConfigFromSources(yamlPath, quietLogger())
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.NativeAddr != "" {
		t.Fatalf("NativeAddr = %q, want empty", cfg.NativeAddr)
	}

	shutdownNative, logged := startDataListenersForTest(t, cfg)
	assertNativeListenerAbsent(t, shutdownNative, logged)
}
