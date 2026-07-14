package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivangsm/jay/meta"
)

func TestStartServerReturnsBindError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	shutdown, err := startServer(ln.Addr().String(), http.NewServeMux(), log, "test", "", "")
	if err == nil {
		if shutdown != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = shutdown(ctx)
			cancel()
		}
		t.Fatal("expected bind error")
	}
	if shutdown != nil {
		t.Fatal("shutdown function should be nil when bind fails")
	}
}

func TestStartServerBindsSynchronously(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	shutdown, err := startServer("127.0.0.1:0", http.NewServeMux(), log, "test", "", "")
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	if shutdown == nil {
		t.Fatal("missing shutdown function")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

// ── HealthChecker ────────────────────────────────────────────────────────────

// newTestHealthChecker returns a HealthChecker backed by a real bbolt DB in a
// temp dir. The returned meta.DB is registered for cleanup.
func newTestHealthChecker(t *testing.T, minFreeBytes int64) (*HealthChecker, *meta.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatalf("open meta db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewHealthChecker(db, dir, minFreeBytes), db
}

func readiness(t *testing.T, hc *HealthChecker) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	hc.ReadinessHandler(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	return rec.Code, rec.Body.String()
}

func TestReadinessHandler_NotReadyBeforeRecovery(t *testing.T) {
	hc, _ := newTestHealthChecker(t, 0)

	code, body := readiness(t, hc)
	if code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want 503", code)
	}
	if !strings.Contains(body, "recovery in progress") {
		t.Errorf("body should mention recovery, got %q", body)
	}
}

func TestReadinessHandler_ReadyWithHealthyDBAndDisk(t *testing.T) {
	hc, _ := newTestHealthChecker(t, 1) // 1 byte free is always satisfiable
	hc.SetReady(true)

	code, body := readiness(t, hc)
	if code != http.StatusOK {
		t.Errorf("status: got %d, want 200 (body %q)", code, body)
	}
	if !strings.Contains(body, `"ready"`) {
		t.Errorf("body should report ready, got %q", body)
	}
}

func TestReadinessHandler_ClosedDBReports503(t *testing.T) {
	hc, db := newTestHealthChecker(t, 0)
	hc.SetReady(true)
	_ = db.Close()

	code, body := readiness(t, hc)
	if code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want 503 (body %q)", code, body)
	}
	if !strings.Contains(body, "metadata db check failed") {
		t.Errorf("body should mention db check failure, got %q", body)
	}
}

func TestReadinessHandler_LowDiskSpaceReports503(t *testing.T) {
	// Threshold no filesystem can satisfy forces the low-disk branch.
	hc, _ := newTestHealthChecker(t, 1<<62)
	hc.SetReady(true)

	code, body := readiness(t, hc)
	if code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want 503 (body %q)", code, body)
	}
	if !strings.Contains(body, "low disk space") {
		t.Errorf("body should mention low disk space, got %q", body)
	}
}

func TestReadinessHandler_DiskCheckDisabledWithZeroThreshold(t *testing.T) {
	hc, _ := newTestHealthChecker(t, 0)
	hc.SetReady(true)

	code, _ := readiness(t, hc)
	if code != http.StatusOK {
		t.Errorf("status: got %d, want 200 when min_free_bytes=0", code)
	}
}

func TestLivenessHandler_AlwaysOK(t *testing.T) {
	hc, _ := newTestHealthChecker(t, 0)
	// Never marked ready — liveness must still be 200.
	rec := httptest.NewRecorder()
	hc.LivenessHandler(rec, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", rec.Code)
	}
}
