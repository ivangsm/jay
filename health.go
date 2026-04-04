package main

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/ivangsm/jay/meta"
)

// HealthChecker provides liveness and readiness probes.
type HealthChecker struct {
	ready atomic.Bool
	db    *meta.DB
}

// NewHealthChecker creates a new HealthChecker (not ready by default).
func NewHealthChecker(db *meta.DB) *HealthChecker {
	return &HealthChecker{db: db}
}

// SetReady marks the service as ready to accept traffic.
func (hc *HealthChecker) SetReady(v bool) {
	hc.ready.Store(v)
}

// LivenessHandler always returns 200 — the process is alive.
func (hc *HealthChecker) LivenessHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "alive"})
}

// ReadinessHandler returns 200 if ready, 503 if not.
func (hc *HealthChecker) ReadinessHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if hc.ready.Load() {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "not_ready", "reason": "recovery in progress"})
	}
}
