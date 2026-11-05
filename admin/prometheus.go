package admin

import (
	"bytes"
	"net/http"

	"github.com/ivangsm/jay/maintenance"
)

// PrometheusHandler serves GET /metrics: the same counters as /_jay/metrics,
// in the Prometheus text exposition format, plus the families ExtraMetrics
// adds on every scrape.
//
// Who may scrape, in order:
//
//   - With MetricsPublic, anyone. That is an explicit opt-in for a private
//     network, and the server says so at startup.
//   - Otherwise the admin token, and the metrics token when one is
//     configured. The metrics token opens this route and no other, so a
//     Prometheus server never has to hold the credential that mints tokens.
//
// Refusals go through the same gate as the rest of the listener: the same
// per-address backoff, the same log line, the same counter.
func (h *Handler) PrometheusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.metricsPublic && !h.authorize(r, scopeMetrics) {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if h.metrics == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "metrics not available")
			return
		}

		families := h.metrics.Snapshot().PrometheusFamilies()
		if h.extraMetrics != nil {
			families = append(families, h.extraMetrics()...)
		}
		// Rendered in full before anything is sent, so a family that fails
		// validation is a 500 and never a 200 carrying half the metrics.
		var body bytes.Buffer
		if err := maintenance.WritePrometheus(&body, families); err != nil {
			h.log.Error("render prometheus metrics", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "internal error")
			return
		}
		w.Header().Set("Content-Type", maintenance.PrometheusContentType)
		_, _ = body.WriteTo(w)
	})
}
