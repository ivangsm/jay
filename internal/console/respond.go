package console

import (
	jsonv2 "encoding/json/v2"
	"net/http"
)

// writeJSON writes v as the response body. Deterministic output keeps the
// bytes stable for tests and for anyone diffing responses.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := jsonv2.Marshal(v, jsonv2.Deterministic(true))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeJSONError writes the console's error shape: {"error": "..."}.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSONReason(w, status, message, "")
}

// writeJSONReason is writeJSONError plus a machine-readable "reason" the UI
// branches on (why the session is gone, for instance). An empty reason is
// omitted.
func writeJSONReason(w http.ResponseWriter, status int, message, reason string) {
	body := map[string]string{"error": message}
	if reason != "" {
		body["reason"] = reason
	}
	raw, err := jsonv2.Marshal(body, jsonv2.Deterministic(true))
	if err != nil {
		raw = []byte(`{"error":"internal error"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

// methodNotAllowed answers 405 with the Allow header a client needs to recover.
func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}
