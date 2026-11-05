package console

import (
	"net/http"
	"strings"
)

const (
	disabledHint = "web console is disabled: set JAY_CONSOLE_ENABLED=true (console.enabled in YAML) and restart"
	disabledPage = "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>jay console disabled</title></head>" +
		"<body><p>The jay web console is disabled. Set JAY_CONSOLE_ENABLED=true (console.enabled in YAML) and restart jay.</p></body></html>\n"
)

// serveDisabled is the only thing a disabled console says: a 404 that names the
// switch. No session, proxy or asset is reachable.
func serveDisabled(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", cspLocked)
		w.WriteHeader(http.StatusNotFound)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(disabledPage))
		}
		return
	}
	writeJSONError(w, http.StatusNotFound, disabledHint)
}
