package console

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxAdminBody bounds what the console forwards to the admin API. Its bodies
// are small JSON documents (a bucket policy is the largest).
const maxAdminBody = 1 << 20

// serveAdminProxy forwards /console/api/admin/<rest> to /_jay/<rest> with the
// admin token as the bearer. Nothing of the browser's request survives but the
// method, the path, the query and the content type: the cookie, the CSRF token
// and every other header stop here.
func (h *Handler) serveAdminProxy(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireSessionCSRF(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete:
	default:
		methodNotAllowed(w, "GET, POST, PUT, DELETE")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, pathAdmin)
	if rest == "" {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}

	body, ok := h.adminBody(w, r)
	if !ok {
		return
	}

	out := r.Clone(r.Context())
	out.URL = &url.URL{Path: "/_jay/" + rest, RawQuery: r.URL.RawQuery}
	out.RequestURI = out.URL.RequestURI()
	out.Header = make(http.Header)
	if ct := r.Header.Get("Content-Type"); ct != "" {
		out.Header.Set("Content-Type", ct)
	}
	out.Header.Set("Authorization", "Bearer "+h.adminToken)
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	out.TransferEncoding = nil
	out.Trailer = nil

	fw := newFilterWriter(w, filterOptions{allow: adminResponseHeader})
	h.adminAPI.ServeHTTP(fw, out)
	fw.finish()
}

// adminBody reads the request body under the 1 MiB cap. An oversize body is a
// 413 and the admin API is never called: a declared length is judged before a
// byte is read, and an undeclared one (chunked) is read in full under the cap
// first, because MaxBytesReader alone would let the admin handler start acting
// on a request the console is about to refuse.
func (h *Handler) adminBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.ContentLength > maxAdminBody {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return nil, false
	}
	if r.Body == nil || r.Body == http.NoBody {
		return nil, true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAdminBody+1))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "could not read request body")
		return nil, false
	}
	if len(body) > maxAdminBody {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return nil, false
	}
	return body, true
}

// adminResponseHeader is the allowlist of admin response headers the browser
// sees. The request id header is left out on purpose: the console's own
// listener already stamped one.
func adminResponseHeader(canonical string) bool {
	switch canonical {
	case "Content-Type", "Content-Length", "Retry-After":
		return true
	}
	return false
}
