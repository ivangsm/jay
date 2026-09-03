package api

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The request ID is only useful if the value the client is handed is the value
// that appears in the server's log. These tests assert exactly that identity —
// header == access log line == <RequestId> of the error document — instead of
// asserting that a header merely exists, which is what let the ID be empty in
// every log line of a production jay while every response carried a real one.

// captureLog swaps the handler's logger for one writing JSON lines into a
// buffer, so a test can read back what the server logged.
func captureLog(h *Handler) *bytes.Buffer {
	buf := &bytes.Buffer{}
	h.log = slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return buf
}

// logLines decodes the captured JSON log lines whose msg matches.
func logLines(t *testing.T, buf *bytes.Buffer, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// accessLogRequestID returns the request_id of the one access-log line the
// request produced.
func accessLogRequestID(t *testing.T, buf *bytes.Buffer) string {
	t.Helper()
	lines := logLines(t, buf, "request")
	if len(lines) != 1 {
		t.Fatalf("want exactly 1 access log line, got %d: %s", len(lines), buf.String())
	}
	id, _ := lines[0]["request_id"].(string)
	return id
}

// assertCorrelated checks the recorded response and the captured log agree on
// one non-empty request ID, and returns it.
func assertCorrelated(t *testing.T, w *httptest.ResponseRecorder, buf *bytes.Buffer) string {
	t.Helper()
	header := w.Header().Get("x-amz-request-id")
	if header == "" {
		t.Fatalf("response carries no x-amz-request-id")
	}
	logged := accessLogRequestID(t, buf)
	if logged != header {
		t.Fatalf("request ID mismatch: header %q, access log %q", header, logged)
	}
	return header
}

// assertErrorBodyRequestID checks the S3 error document reports the same ID.
func assertErrorBodyRequestID(t *testing.T, w *httptest.ResponseRecorder, want string) {
	t.Helper()
	var errResp S3Error
	if err := xml.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("decode error body %q: %v", w.Body.String(), err)
	}
	if errResp.RequestID != want {
		t.Fatalf("error body RequestId %q, want %q", errResp.RequestID, want)
	}
}

func TestRequestID_AuthenticatedRequest_HeaderMatchesLog(t *testing.T) {
	h, _, tok, secret := setupTestHandler(t)
	buf := captureLog(h)

	req := httptest.NewRequest(http.MethodPut, "/reqid-bucket", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	assertCorrelated(t, w, buf)
}

// A rejected request is where the ID matters most: it is the one the caller
// quotes when reporting the failure.
func TestRequestID_RejectedRequest_HeaderMatchesLogAndBody(t *testing.T) {
	h, _, _, _ := setupTestHandler(t)
	buf := captureLog(h)

	req := httptest.NewRequest(http.MethodGet, "/", nil) // no credentials
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorBodyRequestID(t, w, assertCorrelated(t, w, buf))
}

// Presigned URLs are dispatched by withPresigned, which bypasses the
// credential middleware entirely. That branch used to mint its own ID.
func TestRequestID_PresignedRequest_HeaderMatchesLog(t *testing.T) {
	h, _, tok, secret := presignSetup(t)
	buf := captureLog(h)

	target := presignedTarget(t, presignSpec{
		accessKey: tok.TokenID, secret: secret,
		method: http.MethodGet, path: "/presign-bucket/hello.txt",
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, presignedRequest(t, http.MethodGet, target, "", presignSpec{}))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	assertCorrelated(t, w, buf)
}

// A presigned URL that does not verify is answered by rejectPresigned, which
// never had an ID at all: it runs before the middleware that used to mint one.
func TestRequestID_PresignedRejection_HeaderMatchesLogAndBody(t *testing.T) {
	h, _, tok, secret := presignSetup(t)
	buf := captureLog(h)

	target := flipLastHexDigit(presignedTarget(t, presignSpec{
		accessKey: tok.TokenID, secret: secret,
		method: http.MethodGet, path: "/presign-bucket/hello.txt",
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, presignedRequest(t, http.MethodGet, target, "", presignSpec{}))

	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorBodyRequestID(t, w, assertCorrelated(t, w, buf))
}

// The aws-chunked refusal logs its own warning line. Both it and the access
// log line must carry the ID the client received.
func TestRequestID_ChunkedRejection_HeaderMatchesBothLogLines(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	chunkedTestBucket(t, db, tok, "chunk-bkt")
	buf := captureLog(h)

	req := httptest.NewRequest(http.MethodPut, "/chunk-bkt/obj.txt", strings.NewReader(awsChunkedBody))
	req.Header.Set("Authorization", authHeader(tok, secret))
	req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("want 501, got %d: %s", w.Code, w.Body.String())
	}
	id := assertCorrelated(t, w, buf)
	assertErrorBodyRequestID(t, w, id)

	warns := logLines(t, buf, "rejected aws-chunked request body")
	if len(warns) != 1 {
		t.Fatalf("want exactly 1 rejection log line, got %d: %s", len(warns), buf.String())
	}
	if got, _ := warns[0]["request_id"].(string); got != id {
		t.Fatalf("rejection log request_id %q, want %q", got, id)
	}
}

// The pre-auth IP limiter answers before any credential is looked at. Its 429
// used to leave x-amz-request-id empty in both the header and the body.
func TestRequestID_RateLimited_HeaderMatchesLogAndBody(t *testing.T) {
	h, _, tok, secret := setupTestHandler(t)
	// Burst of 1 with a rate low enough that the bucket cannot refill inside
	// the test: the second request is refused deterministically.
	h.ipRateLimiter = newRateLimiter(RateLimiterConfig{Rate: 0.001, Burst: 1})

	first := httptest.NewRequest(http.MethodPut, "/ratelimit-bucket", nil)
	first.Header.Set("Authorization", authHeader(tok, secret))
	h.ServeHTTP(httptest.NewRecorder(), first)

	buf := captureLog(h)
	req := httptest.NewRequest(http.MethodPut, "/ratelimit-bucket-2", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorBodyRequestID(t, w, assertCorrelated(t, w, buf))
}

// Two requests must not share an ID — a constant would satisfy every other
// assertion here.
func TestRequestID_DistinctPerRequest(t *testing.T) {
	h, _, tok, secret := setupTestHandler(t)

	seen := map[string]bool{}
	for i := range 5 {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", authHeader(tok, secret))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		id := w.Header().Get("x-amz-request-id")
		if id == "" {
			t.Fatalf("request %d: empty x-amz-request-id", i)
		}
		if seen[id] {
			t.Fatalf("request %d: repeated request ID %q", i, id)
		}
		seen[id] = true
	}
}
