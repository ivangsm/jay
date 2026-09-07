package api

// A panic used to be the one request that left no trace (PND-0193): net/http
// recovered it, closed the connection with no response, and wrote the stack to
// the package-level logger — plain text in a stream that is JSON everywhere
// else, which the collector drops.
//
// Every assertion here is about the EVIDENCE, not about the process staying
// alive. "The server did not crash" passes just as well with the log still
// missing, and the log is the half that matters.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// panicFixture is the real middleware chain with a capturing logger behind it.
// The terminal handler is supplied by the test, so the panic travels through
// the same stack a production request does — not a reconstruction of it.
type panicFixture struct {
	h   *Handler
	log *bytes.Buffer
}

func newPanicFixture(t *testing.T) *panicFixture {
	t.Helper()
	h, _, _, _ := setupTestHandler(t)
	buf := &bytes.Buffer{}
	h.log = slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return &panicFixture{h: h, log: buf}
}

// serve pushes one request through the full chain with final at the bottom.
func (f *panicFixture) serve(final http.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.serveInto(w, final, r)
	return w
}

// serveInto is serve with the recorder supplied by the caller, for the cases
// where the chain re-panics and the response still has to be inspected.
func (f *panicFixture) serveInto(w http.ResponseWriter, final http.HandlerFunc, r *http.Request) {
	f.h.chain(final)(w, r)
}

// lines parses the captured log as one JSON object per line. A line that does
// not parse is a failure in itself: the whole point is that the panic stays
// inside the machine-readable stream.
func (f *panicFixture) lines(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	scanner := bufio.NewScanner(bytes.NewReader(f.log.Bytes()))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal(raw, &entry); err != nil {
			t.Fatalf("log line is not JSON: %q (%v)", raw, err)
		}
		out = append(out, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan log: %v", err)
	}
	return out
}

// findLine returns the single entry whose "msg" is msg.
func (f *panicFixture) findLine(t *testing.T, msg string) map[string]any {
	t.Helper()
	var found map[string]any
	for _, entry := range f.lines(t) {
		if entry["msg"] == msg {
			if found != nil {
				t.Fatalf("more than one %q line in the log:\n%s", msg, f.log.String())
			}
			found = entry
		}
	}
	if found == nil {
		t.Fatalf("no %q line in the log:\n%s", msg, f.log.String())
	}
	return found
}

func (f *panicFixture) hasLine(t *testing.T, msg string) bool {
	t.Helper()
	for _, entry := range f.lines(t) {
		if entry["msg"] == msg {
			return true
		}
	}
	return false
}

// requestIDFromXML pulls <RequestId> out of an S3 error document.
func requestIDFromXML(t *testing.T, body string) string {
	t.Helper()
	var doc S3Error
	if err := xml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("response is not an S3 error document: %v (%q)", err, body)
	}
	return doc.RequestID
}

func TestPanicInHandler_Answers500AndLogsBothLines(t *testing.T) {
	f := newPanicFixture(t)

	req := httptest.NewRequest(http.MethodGet, "/some-bucket/some-key", nil)
	w := f.serve(func(http.ResponseWriter, *http.Request) {
		panic("deliberate test panic")
	}, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d: %s", w.Code, w.Body.String())
	}

	header := w.Header().Get("x-amz-request-id")
	if header == "" {
		t.Fatal("no x-amz-request-id header on the 500")
	}
	if got := requestIDFromXML(t, w.Body.String()); got != header {
		t.Fatalf("<RequestId> is %q but the header says %q — the id the client "+
			"reports would not find the request", got, header)
	}

	// The error line: the trace that did not exist before.
	errLine := f.findLine(t, "panic recovered")
	if errLine["level"] != "ERROR" {
		t.Fatalf("panic line logged at level %v, want ERROR", errLine["level"])
	}
	if errLine["request_id"] != header {
		t.Fatalf("panic line request_id = %v, want %q", errLine["request_id"], header)
	}
	if errLine["panic"] != "deliberate test panic" {
		t.Fatalf("panic line does not carry the panic value: %v", errLine["panic"])
	}
	stack, _ := errLine["stack"].(string)
	if !strings.Contains(stack, "TestPanicInHandler_Answers500AndLogsBothLines") {
		t.Fatalf("stack does not reach the frame that panicked:\n%s", stack)
	}
	if errLine["method"] != http.MethodGet || errLine["path"] != "/some-bucket/some-key" {
		t.Fatalf("panic line does not name the request: %v %v", errLine["method"], errLine["path"])
	}
	if errLine["response_started"] != false {
		t.Fatalf("response_started = %v, want false", errLine["response_started"])
	}

	// The access line: it used to be skipped entirely, because withLogging
	// wrote it after next() returned and a panic jumps over that.
	accessLine := f.findLine(t, "request")
	if accessLine["request_id"] != header {
		t.Fatalf("access line request_id = %v, want %q", accessLine["request_id"], header)
	}
	if status, _ := accessLine["status"].(float64); int(status) != http.StatusInternalServerError {
		t.Fatalf("access line status = %v, want 500", accessLine["status"])
	}

	if got := f.h.metrics.PanicsRecovered.Load(); got != 1 {
		t.Fatalf("panics_recovered = %d, want 1", got)
	}
}

func TestPanicAfterResponseStarted_AbortsInsteadOfAppending(t *testing.T) {
	f := newPanicFixture(t)

	const partial = "the first half of an object"
	req := httptest.NewRequest(http.MethodGet, "/some-bucket/big-object", nil)

	w := httptest.NewRecorder()
	aborted := func() (rec any) {
		defer func() { rec = recover() }()
		f.serveInto(w, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(partial))
			panic("died halfway through the body")
		}, req)
		return nil
	}()

	// Tearing the connection down is the only honest answer once a 200 and part
	// of a body are already on the wire: appending an error document would hand
	// the client a truncated object under a success code.
	if err, ok := aborted.(error); !ok || err != http.ErrAbortHandler {
		t.Fatalf("want the chain to abort the connection, got panic %v", aborted)
	}
	if w.Body.String() != partial {
		t.Fatalf("body = %q, want the partial write untouched (%q)", w.Body.String(), partial)
	}

	errLine := f.findLine(t, "panic recovered")
	if errLine["response_started"] != true {
		t.Fatalf("response_started = %v, want true", errLine["response_started"])
	}
	if errLine["panic"] != "died halfway through the body" {
		t.Fatalf("panic value not logged: %v", errLine["panic"])
	}

	accessLine := f.findLine(t, "request")
	if status, _ := accessLine["status"].(float64); int(status) != http.StatusOK {
		t.Fatalf("access line status = %v, want 200 (that is what the client got)", accessLine["status"])
	}

	if got := f.h.metrics.PanicsRecovered.Load(); got != 1 {
		t.Fatalf("panics_recovered = %d, want 1", got)
	}
}

func TestErrAbortHandler_IsNotTreatedAsAFault(t *testing.T) {
	f := newPanicFixture(t)

	req := httptest.NewRequest(http.MethodGet, "/some-bucket/some-key", nil)
	rec := func() (rec any) {
		defer func() { rec = recover() }()
		f.serve(func(http.ResponseWriter, *http.Request) {
			panic(http.ErrAbortHandler)
		}, req)
		return nil
	}()

	// net/http documents ErrAbortHandler as the way to abandon a response on
	// purpose and suppresses its stack. Counting it as a fault would make the
	// metric lie the day any dependency uses it.
	if err, ok := rec.(error); !ok || err != http.ErrAbortHandler {
		t.Fatalf("ErrAbortHandler must pass through untouched, got %v", rec)
	}
	if f.hasLine(t, "panic recovered") {
		t.Fatalf("ErrAbortHandler produced a fault line:\n%s", f.log.String())
	}
	if got := f.h.metrics.PanicsRecovered.Load(); got != 0 {
		t.Fatalf("panics_recovered = %d, want 0", got)
	}

	// The access line still comes out: withLogging defers it.
	f.findLine(t, "request")
}
