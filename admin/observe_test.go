package admin

// Tests for what the admin listener exposes about itself: GET /metrics and
// who may read it, the access line every request leaves, and the audit line
// every change leaves.
//
// The logging tests count lines. A test that only checked "the request
// answered 201" passed for years while creating an account wrote nothing at
// all; what is asserted here is the log itself.

import (
	"bufio"
	"bytes"
	jsonv2 "encoding/json/v2"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/ivangsm/jay/internal/accesslog"
	"github.com/ivangsm/jay/maintenance"
)

const testMetricsToken = "metrics-token-for-tests-of-32-chars-or-more"

var metricsBearer = "Bearer " + testMetricsToken

// observed is a control fixture whose admin handler logs JSON into a buffer
// and is served the way the listener serves it: /_jay, /metrics and a
// pprof-like guarded route on one mux, wrapped in Trace.
type observed struct {
	*controlFixture
	log    *bytes.Buffer
	traced http.Handler
	// guardedHits counts requests that got past RequireAdmin on /debug/.
	guardedHits int
}

func newObserved(t *testing.T, level slog.Level, edit func(*AdminConfig)) *observed {
	t.Helper()
	f := newControlFixture(t)
	o := &observed{controlFixture: f, log: &bytes.Buffer{}}

	cfg := AdminConfig{
		DB:            f.db,
		Store:         f.st,
		Auth:          f.au,
		AdminToken:    testAdminToken,
		Log:           slog.New(slog.NewJSONHandler(o.log, &slog.HandlerOptions{Level: level})),
		Metrics:       f.metrics,
		SigningSecret: testSigningKey,
		ListenAddr:    "jay.test:9000",
	}
	if edit != nil {
		edit(&cfg)
	}
	f.admin = NewHandler(cfg)
	t.Cleanup(func() { _ = f.admin.Close() })

	mux := http.NewServeMux()
	mux.Handle("/_jay/", f.admin)
	mux.Handle("/metrics", f.admin.PrometheusHandler())
	mux.Handle("/debug/", f.admin.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		o.guardedHits++
		_, _ = w.Write([]byte("profile"))
	})))
	o.traced = f.admin.Trace(mux)
	return o
}

// do issues one request through the traced listener.
func (o *observed) do(t *testing.T, method, target, body, authorization, remote string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	var req *http.Request
	if reader != nil {
		req = httptest.NewRequest(method, "http://jay.test"+target, reader)
	} else {
		req = httptest.NewRequest(method, "http://jay.test"+target, nil)
	}
	req.RemoteAddr = remote
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	w := httptest.NewRecorder()
	o.traced.ServeHTTP(w, req)
	return w
}

// logLine is one decoded JSON log line.
type logLine map[string]any

func (l logLine) str(key string) string { s, _ := l[key].(string); return s }

// lines decodes every line logged so far.
func (o *observed) lines(t *testing.T) []logLine {
	t.Helper()
	var out []logLine
	sc := bufio.NewScanner(bytes.NewReader(o.log.Bytes()))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var l logLine
		if err := jsonv2.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", sc.Text(), err)
		}
		out = append(out, l)
	}
	return out
}

func only(lines []logLine, msg string) []logLine {
	var out []logLine
	for _, l := range lines {
		if l.str("msg") == msg {
			out = append(out, l)
		}
	}
	return out
}

// requireOneAccessAndOneAudit asserts the request left exactly one access line
// and one audit line, and that every line it left — those two and any the
// quarantine manager writes on its own — carries the request ID the response
// carried. It returns the audit line.
func requireOneAccessAndOneAudit(t *testing.T, newLines []logLine, w *httptest.ResponseRecorder) logLine {
	t.Helper()
	id := w.Header().Get(accesslog.Header)
	if id == "" {
		t.Fatal("the response carries no request ID")
	}
	access, audit := only(newLines, "admin request"), only(newLines, "audit")
	if len(access) != 1 || len(audit) != 1 {
		t.Fatalf("want exactly one access line and one audit line, got %v", newLines)
	}
	for _, l := range newLines {
		if l.str("request_id") != id {
			t.Fatalf("line %v does not carry the response's request ID %q", l, id)
		}
	}
	if got := int(access[0]["status"].(float64)); got != w.Code {
		t.Fatalf("access line status %d, response %d", got, w.Code)
	}
	return audit[0]
}

// remote returns a distinct source address, so a test making many refused
// calls is not stopped by the lockout it is not testing.
func remote(i int) string {
	return "198.18." + strconv.Itoa(i/256) + "." + strconv.Itoa(i%256) + ":4000"
}

// sampleValue returns the value of one series in an exposition, spelled the
// way the exposition spells it (`name{label="value"}`).
func sampleValue(t *testing.T, body, series string) float64 {
	t.Helper()
	for line := range strings.SplitSeq(body, "\n") {
		if rest, ok := strings.CutPrefix(line, series+" "); ok {
			v, err := strconv.ParseFloat(rest, 64)
			if err != nil {
				t.Fatalf("%s: %v", line, err)
			}
			return v
		}
	}
	t.Fatalf("no series %s in:\n%s", series, body)
	return 0
}

// ---------------------------------------------------------------------------
// GET /metrics and who may read it
// ---------------------------------------------------------------------------

func TestPrometheus_DefaultTakesOnlyTheAdminToken(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, nil)

	for i, header := range []string{"", "Bearer", "Bearer " + testMetricsToken, "Bearer wrong-token-of-plenty-of-characters!!"} {
		w := o.do(t, http.MethodGet, "/metrics", "", header, remote(i))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("Authorization %q with no metrics token configured: want 401, got %d", header, w.Code)
		}
		if msg := errorMessage(t, w); msg != "unauthorized" {
			t.Fatalf("error = %q", msg)
		}
	}

	w := o.do(t, http.MethodGet, "/metrics", "", adminBearer, defaultRemote)
	requireStatus(t, w, http.StatusOK)
	if ct := w.Header().Get("Content-Type"); ct != maintenance.PrometheusContentType {
		t.Fatalf("Content-Type = %q, want %q", ct, maintenance.PrometheusContentType)
	}
	if !strings.Contains(w.Body.String(), "# TYPE jay_operations_total counter\n") {
		t.Fatalf("not a Prometheus exposition:\n%s", w.Body.String())
	}
}

// The metrics token opens GET /metrics and nothing else. On every other route
// — each /_jay endpoint and the pprof guard — it is refused like a wrong
// token, and nothing changes.
func TestPrometheus_TheMetricsTokenOpensMetricsAndNothingElse(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, func(c *AdminConfig) { c.MetricsToken = testMetricsToken })

	requireStatus(t, o.do(t, http.MethodGet, "/metrics", "", metricsBearer, defaultRemote), http.StatusOK)

	before := o.dbDigest(t)
	for i, route := range adminRoutes {
		w := o.do(t, route.method, route.path(o.controlFixture), route.body(o.controlFixture), metricsBearer, remote(i))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s with the metrics token: want 401, got %d: %s", route.signature, w.Code, w.Body.String())
		}
	}
	o.requireUnchanged(t, before, "the metrics token on admin routes")

	if w := o.do(t, http.MethodGet, "/debug/pprof/", "", metricsBearer, remote(100)); w.Code != http.StatusUnauthorized {
		t.Fatalf("pprof with the metrics token: want 401, got %d", w.Code)
	}
	if o.guardedHits != 0 {
		t.Fatal("the metrics token reached a route behind RequireAdmin")
	}

	// The admin token keeps working on /metrics too.
	requireStatus(t, o.do(t, http.MethodGet, "/metrics", "", adminBearer, remote(101)), http.StatusOK)
}

func TestPrometheus_PublicNeedsNoCredentialAndOpensNothingElse(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, func(c *AdminConfig) { c.MetricsPublic = true })

	w := o.do(t, http.MethodGet, "/metrics", "", "", defaultRemote)
	requireStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "jay_operations_total") {
		t.Fatalf("public scrape body:\n%s", w.Body.String())
	}
	if w := o.do(t, http.MethodGet, "/_jay/metrics", "", "", remote(1)); w.Code != http.StatusUnauthorized {
		t.Fatalf("public metrics opened /_jay/metrics: %d", w.Code)
	}
	if w := o.do(t, http.MethodGet, "/debug/pprof/", "", "", remote(2)); w.Code != http.StatusUnauthorized {
		t.Fatalf("public metrics opened pprof: %d", w.Code)
	}
	if n := o.metrics.AdminAuthFailures.Load(); n != 2 {
		t.Fatalf("admin auth failures = %d, want 2 (the public scrape is not one)", n)
	}
}

// A metrics token that cleared the failure count would let whoever holds it
// slip one valid scrape between every few guesses at the admin token and never
// be locked out. Only the admin token clears it.
func TestPrometheus_TheMetricsTokenNeverClearsTheBackoff(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, func(c *AdminConfig) { c.MetricsToken = testMetricsToken })
	const source = "192.0.2.200:1"

	for range maxAuthFailures - 1 {
		_ = o.do(t, http.MethodGet, "/_jay/tokens", "", "Bearer guess", source)
	}
	requireStatus(t, o.do(t, http.MethodGet, "/metrics", "", metricsBearer, source), http.StatusOK)
	_ = o.do(t, http.MethodGet, "/_jay/tokens", "", "Bearer guess", source)

	if w := o.do(t, http.MethodGet, "/_jay/tokens", "", adminBearer, source); w.Code != http.StatusUnauthorized {
		t.Fatalf("after %d guesses around a valid scrape the admin token got %d, want 401: the scrape reset the count",
			maxAuthFailures, w.Code)
	}
}

// Guessing on /metrics costs the same as guessing on /_jay: the same backoff,
// which then refuses both credentials from that address.
func TestPrometheus_FailuresShareTheListenersLockout(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, func(c *AdminConfig) { c.MetricsToken = testMetricsToken })
	const source = "192.0.2.201:1"

	for range maxAuthFailures {
		if w := o.do(t, http.MethodGet, "/metrics", "", "Bearer guess", source); w.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", w.Code)
		}
	}
	if w := o.do(t, http.MethodGet, "/metrics", "", metricsBearer, source); w.Code != http.StatusUnauthorized {
		t.Fatalf("locked-out source scraped with the metrics token: %d", w.Code)
	}
	if w := o.do(t, http.MethodGet, "/_jay/tokens", "", adminBearer, source); w.Code != http.StatusUnauthorized {
		t.Fatalf("failures on /metrics did not count toward the admin lockout: %d", w.Code)
	}
	if w := o.do(t, http.MethodGet, "/metrics", "", metricsBearer, "192.0.2.202:1"); w.Code != http.StatusOK {
		t.Fatalf("another address was locked out too: %d", w.Code)
	}
}

// Admin refusals are counted, apart from S3's: jay_auth_failures_total carries
// one series per listener, and each moves only with its own refusals.
func TestPrometheus_AdminRefusalsAreCountedApartFromS3(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, func(c *AdminConfig) { c.MetricsToken = testMetricsToken })
	s3Before := o.metrics.AuthFailures.Load()

	_ = o.do(t, http.MethodGet, "/_jay/tokens", "", "Bearer guess", remote(1))
	_ = o.do(t, http.MethodGet, "/_jay/tokens", "", metricsBearer, remote(2))
	_ = o.do(t, http.MethodGet, "/metrics", "", "", remote(3))
	_ = o.do(t, http.MethodGet, "/debug/pprof/", "", "Bearer guess", remote(4))
	// A refusal because the source is locked out is a refusal too.
	for range maxAuthFailures + 1 {
		_ = o.do(t, http.MethodGet, "/metrics", "", "Bearer guess", remote(5))
	}
	const wantAdmin = 4 + maxAuthFailures + 1

	// And one refusal on the S3 port.
	req := httptest.NewRequest(http.MethodGet, "http://jay.test/"+ctlBucket+"/"+healthyKey, nil)
	sw := httptest.NewRecorder()
	o.s3.ServeHTTP(sw, req)
	if sw.Code != http.StatusForbidden {
		t.Fatalf("anonymous S3 read of a private bucket: %d", sw.Code)
	}

	if got := o.metrics.AdminAuthFailures.Load(); got != wantAdmin {
		t.Fatalf("admin auth failures = %d, want %d", got, wantAdmin)
	}
	if got := o.metrics.AuthFailures.Load(); got != s3Before+1 {
		t.Fatalf("S3 auth failures = %d, want %d: admin refusals leaked into the S3 counter", got, s3Before+1)
	}

	w := o.do(t, http.MethodGet, "/metrics", "", adminBearer, defaultRemote)
	requireStatus(t, w, http.StatusOK)
	if got := sampleValue(t, w.Body.String(), `jay_auth_failures_total{surface="admin"}`); got != wantAdmin {
		t.Fatalf("exposed admin auth failures = %v, want %d", got, wantAdmin)
	}
	if got := sampleValue(t, w.Body.String(), `jay_auth_failures_total{surface="s3"}`); got != float64(s3Before+1) {
		t.Fatalf("exposed S3 auth failures = %v, want %d", got, s3Before+1)
	}
}

// A real PutObject through the S3 handler moves what /metrics reports.
func TestPrometheus_APutObjectMovesTheExposedCounters(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, nil)
	scrape := func() string {
		t.Helper()
		w := o.do(t, http.MethodGet, "/metrics", "", adminBearer, defaultRemote)
		requireStatus(t, w, http.StatusOK)
		return w.Body.String()
	}
	const puts, uploaded = `jay_operations_total{op="put_object"}`, "jay_uploaded_bytes_total"
	before := scrape()

	const body = "eleven bytes and then some"
	req := httptest.NewRequest(http.MethodPut, "http://jay.test/"+ctlBucket+"/fresh.txt", strings.NewReader(body))
	req.Header.Set("Authorization", bearer(ctlTokenID, ctlTokenSecret))
	w := httptest.NewRecorder()
	o.s3.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", w.Code, w.Body.String())
	}

	after := scrape()
	if d := sampleValue(t, after, puts) - sampleValue(t, before, puts); d != 1 {
		t.Fatalf("%s moved by %v after one PUT", puts, d)
	}
	if d := sampleValue(t, after, uploaded) - sampleValue(t, before, uploaded); d != float64(len(body)) {
		t.Fatalf("%s moved by %v after a %d-byte PUT", uploaded, d, len(body))
	}
}

// ExtraMetrics are appended to the scrape. One that would make the exposition
// invalid turns the scrape into a 500 — never a 200 with part of the metrics.
func TestPrometheus_ExtraMetrics(t *testing.T) {
	extra := []maintenance.MetricFamily{maintenance.Gauge("jay_test_reading", "a reading", 7)}
	o := newObserved(t, slog.LevelInfo, func(c *AdminConfig) {
		c.ExtraMetrics = func() []maintenance.MetricFamily { return extra }
	})

	w := o.do(t, http.MethodGet, "/metrics", "", adminBearer, defaultRemote)
	requireStatus(t, w, http.StatusOK)
	if got := sampleValue(t, w.Body.String(), "jay_test_reading"); got != 7 {
		t.Fatalf("jay_test_reading = %v", got)
	}

	extra = []maintenance.MetricFamily{maintenance.Counter("jay_operations_total", "a clash", 1)}
	w = o.do(t, http.MethodGet, "/metrics", "", adminBearer, defaultRemote)
	requireStatus(t, w, http.StatusInternalServerError)
	if strings.Contains(w.Body.String(), "# TYPE") {
		t.Fatalf("a failed render sent part of the exposition:\n%s", w.Body.String())
	}
	_ = errorMessage(t, w)
}

func TestPrometheus_OtherMethodsAre405AfterAuthentication(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, nil)
	requireStatus(t, o.do(t, http.MethodPost, "/metrics", "", "", remote(1)), http.StatusUnauthorized)

	w := o.do(t, http.MethodPost, "/metrics", "", adminBearer, defaultRemote)
	requireStatus(t, w, http.StatusMethodNotAllowed)
	if allow := w.Header().Get("Allow"); allow != "GET, HEAD" {
		t.Fatalf("Allow = %q", allow)
	}
	requireStatus(t, o.do(t, http.MethodHead, "/metrics", "", adminBearer, defaultRemote), http.StatusOK)
}

func TestPrometheus_WithoutMetricsIs503(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, func(c *AdminConfig) { c.Metrics = nil })
	w := o.do(t, http.MethodGet, "/metrics", "", adminBearer, defaultRemote)
	requireStatus(t, w, http.StatusServiceUnavailable)
	_ = errorMessage(t, w)
}

// ---------------------------------------------------------------------------
// The access line
// ---------------------------------------------------------------------------

// One line per request, carrying the ID the response carried, and never the
// query string: GET /_jay/tokens?account_id=… is logged as /_jay/tokens.
func TestTrace_OneAccessLinePerRequest(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, nil)
	const marker = "query-value-that-must-not-be-logged"

	w := o.do(t, http.MethodGet, "/_jay/tokens?account_id="+marker, "", adminBearer, defaultRemote)
	requireStatus(t, w, http.StatusOK)

	lines := o.lines(t)
	if len(lines) != 1 || lines[0].str("msg") != "admin request" {
		t.Fatalf("want exactly one access line, got %v", lines)
	}
	l := lines[0]
	if l.str("level") != "INFO" || l.str("method") != http.MethodGet || l.str("path") != "/_jay/tokens" ||
		l.str("remote_ip") != "192.0.2.1" || l.str("request_id") != w.Header().Get(accesslog.Header) {
		t.Fatalf("access line = %v (response id %q)", l, w.Header().Get(accesslog.Header))
	}
	if got := int(l["status"].(float64)); got != http.StatusOK {
		t.Fatalf("status %d", got)
	}
	if got := int(l["bytes"].(float64)); got != w.Body.Len() {
		t.Fatalf("bytes %d, body was %d", got, w.Body.Len())
	}
	if _, ok := l["duration"]; !ok {
		t.Fatal("no duration")
	}
	if strings.Contains(o.log.String(), marker) {
		t.Fatal("the query string reached the log")
	}
}

// A refused request is traced like any other, and the gate's own WARN line
// carries the same request ID.
func TestTrace_ARefusedRequestIsTracedWithItsID(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, nil)
	w := o.do(t, http.MethodPost, "/_jay/accounts", `{"name":"x"}`, "Bearer guess", defaultRemote)
	requireStatus(t, w, http.StatusUnauthorized)

	id := w.Header().Get(accesslog.Header)
	lines := o.lines(t)
	failure, access := only(lines, "admin auth failure"), only(lines, "admin request")
	if len(lines) != 2 || len(failure) != 1 || len(access) != 1 {
		t.Fatalf("want one auth failure and one access line, got %v", lines)
	}
	if id == "" || failure[0].str("request_id") != id || access[0].str("request_id") != id {
		t.Fatalf("request IDs: response %q, failure %q, access %q", id, failure[0].str("request_id"), access[0].str("request_id"))
	}
	if len(only(lines, "audit")) != 0 {
		t.Fatal("a refused request wrote an audit line")
	}
}

func TestTrace_TheInboundRequestIDIsNotAdopted(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, nil)
	const forged = "forged-request-id"
	req := httptest.NewRequest(http.MethodGet, "http://jay.test/_jay/tokens", nil)
	req.Header.Set("Authorization", adminBearer)
	req.Header.Set(accesslog.Header, forged)
	w := httptest.NewRecorder()
	o.traced.ServeHTTP(w, req)

	if got := w.Header().Get(accesslog.Header); got == "" || got == forged {
		t.Fatalf("response request ID %q", got)
	}
	if strings.Contains(o.log.String(), forged) {
		t.Fatal("the client's request ID reached the log")
	}
}

// Probes are logged at DEBUG while they answer 200 — a hundred of them write
// nothing at INFO — and at WARN when they do not.
func TestTrace_ProbesStayAtDebugUnlessTheyFail(t *testing.T) {
	status := http.StatusOK
	probe := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
	build := func(level slog.Level) (http.Handler, *bytes.Buffer) {
		buf := &bytes.Buffer{}
		h := NewHandler(AdminConfig{Log: slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: level}))})
		t.Cleanup(func() { _ = h.Close() })
		mux := http.NewServeMux()
		mux.Handle("/health/ready", probe)
		return h.Trace(mux, "/health/ready"), buf
	}
	get := func(h http.Handler) {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	}

	info, infoLog := build(slog.LevelInfo)
	for range 100 {
		get(info)
	}
	if infoLog.Len() != 0 {
		t.Fatalf("100 healthy probes wrote %d bytes at INFO:\n%s", infoLog.Len(), infoLog.String())
	}

	status = http.StatusServiceUnavailable
	get(info)
	if n := strings.Count(infoLog.String(), "\n"); n != 1 || !strings.Contains(infoLog.String(), `"level":"WARN"`) {
		t.Fatalf("a failing probe logged:\n%s\nwant one WARN line", infoLog.String())
	}

	status = http.StatusOK
	debug, debugLog := build(slog.LevelDebug)
	for range 100 {
		get(debug)
	}
	if n := strings.Count(debugLog.String(), `"level":"DEBUG","msg":"admin request"`); n != 100 {
		t.Fatalf("100 probes at DEBUG left %d lines: they must be logged, not excluded", n)
	}
}

// A panic in a handler on the admin listener becomes a JSON 500 that names
// the request, and the access line says 500 — not the 200 a recorder starts
// with.
func TestTrace_APanicIsA500ThatNamesTheRequest(t *testing.T) {
	buf := &bytes.Buffer{}
	metrics := maintenance.NewMetrics()
	h := NewHandler(AdminConfig{Log: slog.New(slog.NewJSONHandler(buf, nil)), Metrics: metrics})
	t.Cleanup(func() { _ = h.Close() })
	traced := h.Trace(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))

	w := httptest.NewRecorder()
	traced.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/_jay/anything", nil))

	requireStatus(t, w, http.StatusInternalServerError)
	_ = errorMessage(t, w)
	o := &observed{log: buf}
	lines := o.lines(t)
	panicLine, access := only(lines, "panic recovered"), only(lines, "admin request")
	if len(panicLine) != 1 || len(access) != 1 {
		t.Fatalf("lines: %v", lines)
	}
	id := w.Header().Get(accesslog.Header)
	if panicLine[0].str("request_id") != id || access[0].str("request_id") != id || int(access[0]["status"].(float64)) != 500 {
		t.Fatalf("panic %v, access %v, response id %q", panicLine[0], access[0], id)
	}
	if metrics.PanicsRecovered.Load() != 1 {
		t.Fatalf("panics recovered = %d", metrics.PanicsRecovered.Load())
	}
}

// Once the body has started there is no honest status left to send: the
// connection is aborted, and the access line keeps the status that went out.
func TestTrace_APanicAfterTheResponseStartedAbortsIt(t *testing.T) {
	buf := &bytes.Buffer{}
	h := NewHandler(AdminConfig{Log: slog.New(slog.NewJSONHandler(buf, nil))})
	t.Cleanup(func() { _ = h.Close() })
	traced := h.Trace(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("half a bo"))
		panic("boom")
	}))

	func() {
		defer func() {
			p := recover()
			err, ok := p.(error)
			if !ok || !errors.Is(err, http.ErrAbortHandler) {
				t.Fatalf("recovered %v, want http.ErrAbortHandler", p)
			}
		}()
		traced.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/_jay/x", nil))
	}()
	if !strings.Contains(buf.String(), `"response_started":true`) || !strings.Contains(buf.String(), `"msg":"admin request"`) {
		t.Fatalf("log:\n%s", buf.String())
	}
}

// ---------------------------------------------------------------------------
// The audit trail
// ---------------------------------------------------------------------------

// auditedRoutes is the action each state-changing route records. It is checked
// against the router: an endpoint that changes something cannot be added
// without deciding what its audit line says.
var auditedRoutes = map[string]string{
	"POST /accounts":                 "account.create",
	"POST /tokens":                   "token.create",
	"DELETE /tokens/{id...}":         "token.revoke",
	"POST /presign":                  "presign.issue",
	"DELETE /quarantine":             "quarantine.purge_all", // adminRoutes sends mode=all
	"POST /quarantine/revalidate":    "quarantine.revalidate",
	"POST /buckets":                  "bucket.create",
	"DELETE /buckets/{name}":         "bucket.delete",
	"PUT /buckets/{name}/policy":     "bucket.policy.put",
	"DELETE /buckets/{name}/policy":  "bucket.policy.delete",
	"PUT /buckets/{name}/visibility": "bucket.visibility.put",
}

func TestAudit_EveryStateChangingRouteHasAnAction(t *testing.T) {
	for _, r := range routes {
		sig := r.method + " " + r.pattern
		_, audited := auditedRoutes[sig]
		if r.method != http.MethodGet && !audited {
			t.Errorf("%s changes state but auditedRoutes gives it no action", sig)
		}
		if r.method == http.MethodGet && audited {
			t.Errorf("%s is a read but auditedRoutes gives it an action", sig)
		}
	}
}

// Every change leaves exactly one access line and one audit line, with the
// request ID of the response — and every read leaves the access line only.
func TestAudit_EveryChangeLeavesOneLineAndEveryReadNone(t *testing.T) {
	for _, route := range adminRoutes {
		t.Run(route.signature, func(t *testing.T) {
			o := newObserved(t, slog.LevelInfo, nil)
			w := o.do(t, route.method, route.path(o.controlFixture), route.body(o.controlFixture), adminBearer, defaultRemote)
			requireStatus(t, w, route.wantStatus)

			action, audited := auditedRoutes[route.signature]
			if !audited {
				lines := o.lines(t)
				if len(lines) != 1 || lines[0].str("msg") != "admin request" {
					t.Fatalf("a read logged %v, want only its access line", lines)
				}
				return
			}
			audit := requireOneAccessAndOneAudit(t, o.lines(t), w)
			if audit.str("action") != action || audit.str("level") != "INFO" || audit.str("remote_ip") != "192.0.2.1" {
				t.Fatalf("audit line = %v, want action %s at INFO", audit, action)
			}
		})
	}
}

// The IDs the audit line records are the IDs the operation produced.
func TestAudit_RecordsTheIDsItCreated(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, nil)

	w := o.do(t, http.MethodPost, "/_jay/accounts", `{"name":"audited"}`, adminBearer, defaultRemote)
	requireStatus(t, w, http.StatusCreated)
	var account struct {
		AccountID string `json:"account_id"`
	}
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &account); err != nil {
		t.Fatal(err)
	}
	audit := requireOneAccessAndOneAudit(t, o.lines(t), w)
	if audit.str("account_id") != account.AccountID || audit.str("name") != "audited" {
		t.Fatalf("audit line %v, created account %s", audit, account.AccountID)
	}

	o.log.Reset()
	w = o.do(t, http.MethodPost, "/_jay/tokens",
		`{"account_id":"`+account.AccountID+`","name":"scoped","allowed_actions":["object:get"],`+
			`"bucket_scope":["b1"],"expires_at":"2099-01-02T03:04:05Z"}`, adminBearer, defaultRemote)
	requireStatus(t, w, http.StatusCreated)
	var tok createdToken
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &tok); err != nil {
		t.Fatal(err)
	}
	audit = requireOneAccessAndOneAudit(t, o.lines(t), w)
	if audit.str("token_id") != tok.TokenID || audit.str("account_id") != account.AccountID ||
		audit.str("expires_at") != "2099-01-02T03:04:05Z" {
		t.Fatalf("audit line %v, created token %s", audit, tok.TokenID)
	}
	if actions, _ := audit["allowed_actions"].([]any); len(actions) != 1 || actions[0] != "object:get" {
		t.Fatalf("allowed_actions = %v", audit["allowed_actions"])
	}
	if scope, _ := audit["bucket_scope"].([]any); len(scope) != 1 || scope[0] != "b1" {
		t.Fatalf("bucket_scope = %v", audit["bucket_scope"])
	}

	o.log.Reset()
	w = o.do(t, http.MethodPost, "/_jay/buckets",
		`{"name":"audited-bucket","owner_account_id":"`+account.AccountID+`"}`, adminBearer, defaultRemote)
	requireStatus(t, w, http.StatusCreated)
	audit = requireOneAccessAndOneAudit(t, o.lines(t), w)
	created, err := o.db.GetBucket("audited-bucket")
	if err != nil {
		t.Fatal(err)
	}
	if audit.str("action") != "bucket.create" || audit.str("bucket") != "audited-bucket" ||
		audit.str("bucket_id") != created.ID || audit.str("owner_account_id") != account.AccountID {
		t.Fatalf("bucket.create audit line = %v, created bucket %+v", audit, created)
	}

	o.log.Reset()
	w = o.do(t, http.MethodDelete, "/_jay/buckets/audited-bucket", "", adminBearer, defaultRemote)
	requireStatus(t, w, http.StatusNoContent)
	audit = requireOneAccessAndOneAudit(t, o.lines(t), w)
	if audit.str("action") != "bucket.delete" || audit.str("bucket") != "audited-bucket" ||
		audit.str("bucket_id") != created.ID {
		t.Fatalf("bucket.delete audit line = %v, deleted bucket %s", audit, created.ID)
	}

	o.log.Reset()
	w = o.do(t, http.MethodDelete, "/_jay/quarantine", o.quarantineBody(sickKey), adminBearer, defaultRemote)
	requireStatus(t, w, http.StatusNoContent)
	audit = requireOneAccessAndOneAudit(t, o.lines(t), w)
	if audit.str("action") != "quarantine.purge" || audit.str("bucket_id") != o.bucketID || audit.str("key") != sickKey {
		t.Fatalf("single purge audit line = %v", audit)
	}
}

// An operation that did not happen leaves its access line, with its status,
// and no audit line.
func TestAudit_AFailedChangeWritesNoAuditLine(t *testing.T) {
	for _, c := range []struct {
		name, method, path, body string
		status                   int
	}{
		{"account without a name", http.MethodPost, "/_jay/accounts", `{}`, http.StatusBadRequest},
		{"token for no account", http.MethodPost, "/_jay/tokens", `{"account_id":"nope","allowed_actions":["*"]}`, http.StatusBadRequest},
		{"revoke of an unknown token", http.MethodDelete, "/_jay/tokens/nope", "", http.StatusNotFound},
		{"presign for an unknown token", http.MethodPost, "/_jay/presign", `{"token_id":"nope","method":"GET","bucket":"b"}`, http.StatusBadRequest},
		{"purge of an active object", http.MethodDelete, "/_jay/quarantine", `{"bucket_id":"x","key":"y"}`, http.StatusNotFound},
		{"bucket for no account", http.MethodPost, "/_jay/buckets", `{"name":"valid-name","owner_account_id":"ghost"}`, http.StatusBadRequest},
		{"bucket that exists", http.MethodPost, "/_jay/buckets", `{"name":"` + ctlBucket + `","owner_account_id":"x"}`, http.StatusBadRequest},
		{"delete of a bucket with objects", http.MethodDelete, "/_jay/buckets/" + ctlBucket, "", http.StatusConflict},
		{"delete of a missing bucket", http.MethodDelete, "/_jay/buckets/nope-nope", "", http.StatusNotFound},
		{"an inert policy", http.MethodPut, "/_jay/buckets/" + ctlBucket + "/policy", `{"statements":[]}`, http.StatusBadRequest},
		{"an unknown visibility", http.MethodPut, "/_jay/buckets/" + ctlBucket + "/visibility", `{"visibility":"open"}`, http.StatusBadRequest},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := newObserved(t, slog.LevelInfo, nil)
			w := o.do(t, c.method, c.path, c.body, adminBearer, defaultRemote)
			requireStatus(t, w, c.status)

			lines := o.lines(t)
			if n := len(only(lines, "audit")); n != 0 {
				t.Fatalf("a refused change wrote %d audit lines: %v", n, lines)
			}
			access := only(lines, "admin request")
			if len(access) != 1 || int(access[0]["status"].(float64)) != c.status {
				t.Fatalf("access lines %v, want one with status %d", access, c.status)
			}
		})
	}
}

// A purge-all that removed some objects and not others still records what it
// removed — those are gone for good — at WARN, with both counts.
func TestAudit_APartialPurgeAllIsRecordedAtWarn(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, nil)
	if err := o.db.QuarantineObject(o.bucketID, healthyKey); err != nil {
		t.Fatal(err)
	}
	o.blockRemoval(t, sickKey)

	w := o.do(t, http.MethodDelete, "/_jay/quarantine", `{"mode":"all"}`, adminBearer, defaultRemote)
	requireStatus(t, w, http.StatusInternalServerError)
	audits := only(o.lines(t), "audit")
	if len(audits) != 1 {
		t.Fatalf("audit lines: %v", audits)
	}
	a := audits[0]
	if a.str("level") != "WARN" || a.str("action") != "quarantine.purge_all" ||
		int(a["purged"].(float64)) != 1 || int(a["failed"].(float64)) != 1 {
		t.Fatalf("partial purge audit line = %v", a)
	}
}

// The secret of a new token exists in the response body and nowhere else.
func TestAudit_TheTokenSecretNeverReachesTheLog(t *testing.T) {
	o := newObserved(t, slog.LevelDebug, nil)
	w := o.do(t, http.MethodPost, "/_jay/tokens",
		`{"account_id":"`+o.account.AccountID+`","name":"t","allowed_actions":["*"]}`, adminBearer, defaultRemote)
	requireStatus(t, w, http.StatusCreated)
	var tok createdToken
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &tok); err != nil || tok.Secret == "" {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}

	if o.log.Len() == 0 {
		t.Fatal("nothing was logged; the check below would prove nothing")
	}
	if strings.Contains(o.log.String(), tok.Secret) {
		t.Fatalf("the token secret is in the log:\n%s", o.log.String())
	}
	if strings.Contains(o.log.String(), testAdminToken) {
		t.Fatal("the admin token is in the log")
	}
}

// Neither form of presigned URL reaches the log: not the URL, not its query
// string, not the signature on its own.
func TestAudit_ThePresignedURLNeverReachesTheLog(t *testing.T) {
	for _, style := range []struct{ name, extra, signature string }{
		{"jay", "", "X-Jay-Signature"},
		{"aws", `,"style":"aws","host":"s3.example.com"`, "X-Amz-Signature"},
	} {
		t.Run(style.name, func(t *testing.T) {
			o := newObserved(t, slog.LevelDebug, nil)
			w := o.do(t, http.MethodPost, "/_jay/presign",
				`{"token_id":"`+ctlTokenID+`","method":"GET","bucket":"`+ctlBucket+`","key":"`+healthyKey+`"`+style.extra+`}`,
				adminBearer, defaultRemote)
			requireStatus(t, w, http.StatusOK)
			var resp presignResponse
			if err := jsonv2.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(resp.URL)
			if err != nil {
				t.Fatal(err)
			}
			signature := u.Query().Get(style.signature)
			if signature == "" {
				t.Fatalf("%s is not in %s", style.signature, resp.URL)
			}

			audit := requireOneAccessAndOneAudit(t, o.lines(t), w)
			if audit.str("action") != "presign.issue" || audit.str("token_id") != ctlTokenID ||
				audit.str("bucket") != ctlBucket || audit.str("key") != healthyKey || audit.str("expires_at") == "" {
				t.Fatalf("presign audit line = %v", audit)
			}
			logged := o.log.String()
			for what, secret := range map[string]string{"URL": resp.URL, "query": u.RawQuery, "signature": signature} {
				if strings.Contains(logged, secret) {
					t.Fatalf("the presigned %s is in the log:\n%s", what, logged)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// AuthenticateAdminToken: the web console's login shares the listener's backoff
// ---------------------------------------------------------------------------

func (o *observed) login(candidate, remoteAddr string) CredentialResult {
	req := httptest.NewRequest(http.MethodPost, "http://jay.test/console/api/session", nil)
	req.RemoteAddr = remoteAddr
	return o.admin.AuthenticateAdminToken(req, candidate)
}

func TestAuthenticateAdminToken_AcceptsOnlyTheAdminTokenAndClearsFailures(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, func(c *AdminConfig) { c.MetricsToken = testMetricsToken })
	const source = "192.0.2.210:1"

	for range maxAuthFailures - 1 {
		if got := o.login("guess", source); got != CredentialRejected {
			t.Fatalf("a wrong token = %v, want CredentialRejected", got)
		}
	}
	if got := o.login(testMetricsToken, source); got != CredentialRejected {
		t.Fatalf("the metrics token = %v, want CredentialRejected: it is not an admin credential", got)
	}
	// The metrics token above was the fifth failure: the address is locked out,
	// so even the right token is refused until the window passes.
	if got := o.login(testAdminToken, source); got != CredentialLockedOut {
		t.Fatalf("the admin token after %d failures = %v, want CredentialLockedOut", maxAuthFailures, got)
	}

	// Under the limit the right token is accepted and wipes the count: a full
	// set of fresh failures is needed to lock the address again.
	const other = "192.0.2.211:1"
	for range maxAuthFailures - 1 {
		o.login("guess", other)
	}
	if got := o.login(testAdminToken, other); got != CredentialAccepted {
		t.Fatalf("the admin token = %v, want CredentialAccepted", got)
	}
	for range maxAuthFailures - 1 {
		o.login("guess", other)
	}
	if got := o.login(testAdminToken, other); got != CredentialAccepted {
		t.Fatalf("the accepted login did not clear the failure count: %v", got)
	}
}

// The backoff is ONE counter: failures at the login lock the address out of
// /_jay too, and failures on /_jay lock it out of the login. A login with its
// own counter would give an attacker a second set of guesses.
func TestAuthenticateAdminToken_SharesTheBackoffWithTheAdminAPI(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, nil)
	const source = "192.0.2.220:1"
	const elsewhere = "192.0.2.221:1"
	before := o.metrics.AdminAuthFailures.Load()

	for range maxAuthFailures {
		if got := o.login("guess", source); got != CredentialRejected {
			t.Fatalf("a wrong token = %v, want CredentialRejected", got)
		}
	}
	if got := o.metrics.AdminAuthFailures.Load() - before; got != maxAuthFailures {
		t.Fatalf("admin auth failures moved by %d, want %d: the login does not use the shared metric", got, maxAuthFailures)
	}

	// The correct bearer on /_jay from the locked address is a 401.
	if w := o.do(t, http.MethodGet, "/_jay/tokens", "", adminBearer, source); w.Code != http.StatusUnauthorized {
		t.Fatalf("login failures did not lock the address out of /_jay: %d", w.Code)
	}
	if got := o.login(testAdminToken, source); got != CredentialLockedOut {
		t.Fatalf("the locked address logging in with the right token = %v, want CredentialLockedOut", got)
	}
	// Another address is unaffected, in both directions.
	if w := o.do(t, http.MethodGet, "/_jay/tokens", "", adminBearer, elsewhere); w.Code != http.StatusOK {
		t.Fatalf("another address was locked out too: %d", w.Code)
	}
	if got := o.login(testAdminToken, elsewhere); got != CredentialAccepted {
		t.Fatalf("another address cannot log in: %v", got)
	}

	// And the other way round: failures on /_jay count at the login.
	const third = "192.0.2.222:1"
	for range maxAuthFailures {
		_ = o.do(t, http.MethodGet, "/_jay/tokens", "", "Bearer guess", third)
	}
	if got := o.login(testAdminToken, third); got != CredentialLockedOut {
		t.Fatalf("failures on /_jay did not lock the login: %v", got)
	}
}

// An unconfigured admin token must never be matched by an empty candidate.
func TestAuthenticateAdminToken_AnEmptyCandidateIsRejected(t *testing.T) {
	o := newObserved(t, slog.LevelInfo, nil)
	for i, candidate := range []string{"", " ", testAdminToken + " ", " " + testAdminToken} {
		if got := o.login(candidate, remote(300+i)); got != CredentialRejected {
			t.Fatalf("candidate %q = %v, want CredentialRejected", candidate, got)
		}
	}
}
