package main

// The admin listener as the server assembles it (buildAdminMux): the access
// log and audit trail that PND-0192 asked for, and GET /metrics (PND-0173).
//
// These go through the real mux on purpose. The admin package tests its own
// pieces; what can only be checked here is that the listener wires every path
// — /_jay, /metrics, pprof, the probes, an unknown path — through them.

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/internal/accesslog"
	"github.com/ivangsm/jay/internal/version"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

const (
	listenerAdminToken   = "admin-token-for-the-listener-tests-32+"
	listenerMetricsToken = "metrics-token-for-the-listener-tests-32+"
	listenerSigning      = "signing-secret-for-the-listener-tests!!"
)

type adminListener struct {
	handler http.Handler
	log     *bytes.Buffer
	hc      *HealthChecker
	db      *meta.DB
}

func newAdminListener(t *testing.T, level slog.Level, edit func(*Config)) *adminListener {
	t.Helper()
	dir := t.TempDir()
	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetSigningSecret(listenerSigning)
	t.Cleanup(func() { _ = db.Close() })
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: level}))
	hc := NewHealthChecker(db, dir, 1, Durability{})
	hc.SetReady(true)

	cfg := Config{
		DataDir:       dir,
		AdminToken:    listenerAdminToken,
		SigningSecret: listenerSigning,
		ListenAddr:    "jay.test:9000",
	}
	if edit != nil {
		edit(&cfg)
	}
	handler, adminHandler := buildAdminMux(cfg, db, st, auth.New(db), maintenance.NewMetrics(), hc, log)
	t.Cleanup(func() { _ = adminHandler.Close() })
	return &adminListener{handler: handler, log: buf, hc: hc, db: db}
}

// remoteN is a distinct source address per call, so refused calls in a table
// do not lock each other out.
func remoteN(i int) string { return "198.51.100." + strconv.Itoa(i%250+1) + ":5000" }

func (l *adminListener) call(t *testing.T, method, path, body, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	return l.callFrom(t, method, path, body, authorization, "192.0.2.10:5000")
}

func (l *adminListener) callFrom(t *testing.T, method, path, body, authorization, remote string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://jay.test"+path, strings.NewReader(body))
	req.RemoteAddr = remote
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	w := httptest.NewRecorder()
	l.handler.ServeHTTP(w, req)
	return w
}

// linesSince decodes the log lines written after offset bytes.
func (l *adminListener) linesSince(t *testing.T, offset int) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(l.log.String()[offset:]), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := jsonv2.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// requireAccessAndAudit is the check PND-0192 described: count the lines the
// request added, and find exactly one access line and one audit line — and
// nothing else — with the request ID the response carried.
func requireAccessAndAudit(t *testing.T, lines []map[string]any, w *httptest.ResponseRecorder, action string) map[string]any {
	t.Helper()
	if len(lines) != 2 {
		t.Fatalf("the request added %d log lines, want exactly 2 (access + audit): %v", len(lines), lines)
	}
	byMsg := map[string]map[string]any{}
	for _, line := range lines {
		byMsg[line["msg"].(string)] = line
	}
	access, audit := byMsg["admin request"], byMsg["audit"]
	if access == nil || audit == nil {
		t.Fatalf("want one access line and one audit line, got %v", lines)
	}
	id := w.Header().Get(accesslog.Header)
	if id == "" || access["request_id"] != id || audit["request_id"] != id {
		t.Fatalf("request IDs: response %q, access %v, audit %v", id, access["request_id"], audit["request_id"])
	}
	if audit["action"] != action {
		t.Fatalf("audit action %v, want %s", audit["action"], action)
	}
	return audit
}

func TestAdminListener_AccountAndTokenLeaveOneAccessAndOneAuditLine(t *testing.T) {
	l := newAdminListener(t, slog.LevelInfo, nil)
	admin := "Bearer " + listenerAdminToken

	before := l.log.Len()
	w := l.call(t, http.MethodPost, "/_jay/accounts", `{"name":"probe"}`, admin)
	if w.Code != http.StatusCreated {
		t.Fatalf("create account: %d %s", w.Code, w.Body.String())
	}
	var account struct {
		AccountID string `json:"account_id"`
	}
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &account); err != nil {
		t.Fatal(err)
	}
	audit := requireAccessAndAudit(t, l.linesSince(t, before), w, "account.create")
	if audit["account_id"] != account.AccountID {
		t.Fatalf("audit account_id %v, created %s", audit["account_id"], account.AccountID)
	}

	before = l.log.Len()
	w = l.call(t, http.MethodPost, "/_jay/tokens",
		`{"account_id":"`+account.AccountID+`","name":"deploy","allowed_actions":["object:get"]}`, admin)
	if w.Code != http.StatusCreated {
		t.Fatalf("create token: %d %s", w.Code, w.Body.String())
	}
	var token struct {
		TokenID string `json:"token_id"`
		Secret  string `json:"secret"`
	}
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &token); err != nil || token.Secret == "" {
		t.Fatalf("decode token: %v", err)
	}
	audit = requireAccessAndAudit(t, l.linesSince(t, before), w, "token.create")
	if audit["token_id"] != token.TokenID {
		t.Fatalf("audit token_id %v, created %s", audit["token_id"], token.TokenID)
	}

	if strings.Contains(l.log.String(), token.Secret) {
		t.Fatalf("the token secret is in the log:\n%s", l.log.String())
	}
}

// A probe loop — an orchestrator checking every five seconds — writes nothing
// at the default level. A probe that fails is a WARN line.
func TestAdminListener_HealthyProbesAreSilentAtInfo(t *testing.T) {
	l := newAdminListener(t, slog.LevelInfo, nil)

	before := l.log.Len()
	for range 100 {
		for _, p := range []string{healthReadyPath, healthLivePath, healthPath} {
			if w := l.call(t, http.MethodGet, p, "", ""); w.Code != http.StatusOK {
				t.Fatalf("GET %s: %d", p, w.Code)
			}
		}
	}
	if added := l.log.Len() - before; added != 0 {
		t.Fatalf("300 healthy probes wrote %d bytes at INFO:\n%s", added, l.log.String()[before:])
	}

	l.hc.SetReady(false)
	before = l.log.Len()
	w := l.call(t, http.MethodGet, healthReadyPath, "", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("not-ready probe: %d", w.Code)
	}
	lines := l.linesSince(t, before)
	if len(lines) != 1 || lines[0]["level"] != "WARN" || lines[0]["status"] != float64(503) ||
		lines[0]["request_id"] != w.Header().Get(accesslog.Header) {
		t.Fatalf("a failing readiness probe logged %v, want one WARN access line", lines)
	}
}

// Kept, not excluded: at DEBUG every probe has its line.
func TestAdminListener_ProbesAreLoggedAtDebug(t *testing.T) {
	l := newAdminListener(t, slog.LevelDebug, nil)
	for range 100 {
		_ = l.call(t, http.MethodGet, healthReadyPath, "", "")
	}
	lines := l.linesSince(t, 0)
	if len(lines) != 100 {
		t.Fatalf("100 probes at DEBUG left %d lines", len(lines))
	}
	for _, line := range lines {
		if line["level"] != "DEBUG" || line["path"] != healthReadyPath {
			t.Fatalf("probe line %v", line)
		}
	}
}

// Every path on the listener — whichever handler answers it — gets a request
// ID in the response and an access line carrying it.
func TestAdminListener_EveryPathIsTraced(t *testing.T) {
	l := newAdminListener(t, slog.LevelDebug, nil)
	admin := "Bearer " + listenerAdminToken

	for i, c := range []struct{ path, authorization string }{
		{"/_jay/tokens", admin},
		{"/_jay/tokens", ""},
		{"/metrics", admin},
		{"/debug/pprof/", admin},
		{"/debug/pprof/", ""},
		{healthReadyPath, ""},
		{healthLivePath, ""},
		{"/no-such-path", ""},
	} {
		before := l.log.Len()
		w := l.callFrom(t, http.MethodGet, c.path, "", c.authorization, remoteN(i))
		id := w.Header().Get(accesslog.Header)
		var access []map[string]any
		for _, line := range l.linesSince(t, before) {
			if line["msg"] == "admin request" {
				access = append(access, line)
			}
		}
		if id == "" || len(access) != 1 || access[0]["request_id"] != id || access[0]["path"] != c.path ||
			access[0]["status"] != float64(w.Code) {
			t.Fatalf("GET %s (%d): response id %q, access lines %v", c.path, w.Code, id, access)
		}
	}
}

func TestAdminListener_WhoMayScrapeMetrics(t *testing.T) {
	admin, metrics := "Bearer "+listenerAdminToken, "Bearer "+listenerMetricsToken
	type check struct {
		path, authorization string
		want                int
	}
	for _, c := range []struct {
		name   string
		edit   func(*Config)
		checks []check
	}{
		{"default: the admin token", nil, []check{
			{"/metrics", "", http.StatusUnauthorized},
			{"/metrics", metrics, http.StatusUnauthorized},
			{"/metrics", admin, http.StatusOK},
		}},
		{"a metrics token", func(c *Config) { c.MetricsToken = listenerMetricsToken }, []check{
			{"/metrics", "", http.StatusUnauthorized},
			{"/metrics", metrics, http.StatusOK},
			{"/metrics", admin, http.StatusOK},
			{"/_jay/metrics", metrics, http.StatusUnauthorized},
			{"/_jay/tokens", metrics, http.StatusUnauthorized},
			{"/_jay/quarantine", metrics, http.StatusUnauthorized},
			{"/debug/pprof/", metrics, http.StatusUnauthorized},
			{"/debug/pprof/cmdline", metrics, http.StatusUnauthorized},
		}},
		{"public", func(c *Config) { c.MetricsPublic = true }, []check{
			{"/metrics", "", http.StatusOK},
			{"/_jay/metrics", "", http.StatusUnauthorized},
			{"/debug/pprof/", "", http.StatusUnauthorized},
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := newAdminListener(t, slog.LevelInfo, c.edit)
			for i, chk := range c.checks {
				w := l.callFrom(t, http.MethodGet, chk.path, "", chk.authorization, remoteN(i))
				if w.Code != chk.want {
					t.Errorf("GET %s with %q: %d, want %d", chk.path, chk.authorization, w.Code, chk.want)
				}
			}
		})
	}
}

// metricValue returns one series' value from an exposition.
func metricValue(t *testing.T, body, series string) (float64, bool) {
	t.Helper()
	for line := range strings.SplitSeq(body, "\n") {
		if rest, ok := strings.CutPrefix(line, series+" "); ok {
			v, err := strconv.ParseFloat(rest, 64)
			if err != nil {
				t.Fatalf("%s: %v", line, err)
			}
			return v, true
		}
	}
	return 0, false
}

// The readings that used to live only in readiness are on /metrics too, taken
// fresh on each scrape.
func TestAdminListener_MetricsCarryTheReadinessReadings(t *testing.T) {
	l := newAdminListener(t, slog.LevelInfo, nil)
	scrape := func() string {
		t.Helper()
		w := l.call(t, http.MethodGet, "/metrics", "", "Bearer "+listenerAdminToken)
		if w.Code != http.StatusOK {
			t.Fatalf("scrape: %d %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}

	body := scrape()
	free, err := l.hc.freeBytes()
	if err != nil {
		t.Fatalf("statfs: %v", err)
	}
	if got, ok := metricValue(t, body, "jay_data_dir_free_bytes"); !ok || got <= 0 ||
		got < float64(free)*0.9 || got > float64(free)*1.1 {
		t.Fatalf("jay_data_dir_free_bytes = %v (present %v), statfs says %d", got, ok, free)
	}
	if got, ok := metricValue(t, body, "jay_metadata_db_up"); !ok || got != 1 {
		t.Fatalf("jay_metadata_db_up = %v (present %v), want 1", got, ok)
	}
	if got, ok := metricValue(t, body, "jay_metadata_db_ping_seconds"); !ok || got < 0 || got > dbPingTimeout.Seconds() {
		t.Fatalf("jay_metadata_db_ping_seconds = %v (present %v)", got, ok)
	}
	series := `jay_build_info{version="` + version.Version + `",commit="` + version.Commit + `"}`
	if got, ok := metricValue(t, body, series); !ok || got != 1 {
		t.Fatalf("%s = %v (present %v)\n%s", series, got, ok, body)
	}
	if !strings.Contains(body, "# TYPE jay_data_dir_free_bytes gauge\n") {
		t.Fatalf("free bytes is not declared a gauge:\n%s", body)
	}

	// A database that no longer answers is a 0 — and no latency, because an
	// error that comes back instantly is not a fast database.
	if err := l.db.Close(); err != nil {
		t.Fatal(err)
	}
	body = scrape()
	if got, ok := metricValue(t, body, "jay_metadata_db_up"); !ok || got != 0 {
		t.Fatalf("with the database closed jay_metadata_db_up = %v (present %v), want 0", got, ok)
	}
	if _, ok := metricValue(t, body, "jay_metadata_db_ping_seconds"); ok {
		t.Fatal("a failed ping still exported a latency")
	}
}

func TestCheckMetricsAccess(t *testing.T) {
	for _, c := range []struct {
		name    string
		token   string
		public  bool
		wantErr string
	}{
		{"neither", "", false, ""},
		{"public", "", true, ""},
		{"a proper token", listenerMetricsToken, false, ""},
		{"a short token", "too-short", false, "at least 32"},
		{"the admin token", listenerAdminToken, false, "must differ from JAY_ADMIN_TOKEN"},
		{"both", listenerMetricsToken, true, "mutually exclusive"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := checkMetricsAccess(Config{AdminToken: listenerAdminToken, MetricsToken: c.token, MetricsPublic: c.public})
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("error %v, want one containing %q", err, c.wantErr)
			}
		})
	}
}

// Only the public case is announced, and loudly.
func TestAnnounceMetricsAccess(t *testing.T) {
	for _, c := range []struct {
		cfg      Config
		wantWarn bool
	}{
		{Config{}, false},
		{Config{MetricsToken: listenerMetricsToken}, false},
		{Config{MetricsPublic: true}, true},
	} {
		var buf bytes.Buffer
		announceMetricsAccess(c.cfg, slog.New(slog.NewJSONHandler(&buf, nil)))
		if got := strings.Contains(buf.String(), `"level":"WARN"`); got != c.wantWarn {
			t.Errorf("public=%v token=%v: logged %q", c.cfg.MetricsPublic, c.cfg.MetricsToken != "", buf.String())
		}
	}
}

func TestLoadConfig_MetricsKeys(t *testing.T) {
	t.Run("env", func(t *testing.T) {
		t.Setenv("JAY_METRICS_TOKEN", listenerMetricsToken)
		t.Setenv("JAY_METRICS_PUBLIC", "true")
		cfg, err := LoadConfigFromSources("", slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MetricsToken != listenerMetricsToken || !cfg.MetricsPublic {
			t.Fatalf("token %q public %v", cfg.MetricsToken, cfg.MetricsPublic)
		}
	})
	t.Run("yaml", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "jay.yml")
		if err := writeFile(path, []byte("metrics:\n  token: "+listenerMetricsToken+"\n  public: false\n")); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfigFromSources(path, slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MetricsToken != listenerMetricsToken || cfg.MetricsPublic {
			t.Fatalf("token %q public %v", cfg.MetricsToken, cfg.MetricsPublic)
		}
	})
	t.Run("defaults", func(t *testing.T) {
		cfg, err := LoadConfigFromSources("", slog.New(slog.DiscardHandler))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MetricsToken != "" || cfg.MetricsPublic {
			t.Fatalf("defaults: token %q public %v — neither may default to anything", cfg.MetricsToken, cfg.MetricsPublic)
		}
	})
}
