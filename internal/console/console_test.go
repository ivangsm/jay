package console

import (
	"bytes"
	"context"
	"crypto/tls"
	jsonv2 "encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ivangsm/jay/meta"
)

const (
	testAdminToken = "admin-token-0123456789-0123456789-abcdef"
	testPeer       = "192.0.2.10:5555"
)

// fakeHandler stands in for the admin API and for the S3 handler. It counts
// calls: "never called" is what most refusals have to prove.
type fakeHandler struct {
	mu       sync.Mutex
	calls    int
	last     *http.Request
	lastBody []byte

	status int
	header http.Header
	body   string
}

func (f *fakeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls++
	f.last = r.Clone(r.Context())
	f.lastBody = body
	status, header, resp := f.status, f.header, f.body
	f.mu.Unlock()

	for k, vs := range header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, resp)
}

func (f *fakeHandler) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeHandler) request() *http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

func (f *fakeHandler) respond(status int, header http.Header, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.header, f.body = status, header, body
}

// fakeTokens is a TokenSource that counts reads.
type fakeTokens struct {
	mu        sync.Mutex
	tokens    map[string]*meta.Token
	accounts  map[string]*meta.Account
	tokenErr  error
	acctErr   error
	tokenGets int
}

func (f *fakeTokens) GetToken(id string) (*meta.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenGets++
	if f.tokenErr != nil {
		return nil, f.tokenErr
	}
	if t, ok := f.tokens[id]; ok {
		return t, nil
	}
	return nil, meta.ErrTokenNotFound
}

func (f *fakeTokens) GetAccount(id string) (*meta.Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acctErr != nil {
		return nil, f.acctErr
	}
	if a, ok := f.accounts[id]; ok {
		return a, nil
	}
	return nil, meta.ErrAccountNotFound
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// auditLines returns the parsed "audit" log lines with the given action.
func (s *syncBuffer) auditLines(action string) []map[string]any {
	var out []map[string]any
	for line := range strings.SplitSeq(s.String(), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := jsonv2.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if m["msg"] == "audit" && m["action"] == action {
			out = append(out, m)
		}
	}
	return out
}

type harness struct {
	t     *testing.T
	h     *Handler
	admin *fakeHandler
	s3    *fakeHandler
	toks  *fakeTokens
	logs  *syncBuffer
	clock *fakeClock
	cfg   Config

	authResult atomic.Int32 // a LoginResult
	authCalls  atomic.Int32
	authSeen   atomic.Value // last candidate (string)

	signMu    sync.Mutex
	signCalls int
	signIDs   []string
	signQuery []string // RawQuery as SignS3 saw it
	signErr   error

	ready atomic.Bool
}

// testAssets is a tiny UI tree: enough to exercise hashing and serving.
func testAssets() fstest.MapFS {
	return fstest.MapFS{
		"index.html":          {Data: []byte(`<!doctype html><link rel="stylesheet" href="{{.Base}}console.css"><script type="module" src="{{.Base}}js/app.js"></script><p>{{.Version}}</p>`)},
		"console.css":         {Data: []byte("body{}")},
		"js/app.js":           {Data: []byte("export {}")},
		"favicon.svg":         {Data: []byte("<svg/>")},
		"fonts/x.woff2":       {Data: []byte("woff2")},
		"fonts/OFL.txt":       {Data: []byte("license")},
		"secret/not-an-asset": {Data: []byte("x")},
	}
}

func newHarness(t *testing.T, mutate ...func(*Config)) *harness {
	t.Helper()
	hn := &harness{
		t:     t,
		admin: &fakeHandler{},
		s3:    &fakeHandler{},
		toks: &fakeTokens{
			tokens:   map[string]*meta.Token{},
			accounts: map[string]*meta.Account{},
		},
		logs:  &syncBuffer{},
		clock: &fakeClock{t: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)},
	}
	hn.authResult.Store(int32(LoginAccepted))
	hn.ready.Store(true)
	hn.toks.tokens["tok1"] = &meta.Token{TokenID: "tok1", AccountID: "acc1", Status: "active"}
	hn.toks.accounts["acc1"] = &meta.Account{AccountID: "acc1", Status: "active"}

	hn.cfg = Config{
		Enabled:    true,
		AdminAPI:   hn.admin,
		S3:         hn.s3,
		AdminToken: testAdminToken,
		Authenticate: func(_ *http.Request, candidate string) LoginResult {
			hn.authCalls.Add(1)
			hn.authSeen.Store(candidate)
			return LoginResult(hn.authResult.Load())
		},
		SignS3: func(r *http.Request, tokenID string) error {
			hn.signMu.Lock()
			defer hn.signMu.Unlock()
			hn.signCalls++
			hn.signIDs = append(hn.signIDs, tokenID)
			hn.signQuery = append(hn.signQuery, r.URL.RawQuery)
			if hn.signErr != nil {
				return hn.signErr
			}
			r.URL.RawQuery += "&X-Jay-Signature=fake"
			return nil
		},
		Tokens: hn.toks,
		Ready:  hn.ready.Load,
		Info: Info{
			Version: "9.9.9", Commit: "abc1234", S3ListenAddr: ":9000",
			MaxObjectSize: 123, Actions: []string{"object:get", "object:put"},
		},
		Log:    slog.New(slog.NewJSONHandler(hn.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:    hn.clock.now,
		Assets: testAssets(),
	}
	for _, m := range mutate {
		m(&hn.cfg)
	}
	h, err := New(hn.cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	hn.h = h
	return hn
}

func (hn *harness) signCount() int {
	hn.signMu.Lock()
	defer hn.signMu.Unlock()
	return hn.signCalls
}

// serve runs one request and returns the recorded response.
func (hn *harness) serve(r *http.Request) *httptest.ResponseRecorder {
	hn.t.Helper()
	if r.RemoteAddr == "" || r.RemoteAddr == "192.0.2.1:1234" {
		r.RemoteAddr = testPeer
	}
	rec := httptest.NewRecorder()
	hn.h.ServeHTTP(rec, r)
	return rec
}

func jsonReq(method, target, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

// client is a signed-in browser: a cookie and the CSRF token that goes with it.
type client struct {
	hn     *harness
	cookie *http.Cookie
	csrf   string
}

func (hn *harness) login() *client {
	hn.t.Helper()
	rec := hn.serve(jsonReq(http.MethodPost, "/console/api/session", `{"token":"`+testAdminToken+`"}`))
	if rec.Code != http.StatusCreated {
		hn.t.Fatalf("login: status %d body %s", rec.Code, rec.Body)
	}
	var info SessionInfo
	if err := jsonv2.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		hn.t.Fatalf("login body: %v", err)
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == hn.h.cookieName {
			cookie = c
		}
	}
	if cookie == nil {
		hn.t.Fatalf("login set no session cookie")
	}
	return &client{hn: hn, cookie: cookie, csrf: info.CSRFToken}
}

// newReq builds an authenticated request. Unsafe methods carry the CSRF token.
func (c *client) newReq(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	r.AddCookie(c.cookie)
	if !safeMethod(method) {
		r.Header.Set(csrfHeader, c.csrf)
	}
	return r
}

func (c *client) do(method, target, body string) *httptest.ResponseRecorder {
	c.hn.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := c.newReq(method, target, rd)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	return c.hn.serve(r)
}

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := jsonv2.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return v
}

func TestNewEnabledRequiresEveryField(t *testing.T) {
	cases := map[string]func(*Config){
		"AdminAPI":     func(c *Config) { c.AdminAPI = nil },
		"S3":           func(c *Config) { c.S3 = nil },
		"Authenticate": func(c *Config) { c.Authenticate = nil },
		"SignS3":       func(c *Config) { c.SignS3 = nil },
		"Tokens":       func(c *Config) { c.Tokens = nil },
		"Ready":        func(c *Config) { c.Ready = nil },
		"Log":          func(c *Config) { c.Log = nil },
		"Version":      func(c *Config) { c.Info.Version = "" },
		"S3ListenAddr": func(c *Config) { c.Info.S3ListenAddr = "" },
		"Actions":      func(c *Config) { c.Info.Actions = nil },
		"short token":  func(c *Config) { c.AdminToken = strings.Repeat("a", 31) },
		"empty token":  func(c *Config) { c.AdminToken = "" },
		"no index":     func(c *Config) { c.Assets = fstest.MapFS{"console.css": {Data: []byte("x")}} },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			hn := newHarness(t)
			cfg := hn.cfg
			breakIt(&cfg)
			if h, err := New(cfg); err == nil || h != nil {
				t.Fatalf("New accepted a config with %s broken (handler=%v)", name, h)
			}
		})
	}
}

func TestNewDisabledNeedsNothing(t *testing.T) {
	h, err := New(Config{})
	if err != nil || h == nil {
		t.Fatalf("New(disabled) = %v, %v", h, err)
	}
}

func TestLoginAccepted(t *testing.T) {
	for _, tls := range []bool{false, true} {
		hn := newHarness(t, func(c *Config) { c.Info.TLS = tls })
		rec := hn.serve(jsonReq(http.MethodPost, "/console/api/session", `{"token":"`+testAdminToken+`"}`))
		if rec.Code != http.StatusCreated {
			t.Fatalf("tls=%v: status %d", tls, rec.Code)
		}
		cookies := rec.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("tls=%v: want one cookie, got %d", tls, len(cookies))
		}
		c := cookies[0]
		wantName := "jay_console"
		if tls {
			wantName = "__Host-jay_console"
		}
		if c.Name != wantName || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" ||
			c.Secure != tls || c.Domain != "" || c.MaxAge != 0 {
			t.Fatalf("tls=%v: cookie = %+v", tls, c)
		}
		if got := hn.authCalls.Load(); got != 1 {
			t.Fatalf("Authenticate calls = %d, want 1", got)
		}
		if got := hn.authSeen.Load(); got != testAdminToken {
			t.Fatalf("Authenticate saw %v", got)
		}
		info := decodeBody[SessionInfo](t, rec)
		if len(info.CSRFToken) != 43 || info.Version != "9.9.9" || info.Commit != "abc1234" || !info.Ready ||
			info.TLS != tls || info.S3ListenAddr != ":9000" || info.MaxObjectSize != 123 ||
			info.IdleTimeoutSeconds != 1800 || len(info.Actions) != 2 {
			t.Fatalf("session info = %+v", info)
		}
		if want := hn.clock.now().Add(8 * time.Hour); !info.ExpiresAt.Equal(want) {
			t.Fatalf("expires_at = %v, want %v", info.ExpiresAt, want)
		}
		if hn.h.sessions.len() != 1 {
			t.Fatalf("store holds %d sessions, want 1", hn.h.sessions.len())
		}
		lines := hn.logs.auditLines("console.login")
		if len(lines) != 1 || len(lines[0]["session"].(string)) != 8 || lines[0]["remote_ip"] != "192.0.2.10" {
			t.Fatalf("login audit = %v", lines)
		}
	}
}

func TestLoginRejectedAndLockedOutOpenNothing(t *testing.T) {
	hn := newHarness(t)
	hn.authResult.Store(int32(LoginRejected))
	rec := hn.serve(jsonReq(http.MethodPost, "/console/api/session", `{"token":"nope"}`))
	if rec.Code != http.StatusUnauthorized || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("rejected: status %d cookies %v", rec.Code, rec.Result().Cookies())
	}

	hn.authResult.Store(int32(LoginLockedOut))
	rec = hn.serve(jsonReq(http.MethodPost, "/console/api/session", `{"token":"nope"}`))
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "900" ||
		len(rec.Result().Cookies()) != 0 {
		t.Fatalf("locked out: status %d retry-after %q cookies %v", rec.Code, rec.Header().Get("Retry-After"), rec.Result().Cookies())
	}
	if hn.h.sessions.len() != 0 {
		t.Fatalf("a refused login left %d sessions", hn.h.sessions.len())
	}
	if len(hn.logs.auditLines("console.login")) != 0 {
		t.Fatalf("a refused login wrote a console.login audit line")
	}
}

func TestLoginUnknownResultOpensNothing(t *testing.T) {
	hn := newHarness(t)
	hn.authResult.Store(99)
	rec := hn.serve(jsonReq(http.MethodPost, "/console/api/session", `{"token":"x"}`))
	if rec.Code != http.StatusUnauthorized || hn.h.sessions.len() != 0 {
		t.Fatalf("status %d sessions %d", rec.Code, hn.h.sessions.len())
	}
}

func TestLoginBodyRules(t *testing.T) {
	hn := newHarness(t)
	t.Run("content type", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/console/api/session", strings.NewReader(`{"token":"x"}`))
		r.Header.Set("Content-Type", "text/plain")
		if rec := hn.serve(r); rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status %d", rec.Code)
		}
		r = httptest.NewRequest(http.MethodPost, "/console/api/session", strings.NewReader(`{"token":"x"}`))
		if rec := hn.serve(r); rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("no content type: status %d", rec.Code)
		}
	})
	t.Run("extra field", func(t *testing.T) {
		if rec := hn.serve(jsonReq(http.MethodPost, "/console/api/session", `{"token":"x","extra":1}`)); rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("not json", func(t *testing.T) {
		if rec := hn.serve(jsonReq(http.MethodPost, "/console/api/session", `nope`)); rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("empty token", func(t *testing.T) {
		if rec := hn.serve(jsonReq(http.MethodPost, "/console/api/session", `{"token":""}`)); rec.Code != http.StatusBadRequest {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("oversize", func(t *testing.T) {
		big := `{"token":"` + strings.Repeat("a", 5000) + `"}`
		if rec := hn.serve(jsonReq(http.MethodPost, "/console/api/session", big)); rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status %d", rec.Code)
		}
	})
	if got := hn.authCalls.Load(); got != 0 {
		t.Fatalf("Authenticate was called %d times for malformed logins", got)
	}
	if hn.h.sessions.len() != 0 {
		t.Fatalf("malformed logins left %d sessions", hn.h.sessions.len())
	}
}

func TestSessionInfoReflectsReadiness(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	hn.ready.Store(false)
	rec := c.do(http.MethodGet, "/console/api/session", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	info := decodeBody[SessionInfo](t, rec)
	if info.Ready || info.CSRFToken != c.csrf {
		t.Fatalf("info = %+v (csrf want %s)", info, c.csrf)
	}
}

// A secret that reaches a log line is a leak; the console handles four.
func TestNoSecretReachesTheLogs(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	c.do(http.MethodGet, "/console/api/admin/tokens", "")
	hn.s3.respond(200, nil, "x")
	c.do(http.MethodPut, "/console/api/s3/bkt/k?as_token=tok1", "bytes")
	c.do(http.MethodDelete, "/console/api/session", "")

	out := hn.logs.String()
	if out == "" {
		t.Fatal("no log output to check")
	}
	for name, secret := range map[string]string{
		"admin token": testAdminToken,
		"csrf token":  c.csrf,
		"session id":  c.cookie.Value,
		"session key": sessionKey(c.cookie.Value),
	} {
		if strings.Contains(out, secret) {
			t.Fatalf("log output contains the %s", name)
		}
	}
}

func TestRootRedirect(t *testing.T) {
	on := newHarness(t).h.RootRedirect()
	rec := httptest.NewRecorder()
	on.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/console/" {
		t.Fatalf("enabled: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = httptest.NewRecorder()
	on.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/elsewhere", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("other path: %d", rec.Code)
	}

	off, _ := New(Config{})
	rec = httptest.NewRecorder()
	off.RootRedirect().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled: %d", rec.Code)
	}
}

func TestConsoleRedirectsToSlash(t *testing.T) {
	hn := newHarness(t)
	rec := hn.serve(httptest.NewRequest(http.MethodGet, "/console", nil))
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/console/" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestDisabledServesNothing(t *testing.T) {
	// Built from the full config on purpose: even with everything wired, a
	// disabled console must not touch any of it.
	hn := newHarness(t, func(c *Config) { c.Enabled = false })
	paths := []struct{ method, target string }{
		{http.MethodGet, "/console/"},
		{http.MethodGet, "/console"},
		{http.MethodGet, "/console/static/abc/js/app.js"},
		{http.MethodPost, "/console/api/session"},
		{http.MethodGet, "/console/api/session"},
		{http.MethodGet, "/console/api/admin/tokens"},
		{http.MethodPut, "/console/api/s3/b/k?as_token=tok1"},
	}
	for _, p := range paths {
		for _, accept := range []string{"", "text/html,application/xhtml+xml"} {
			r := jsonReq(p.method, p.target, `{"token":"`+testAdminToken+`"}`)
			if accept != "" {
				r.Header.Set("Accept", accept)
			}
			rec := hn.serve(r)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s %s: status %d", p.method, p.target, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "JAY_CONSOLE_ENABLED") {
				t.Fatalf("%s %s: body does not name the variable: %q", p.method, p.target, rec.Body)
			}
			if len(rec.Result().Cookies()) != 0 {
				t.Fatalf("%s %s: disabled console set a cookie", p.method, p.target)
			}
		}
	}
	if hn.admin.count() != 0 || hn.s3.count() != 0 || hn.authCalls.Load() != 0 || hn.signCount() != 0 || hn.toks.tokenGets != 0 {
		t.Fatalf("disabled console touched a dependency: admin=%d s3=%d auth=%d sign=%d tokens=%d",
			hn.admin.count(), hn.s3.count(), hn.authCalls.Load(), hn.signCount(), hn.toks.tokenGets)
	}
}

func TestDisabledContentNegotiation(t *testing.T) {
	h, _ := New(Config{})
	r := httptest.NewRequest(http.MethodGet, "/console/", nil)
	r.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("html client got %q", ct)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/console/", nil))
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("api client got %q", ct)
	}
}

func TestUnknownConsolePathIs404(t *testing.T) {
	hn := newHarness(t)
	for _, p := range []string{"/console/nope", "/console/api/nope", "/console/api/admin"} {
		if rec := hn.serve(httptest.NewRequest(http.MethodGet, p, nil)); rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status %d", p, rec.Code)
		}
	}
}

var tlsState = tls.ConnectionState{}

func contextWith(ctx context.Context, k, v any) context.Context { return context.WithValue(ctx, k, v) }

// hideLength hides the concrete reader type so httptest cannot infer a length.
func hideLength(r io.Reader) io.Reader { return struct{ io.Reader }{r} }
