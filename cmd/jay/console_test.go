package main

// The web console as the server assembles it: the real admin mux, the real S3
// handler, real data in a temp dir, and a real HTTP client with a cookie jar.
// Every check asserts an effect — what meta holds, what the store holds, what
// the log recorded — never the text of a response.

import (
	"bytes"
	"encoding/xml"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	jsonv2 "encoding/json/v2"

	"github.com/ivangsm/jay/api"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

const consoleCSRFHeader = "X-Jay-Console-CSRF"

type consoleFixture struct {
	srv  *httptest.Server
	cli  *http.Client
	db   *meta.DB
	st   *store.Store
	hc   *HealthChecker
	log  *syncBuffer
	csrf string
}

func newConsoleFixture(t *testing.T, enabled bool) *consoleFixture {
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

	buf := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	hc := NewHealthChecker(db, dir, 1, Durability{})
	hc.SetReady(true)

	cfg := Config{
		DataDir:        dir,
		AdminToken:     listenerAdminToken,
		SigningSecret:  listenerSigning,
		ListenAddr:     "jay.test:9000",
		ConsoleEnabled: enabled,
	}
	au := auth.New(db)
	metrics := maintenance.NewMetrics()
	db.SetTokenInvalidateHook(au.InvalidateToken)
	handler, adminHandler, err := buildAdminMux(cfg, db, st, au, metrics, hc, log,
		newS3Handler(cfg, db, st, au, log, metrics))
	if err != nil {
		t.Fatalf("build admin mux: %v", err)
	}
	t.Cleanup(func() { _ = adminHandler.Close() })

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("jar: %v", err)
	}
	// Redirects are asserted, not followed.
	cli := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return &consoleFixture{srv: srv, cli: cli, db: db, st: st, hc: hc, log: buf}
}

func (f *consoleFixture) do(t *testing.T, method, path string, body io.Reader, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+path, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if f.csrf != "" && method != http.MethodGet && method != http.MethodHead {
		req.Header.Set(consoleCSRFHeader, f.csrf)
	}
	resp, err := f.cli.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, data
}

func (f *consoleFixture) login(t *testing.T) {
	t.Helper()
	resp, body := f.do(t, http.MethodPost, "/console/api/session",
		strings.NewReader(`{"token":"`+listenerAdminToken+`"}`),
		map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("login: status %d: %s", resp.StatusCode, body)
	}
	var info struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := jsonv2.Unmarshal(body, &info); err != nil || info.CSRFToken == "" {
		t.Fatalf("login response has no csrf_token: %s (%v)", body, err)
	}
	f.csrf = info.CSRFToken
}

func (f *consoleFixture) adminJSON(t *testing.T, method, path, body string, want int, out any) {
	t.Helper()
	resp, data := f.do(t, method, "/console/api/admin"+path, strings.NewReader(body),
		map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, data)
	}
	if out != nil {
		if err := jsonv2.Unmarshal(data, out); err != nil {
			t.Fatalf("decode %s: %v: %s", path, err, data)
		}
	}
}

func (f *consoleFixture) logLines(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(f.log.String()), "\n") {
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

// objectBytes reads an object the way no console code does: meta for the
// location, then the store directly.
func (f *consoleFixture) objectBytes(t *testing.T, bucket, key string) ([]byte, bool) {
	t.Helper()
	b, err := f.db.GetBucket(bucket)
	if err != nil {
		t.Fatalf("get bucket %s: %v", bucket, err)
	}
	obj, err := f.db.GetObjectMeta(b.ID, key)
	if err != nil || obj == nil || obj.State != "active" {
		return nil, false
	}
	file, err := f.st.ReadObject(obj.LocationRef)
	if err != nil {
		t.Fatalf("read object from store: %v", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("read object bytes: %v", err)
	}
	return data, true
}

// provision creates an account, a token with the given actions and a bucket,
// all through the console's own admin proxy.
func (f *consoleFixture) provision(t *testing.T, bucket string, actions []string) (accountID, tokenID string) {
	t.Helper()
	var acct struct {
		AccountID string `json:"account_id"`
	}
	f.adminJSON(t, http.MethodPost, "/accounts", `{"name":"Console Test"}`, http.StatusCreated, &acct)
	tokenID = f.token(t, acct.AccountID, actions)
	f.adminJSON(t, http.MethodPost, "/buckets",
		`{"name":"`+bucket+`","owner_account_id":"`+acct.AccountID+`"}`, http.StatusCreated, nil)
	return acct.AccountID, tokenID
}

func (f *consoleFixture) token(t *testing.T, accountID string, actions []string) string {
	t.Helper()
	req := map[string]any{"account_id": accountID, "name": "t", "allowed_actions": actions}
	body, err := jsonv2.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var tok struct {
		TokenID string `json:"token_id"`
	}
	f.adminJSON(t, http.MethodPost, "/tokens", string(body), http.StatusCreated, &tok)
	return tok.TokenID
}

func (f *consoleFixture) s3(t *testing.T, method, bucketAndKey, query string, body []byte, hdr map[string]string) (*http.Response, []byte) {
	t.Helper()
	path := "/console/api/s3/" + bucketAndKey
	if query != "" {
		path += "?" + query
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	return f.do(t, method, path, rdr, hdr)
}

func TestConsole_DisabledByDefault(t *testing.T) {
	f := newConsoleFixture(t, false)

	for _, path := range []string{"/console/", "/console", "/console/api/session", "/console/static/x/app.js", "/"} {
		resp, body := f.do(t, http.MethodGet, path, nil, map[string]string{"Accept": "application/json"})
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", path, resp.StatusCode)
		}
		if path != "/" && !bytes.Contains(body, []byte("JAY_CONSOLE_ENABLED")) {
			t.Errorf("GET %s: the 404 does not say how to enable the console: %s", path, body)
		}
	}

	// A login attempt is not a way in, and it leaves no session behind.
	resp, _ := f.do(t, http.MethodPost, "/console/api/session",
		strings.NewReader(`{"token":"`+listenerAdminToken+`"}`),
		map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("login on a disabled console: status %d, want 404", resp.StatusCode)
	}
	if len(resp.Cookies()) != 0 {
		t.Errorf("a disabled console set a cookie: %v", resp.Cookies())
	}
	// And the proxies are not mounted: nothing reaches the admin API through them.
	resp, _ = f.do(t, http.MethodPost, "/console/api/admin/accounts", strings.NewReader(`{"name":"x"}`),
		map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("admin proxy on a disabled console: status %d, want 404", resp.StatusCode)
	}
	accounts, err := f.db.ListAccounts()
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	if len(accounts) != 0 {
		t.Errorf("a disabled console created %d accounts", len(accounts))
	}
}

func TestConsole_EnabledFlow(t *testing.T) {
	f := newConsoleFixture(t, true)

	resp, _ := f.do(t, http.MethodGet, "/", nil, nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/console/" {
		t.Fatalf("GET /: status %d Location %q, want 302 /console/", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Wrong token: no session, nothing behind the door.
	resp, _ = f.do(t, http.MethodPost, "/console/api/session", strings.NewReader(`{"token":"nope"}`),
		map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login: status %d, want 401", resp.StatusCode)
	}
	resp, _ = f.do(t, http.MethodGet, "/console/api/admin/accounts", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin proxy without a session: status %d, want 401", resp.StatusCode)
	}

	f.login(t)

	// Account through the proxy; the effect is in meta, and the audit line joins
	// the access line by request id with the client's address.
	var acct struct {
		AccountID string `json:"account_id"`
	}
	f.adminJSON(t, http.MethodPost, "/accounts", `{"name":"Acme"}`, http.StatusCreated, &acct)
	accounts, err := f.db.ListAccounts()
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	if !slices.ContainsFunc(accounts, func(a meta.Account) bool { return a.AccountID == acct.AccountID && a.Name == "Acme" }) {
		t.Fatalf("account %s not in meta: %+v", acct.AccountID, accounts)
	}
	var audit map[string]any
	for _, l := range f.logLines(t) {
		if l["msg"] == "audit" && l["action"] == "account.create" {
			audit = l
		}
	}
	if audit == nil {
		t.Fatal("no audit line for account.create")
	}
	if audit["remote_ip"] != "127.0.0.1" {
		t.Errorf("audit remote_ip = %v, want 127.0.0.1", audit["remote_ip"])
	}
	joined := slices.ContainsFunc(f.logLines(t), func(l map[string]any) bool {
		return l["msg"] == "admin request" && l["request_id"] == audit["request_id"] && l["path"] == "/console/api/admin/accounts"
	})
	if !joined {
		t.Errorf("no access line shares request_id %v with the audit line", audit["request_id"])
	}

	// A full token and a bucket, both through the proxy.
	tokenID := f.token(t, acct.AccountID, meta.AllActions)
	f.adminJSON(t, http.MethodPost, "/buckets",
		`{"name":"fotos","owner_account_id":"`+acct.AccountID+`"}`, http.StatusCreated, nil)

	// Upload with a key that needs encoding.
	payload := bytes.Repeat([]byte("jay console \x00\xff bytes "), 500)
	key := "dir/a b+c.txt"
	resp, body := f.s3(t, http.MethodPut, "fotos/"+(&url.URL{Path: key}).EscapedPath(),
		"as_token="+tokenID, payload, map[string]string{"Content-Type": "text/plain"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT: status %d: %s", resp.StatusCode, body)
	}
	got, ok := f.objectBytes(t, "fotos", key)
	if !ok || !bytes.Equal(got, payload) {
		t.Fatalf("stored bytes differ from what was uploaded (present=%v, %d vs %d bytes)", ok, len(got), len(payload))
	}
	var s3audit map[string]any
	for _, l := range f.logLines(t) {
		if l["msg"] == "audit" && l["action"] == "console.s3" && l["method"] == "PUT" {
			s3audit = l
		}
	}
	if s3audit == nil || s3audit["key"] != key || s3audit["as_token"] != tokenID {
		t.Errorf("console.s3 audit line missing or wrong: %v", s3audit)
	}

	// Listing through the proxy.
	resp, body = f.s3(t, http.MethodGet, "fotos", "list-type=2&as_token="+tokenID, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: status %d: %s", resp.StatusCode, body)
	}
	var list api.ListBucketResult
	if err := xml.Unmarshal(body, &list); err != nil {
		t.Fatalf("list is not XML: %v: %s", err, body)
	}
	if !slices.ContainsFunc(list.Contents, func(c api.S3Content) bool { return c.Key == key }) {
		t.Errorf("listing does not contain %q: %+v", key, list.Contents)
	}

	// Download: same bytes, hardened headers.
	resp, body = f.s3(t, http.MethodGet, "fotos/"+(&url.URL{Path: key}).EscapedPath(), "as_token="+tokenID, nil, nil)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
		t.Fatalf("GET: status %d, bytes equal=%v", resp.StatusCode, bytes.Equal(body, payload))
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment; filename*=UTF-8''") {
		t.Errorf("Content-Disposition = %q, want an attachment", cd)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Cache-Control") != "no-store" ||
		!strings.Contains(resp.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Errorf("object response is missing its hardening headers: %v", resp.Header)
	}

	// A read-only token cannot write, and nothing lands in meta.
	readOnly := f.token(t, acct.AccountID, []string{"object:get", "object:list", "bucket:list"})
	resp, _ = f.s3(t, http.MethodPut, "fotos/blocked.txt", "as_token="+readOnly, []byte("nope"), nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("PUT as a read-only token: status %d, want 403", resp.StatusCode)
	}
	if _, present := f.objectBytes(t, "fotos", "blocked.txt"); present {
		t.Error("a refused upload left an object in meta")
	}

	// A token from another account sees a 403, not the listing.
	var other struct {
		AccountID string `json:"account_id"`
	}
	f.adminJSON(t, http.MethodPost, "/accounts", `{"name":"Other"}`, http.StatusCreated, &other)
	otherToken := f.token(t, other.AccountID, meta.AllActions)
	resp, _ = f.s3(t, http.MethodGet, "fotos", "list-type=2&as_token="+otherToken, nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("list as another account's token: status %d, want 403", resp.StatusCode)
	}

	// Recovery running: the proxy refuses and writes nothing.
	f.hc.SetReady(false)
	resp, _ = f.s3(t, http.MethodPut, "fotos/during-recovery.txt", "as_token="+tokenID, []byte("x"), nil)
	f.hc.SetReady(true)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("PUT during recovery: status %d, want 503", resp.StatusCode)
	}
	if _, present := f.objectBytes(t, "fotos", "during-recovery.txt"); present {
		t.Error("an upload during recovery left an object in meta")
	}

	// Delete through the proxy (multi-delete) and then the empty bucket.
	del := `<Delete><Object><Key>` + key + `</Key></Object></Delete>`
	resp, body = f.s3(t, http.MethodPost, "fotos", "delete&as_token="+tokenID, []byte(del),
		map[string]string{"Content-Type": "application/xml"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: status %d: %s", resp.StatusCode, body)
	}
	var dr api.DeleteResult
	if err := xml.Unmarshal(body, &dr); err != nil || len(dr.Deleted) != 1 {
		t.Fatalf("delete result: %v: %s", err, body)
	}
	if _, present := f.objectBytes(t, "fotos", key); present {
		t.Error("the key is still in meta after the delete")
	}

	f.adminJSON(t, http.MethodDelete, "/buckets/fotos", "", http.StatusNoContent, nil)
	if _, err := f.db.GetBucket("fotos"); err == nil {
		t.Error("the bucket still exists in meta after the delete")
	}
}

// A mutation without the CSRF token is refused and changes nothing.
func TestConsole_MutationWithoutCSRFChangesNothing(t *testing.T) {
	f := newConsoleFixture(t, true)
	f.login(t)
	csrf := f.csrf
	f.csrf = ""

	resp, _ := f.do(t, http.MethodPost, "/console/api/admin/accounts", strings.NewReader(`{"name":"Sneaky"}`),
		map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without CSRF: status %d, want 403", resp.StatusCode)
	}
	accounts, err := f.db.ListAccounts()
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	if len(accounts) != 0 {
		t.Errorf("a refused mutation created %d accounts", len(accounts))
	}
	f.csrf = csrf
}

// The proxy keeps the browser's Host. The S3 handler must not read it as a
// virtual-hosted bucket (bucket.host): with any Host the object lands in the
// bucket named in the path.
func TestConsole_ProxyIgnoresHostForBucketRouting(t *testing.T) {
	f := newConsoleFixture(t, true)
	f.login(t)
	_, tokenID := f.provision(t, "fotos", meta.AllActions)

	for _, host := range []string{"other.example.com", "fotos.jay.test:9000", "wrong.jay.test"} {
		key := "host-" + strings.NewReplacer(".", "-", ":", "-").Replace(host) + ".txt"
		req, err := http.NewRequest(http.MethodPut,
			f.srv.URL+"/console/api/s3/fotos/"+key+"?as_token="+tokenID, strings.NewReader("hello "+host))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Host = host
		// Go's client keys the jar by req.Host, so the cookie is attached by hand.
		srvURL, _ := url.Parse(f.srv.URL)
		for _, c := range f.cli.Jar.Cookies(srvURL) {
			req.AddCookie(c)
		}
		req.Header.Set(consoleCSRFHeader, f.csrf)
		resp, err := f.cli.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		rb, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT with Host %q: status %d, want 200: %s", host, resp.StatusCode, rb)
		}
		got, ok := f.objectBytes(t, "fotos", key)
		if !ok || string(got) != "hello "+host {
			t.Errorf("Host %q: object in bucket fotos = %q (present=%v)", host, got, ok)
		}
	}
}

func TestConsoleExposureWarning(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		warn bool
	}{
		{"all interfaces, plain", Config{ConsoleEnabled: true, AdminAddr: ":9001"}, true},
		{"empty address, plain", Config{ConsoleEnabled: true, AdminAddr: ""}, true},
		{"0.0.0.0, plain", Config{ConsoleEnabled: true, AdminAddr: "0.0.0.0:9001"}, true},
		{"private address, plain", Config{ConsoleEnabled: true, AdminAddr: "10.0.0.5:9001"}, true},
		{"127.0.0.1", Config{ConsoleEnabled: true, AdminAddr: "127.0.0.1:9001"}, false},
		{"localhost", Config{ConsoleEnabled: true, AdminAddr: "localhost:9001"}, false},
		{"::1", Config{ConsoleEnabled: true, AdminAddr: "[::1]:9001"}, false},
		{"all interfaces, TLS", Config{ConsoleEnabled: true, AdminAddr: ":9001", TLSCert: "c", TLSKey: "k"}, false},
		{"disabled", Config{ConsoleEnabled: false, AdminAddr: ":9001"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detail, warn := consoleExposureWarning(tc.cfg)
			if warn != tc.warn {
				t.Errorf("warn = %v, want %v", warn, tc.warn)
			}
			if warn && detail == "" {
				t.Error("a warning without a detail")
			}
		})
	}
}
