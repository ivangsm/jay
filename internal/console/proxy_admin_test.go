package console

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminProxyRequiresASession(t *testing.T) {
	hn := newHarness(t)
	rec := hn.serve(httptest.NewRequest(http.MethodGet, "/console/api/admin/tokens", nil))
	if rec.Code != http.StatusUnauthorized || hn.admin.count() != 0 {
		t.Fatalf("status %d, admin calls %d", rec.Code, hn.admin.count())
	}
}

func TestAdminProxyForwardsOnlyWhatItShould(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	hn.admin.respond(http.StatusCreated, http.Header{
		"Content-Type": {"application/json"},
		"Set-Cookie":   {"admin=leak"},
		"X-Internal":   {"1"},
	}, `{"ok":true}`)

	r := c.newReq(http.MethodPost, "/console/api/admin/tokens/a%2Fb?x=1&y=two", strings.NewReader(`{"name":"n"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer browser-supplied")
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.Header.Set("X-Anything", "x")
	r.RemoteAddr = "198.51.100.7:4242"
	rec := hn.serve(r)

	if rec.Code != http.StatusCreated || rec.Body.String() != `{"ok":true}` {
		t.Fatalf("response passthrough: %d %q", rec.Code, rec.Body)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content type = %q", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Set-Cookie") != "" || rec.Header().Get("X-Internal") != "" {
		t.Fatalf("an admin response header outside the allowlist reached the browser: %v", rec.Header())
	}

	if hn.admin.count() != 1 {
		t.Fatalf("admin calls = %d", hn.admin.count())
	}
	got := hn.admin.request()
	if got.Method != http.MethodPost || got.URL.Path != "/_jay/tokens/a/b" || got.URL.RawQuery != "x=1&y=two" {
		t.Fatalf("forwarded %s %s?%s", got.Method, got.URL.Path, got.URL.RawQuery)
	}
	if got.Header.Get("Authorization") != "Bearer "+testAdminToken {
		t.Fatalf("Authorization = %q", got.Header.Get("Authorization"))
	}
	if got.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q", got.Header.Get("Content-Type"))
	}
	for _, h := range []string{"Cookie", csrfHeader, "X-Forwarded-For", "X-Anything"} {
		if v := got.Header.Get(h); v != "" {
			t.Fatalf("header %s reached the admin API: %q", h, v)
		}
	}
	if len(got.Header) != 2 {
		t.Fatalf("admin API saw headers %v, want only Authorization and Content-Type", got.Header)
	}
	if got.RemoteAddr != "198.51.100.7:4242" {
		t.Fatalf("RemoteAddr = %q", got.RemoteAddr)
	}
	if string(hn.admin.lastBody) != `{"name":"n"}` {
		t.Fatalf("body = %q", hn.admin.lastBody)
	}
}

func TestAdminProxyKeepsTheRequestContext(t *testing.T) {
	type key struct{}
	hn := newHarness(t)
	c := hn.login()
	r := c.newReq(http.MethodGet, "/console/api/admin/tokens", nil)
	r = r.WithContext(contextWith(r.Context(), key{}, "req-123"))
	hn.serve(r)
	if got := hn.admin.request().Context().Value(key{}); got != "req-123" {
		t.Fatalf("context value = %v: the admin API would log a different request id", got)
	}
}

func TestAdminProxyBodyLimit(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()

	big := bytes.Repeat([]byte("a"), maxAdminBody+1)
	rec := c.do(http.MethodPost, "/console/api/admin/accounts", string(big))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("declared oversize: status %d", rec.Code)
	}

	// A declared oversize length is judged before a single byte is read.
	cr := &countingReader{r: bytes.NewReader(big)}
	r := c.newReq(http.MethodPost, "/console/api/admin/accounts", cr)
	r.ContentLength = int64(len(big))
	if rec := hn.serve(r); rec.Code != http.StatusRequestEntityTooLarge || cr.n != 0 {
		t.Fatalf("declared oversize: status %d, %d bytes read", rec.Code, cr.n)
	}

	// Undeclared length (chunked): still refused, still before the admin API.
	r = c.newReq(http.MethodPost, "/console/api/admin/accounts", hideLength(bytes.NewReader(big)))
	r.ContentLength = -1
	if rec := hn.serve(r); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked oversize: status %d", rec.Code)
	}
	if hn.admin.count() != 0 {
		t.Fatalf("an oversize body reached the admin API (%d calls)", hn.admin.count())
	}

	// Exactly at the limit passes.
	at := bytes.Repeat([]byte("a"), maxAdminBody)
	r = c.newReq(http.MethodPost, "/console/api/admin/accounts", hideLength(bytes.NewReader(at)))
	r.ContentLength = -1
	if rec := hn.serve(r); rec.Code != http.StatusOK {
		t.Fatalf("at the limit: status %d", rec.Code)
	}
	if len(hn.admin.lastBody) != maxAdminBody || hn.admin.request().ContentLength != maxAdminBody {
		t.Fatalf("forwarded %d bytes (ContentLength %d)", len(hn.admin.lastBody), hn.admin.request().ContentLength)
	}
}

func TestAdminProxyMethods(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	rec := c.do(http.MethodPatch, "/console/api/admin/tokens", "")
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, POST, PUT, DELETE" {
		t.Fatalf("PATCH: status %d Allow %q", rec.Code, rec.Header().Get("Allow"))
	}
	if hn.admin.count() != 0 {
		t.Fatal("PATCH reached the admin API")
	}
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete} {
		if rec := c.do(m, "/console/api/admin/x", ""); rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", m, rec.Code)
		}
	}
	if hn.admin.count() != 4 {
		t.Fatalf("admin calls = %d, want 4", hn.admin.count())
	}
}

func TestAdminProxyPassesErrorsThrough(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	hn.admin.respond(http.StatusConflict, http.Header{"Content-Type": {"application/json"}}, `{"error":"bucket already exists"}`)
	rec := c.do(http.MethodPost, "/console/api/admin/buckets", `{"name":"b"}`)
	if rec.Code != http.StatusConflict || rec.Body.String() != `{"error":"bucket already exists"}` {
		t.Fatalf("%d %q", rec.Code, rec.Body)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}
