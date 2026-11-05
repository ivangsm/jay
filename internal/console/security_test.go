package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSRFRequiredOnUnsafeMethods(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	other := hn.login() // a second session, with its own token

	cases := map[string]func(*http.Request){
		"no header":     func(*http.Request) {},
		"empty header":  func(r *http.Request) { r.Header.Set(csrfHeader, "") },
		"other session": func(r *http.Request) { r.Header.Set(csrfHeader, other.csrf) },
		"garbage":       func(r *http.Request) { r.Header.Set(csrfHeader, "x") },
	}
	for name, setup := range cases {
		for _, target := range []string{"/console/api/admin/accounts", "/console/api/s3/b/k?as_token=tok1"} {
			r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{}`))
			r.AddCookie(c.cookie)
			setup(r)
			rec := hn.serve(r)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %s: status %d", name, target, rec.Code)
			}
		}
	}
	if hn.admin.count() != 0 || hn.s3.count() != 0 || hn.signCount() != 0 {
		t.Fatalf("a request without a valid CSRF token reached a backend: admin=%d s3=%d sign=%d",
			hn.admin.count(), hn.s3.count(), hn.signCount())
	}

	// The same request with the right token goes through.
	if rec := c.do(http.MethodPost, "/console/api/admin/accounts", `{}`); rec.Code != http.StatusOK {
		t.Fatalf("with token: status %d", rec.Code)
	}
	if hn.admin.count() != 1 {
		t.Fatalf("admin calls = %d, want 1", hn.admin.count())
	}
}

func TestSafeMethodsNeedNoCSRF(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	r := httptest.NewRequest(http.MethodGet, "/console/api/admin/tokens", nil)
	r.AddCookie(c.cookie)
	if rec := hn.serve(r); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestCrossSiteFetchMetadataRefused(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	for _, site := range []string{"cross-site", "same-site"} {
		r := c.newReq(http.MethodGet, "/console/api/admin/tokens", nil)
		r.Header.Set("Sec-Fetch-Site", site)
		if rec := hn.serve(r); rec.Code != http.StatusForbidden {
			t.Fatalf("Sec-Fetch-Site %s: status %d", site, rec.Code)
		}
	}
	// The login is an API call too.
	r := jsonReq(http.MethodPost, "/console/api/session", `{"token":"`+testAdminToken+`"}`)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	if rec := hn.serve(r); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site login: status %d", rec.Code)
	}
	if hn.admin.count() != 0 {
		t.Fatalf("a cross-site request reached the admin API (%d)", hn.admin.count())
	}
	if hn.authCalls.Load() != 1 { // only the helper's own login
		t.Fatalf("a cross-site login reached Authenticate (%d calls)", hn.authCalls.Load())
	}

	for _, site := range []string{"same-origin", "none"} {
		r := c.newReq(http.MethodGet, "/console/api/admin/tokens", nil)
		r.Header.Set("Sec-Fetch-Site", site)
		if rec := hn.serve(r); rec.Code != http.StatusOK {
			t.Fatalf("Sec-Fetch-Site %s: status %d", site, rec.Code)
		}
	}
}

func TestForeignOriginRefusedOnUnsafeMethods(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()

	r := c.newReq(http.MethodPost, "/console/api/admin/accounts", strings.NewReader(`{}`))
	r.Header.Set("Origin", "https://evil.example")
	if rec := hn.serve(r); rec.Code != http.StatusForbidden {
		t.Fatalf("foreign origin: status %d", rec.Code)
	}
	// The same origin on the other scheme is a different origin.
	r = c.newReq(http.MethodPost, "/console/api/admin/accounts", strings.NewReader(`{}`))
	r.Header.Set("Origin", "https://example.com")
	if rec := hn.serve(r); rec.Code != http.StatusForbidden {
		t.Fatalf("scheme mismatch: status %d", rec.Code)
	}
	r = c.newReq(http.MethodPost, "/console/api/admin/accounts", strings.NewReader(`{}`))
	r.Header.Set("Origin", "null")
	if rec := hn.serve(r); rec.Code != http.StatusForbidden {
		t.Fatalf("null origin: status %d", rec.Code)
	}
	if hn.admin.count() != 0 {
		t.Fatalf("a foreign-origin request reached the admin API (%d)", hn.admin.count())
	}

	r = c.newReq(http.MethodPost, "/console/api/admin/accounts", strings.NewReader(`{}`))
	r.Header.Set("Origin", "http://example.com")
	if rec := hn.serve(r); rec.Code != http.StatusOK {
		t.Fatalf("own origin: status %d", rec.Code)
	}
	// Login: also checked.
	r = jsonReq(http.MethodPost, "/console/api/session", `{"token":"`+testAdminToken+`"}`)
	r.Header.Set("Origin", "https://evil.example")
	before := hn.authCalls.Load()
	if rec := hn.serve(r); rec.Code != http.StatusForbidden || hn.authCalls.Load() != before {
		t.Fatalf("foreign-origin login: status %d, Authenticate calls %d->%d", rec.Code, before, hn.authCalls.Load())
	}
}

func TestOriginUsesHTTPSOnTLS(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "https://admin.test/console/api/session", nil)
	r.TLS = &tlsState
	r.Header.Set("Origin", "https://admin.test")
	if !checkOrigin(r) {
		t.Fatal("own https origin refused")
	}
	r.Header.Set("Origin", "http://admin.test")
	if checkOrigin(r) {
		t.Fatal("http origin accepted on a TLS request")
	}
}

func TestEveryResponseCarriesTheCommonHeaders(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	want := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	}
	targets := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/console/", nil),
		httptest.NewRequest(http.MethodGet, "/console/static/"+hn.h.assets.hash+"/console.css", nil),
		httptest.NewRequest(http.MethodGet, "/console/api/session", nil),
		c.newReq(http.MethodGet, "/console/api/admin/tokens", nil),
		c.newReq(http.MethodGet, "/console/api/s3/b/k?as_token=tok1", nil),
		httptest.NewRequest(http.MethodGet, "/console/nope", nil),
	}
	for _, r := range targets {
		rec := hn.serve(r)
		for k, v := range want {
			if got := rec.Header().Get(k); got != v {
				t.Fatalf("%s: %s = %q, want %q", r.URL.Path, k, got, v)
			}
		}
		if rec.Header().Get("Permissions-Policy") == "" {
			t.Fatalf("%s: no Permissions-Policy", r.URL.Path)
		}
		for k := range rec.Header() {
			if strings.HasPrefix(k, "Access-Control-") {
				t.Fatalf("%s: response carries %s", r.URL.Path, k)
			}
		}
	}
}

func TestAPIResponsesAreLockedDown(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/console/api/session", nil),
		c.newReq(http.MethodGet, "/console/api/admin/tokens", nil),
	} {
		rec := hn.serve(r)
		if rec.Header().Get("Content-Security-Policy") != cspLocked || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: CSP %q Cache-Control %q", r.URL.Path,
				rec.Header().Get("Content-Security-Policy"), rec.Header().Get("Cache-Control"))
		}
	}
}
