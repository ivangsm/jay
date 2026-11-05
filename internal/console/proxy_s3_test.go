package console

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ivangsm/jay/meta"
)

func (hn *harness) assertS3Untouched(what string) {
	hn.t.Helper()
	if hn.s3.count() != 0 || hn.signCount() != 0 {
		hn.t.Fatalf("%s: the S3 handler was reached (s3=%d sign=%d)", what, hn.s3.count(), hn.signCount())
	}
}

func TestS3ProxyRequiresSessionAndCSRF(t *testing.T) {
	hn := newHarness(t)
	r := httptest.NewRequest(http.MethodGet, "/console/api/s3/b/k?as_token=tok1", nil)
	if rec := hn.serve(r); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session: status %d", rec.Code)
	}
	hn.assertS3Untouched("no session")
}

func TestS3ProxyRefusals(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	future := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name   string
		target string
		setup  func(hn *harness)
		header map[string]string
		want   int
		msg    string
	}{
		{name: "no as_token", target: "/b/k", want: 400, msg: "as_token is required"},
		{name: "empty as_token", target: "/b/k?as_token=", want: 400, msg: "as_token is required"},
		{name: "two as_token", target: "/b/k?as_token=tok1&as_token=tok2", want: 400, msg: "as_token is required"},
		{name: "X-Amz-Credential", target: "/b/k?as_token=tok1&X-Amz-Credential=x", want: 400, msg: "presigned"},
		{name: "x-amz lowercase", target: "/b/k?as_token=tok1&x-amz-signature=x", want: 400, msg: "presigned"},
		{name: "x-jay-token", target: "/b/k?as_token=tok1&x-jay-token=other", want: 400, msg: "presigned"},
		{name: "X-Jay-Signature", target: "/b/k?as_token=tok1&X-Jay-Signature=x", want: 400, msg: "presigned"},
		{name: "not ready", target: "/b/k?as_token=tok1", setup: func(hn *harness) { hn.ready.Store(false) }, want: 503, msg: "startup recovery"},
		{name: "unknown token", target: "/b/k?as_token=nope", want: 404, msg: "token not found"},
		{
			name: "revoked token", target: "/b/k?as_token=tok1",
			setup: func(hn *harness) { hn.toks.tokens["tok1"].Status = "revoked" },
			want:  409, msg: "token is revoked",
		},
		{
			name: "expired token", target: "/b/k?as_token=tok1",
			setup: func(hn *harness) { hn.toks.tokens["tok1"].ExpiresAt = &past },
			want:  409, msg: "token expired at 2026-01-01T00:00:00Z",
		},
		{
			name: "account missing", target: "/b/k?as_token=tok1",
			setup: func(hn *harness) { delete(hn.toks.accounts, "acc1") },
			want:  409, msg: "token's account not found",
		},
		{
			name: "account suspended", target: "/b/k?as_token=tok1",
			setup: func(hn *harness) { hn.toks.accounts["acc1"].Status = "suspended" },
			want:  409, msg: "token's account is suspended",
		},
		{
			name: "token read fails", target: "/b/k?as_token=tok1",
			setup: func(hn *harness) { hn.toks.tokenErr = errors.New("bolt: disk on fire") },
			want:  500, msg: "internal error",
		},
		{
			name: "account read fails", target: "/b/k?as_token=tok1",
			setup: func(hn *harness) { hn.toks.acctErr = errors.New("bolt: disk on fire") },
			want:  500, msg: "internal error",
		},
		{
			name: "aws-chunked", target: "/b/k?as_token=tok1",
			header: map[string]string{"Content-Encoding": "aws-chunked"}, want: 400, msg: "aws-chunked",
		},
		{
			name: "aws-chunked in a list", target: "/b/k?as_token=tok1",
			header: map[string]string{"Content-Encoding": "gzip, AWS-Chunked"}, want: 400, msg: "aws-chunked",
		},
		{
			name: "sign fails", target: "/b/k?as_token=tok1",
			setup: func(hn *harness) { hn.signErr = errors.New("secret is empty") },
			want:  500, msg: "internal error",
		},
	}
	// A token that is fine until it expires later: the future expiry passes.
	t.Run("future expiry passes", func(t *testing.T) {
		hn := newHarness(t)
		hn.toks.tokens["tok1"].ExpiresAt = &future
		c := hn.login()
		if rec := c.do(http.MethodGet, "/console/api/s3/b/k?as_token=tok1", ""); rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hn := newHarness(t)
			if tc.setup != nil {
				tc.setup(hn)
			}
			c := hn.login()
			r := c.newReq(http.MethodPut, "/console/api/s3"+tc.target, strings.NewReader("data"))
			for k, v := range tc.header {
				r.Header.Set(k, v)
			}
			rec := hn.serve(r)
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d (body %s)", rec.Code, tc.want, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), tc.msg) {
				t.Fatalf("body %q does not contain %q", rec.Body, tc.msg)
			}
			if tc.name == "sign fails" {
				// The one case where signing was attempted; the handler must still be untouched.
				if hn.s3.count() != 0 {
					t.Fatal("S3 handler reached after a signing failure")
				}
				return
			}
			hn.assertS3Untouched(tc.name)
		})
	}
}

func TestS3ProxyHappyPathRequest(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()

	r := c.newReq(http.MethodPut, "/console/api/s3/photos/docs/caf%C3%A9.txt?as_token=tok1&partNumber=2&uploadId=U%2F1", strings.NewReader("payload"))
	r.Header.Set("Authorization", "Bearer smuggled")
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	r.Header.Set("X-Amz-Decoded-Content-Length", "7")
	r.Header.Set("X-Amz-Meta-A", "1")
	r.Header.Set("X-Amz-Meta-Other", "2")
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("Content-Md5", "abc")
	r.Header.Set("Range", "bytes=0-1")
	r.Header.Set("X-Amz-Copy-Source", "/a/b")
	r.RemoteAddr = "198.51.100.7:4242"
	rec := hn.serve(r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}

	if hn.signCount() != 1 || hn.signIDs[0] != "tok1" {
		t.Fatalf("SignS3 calls=%d ids=%v", hn.signCount(), hn.signIDs)
	}
	// SignS3 sees the query without as_token and without any secret.
	if q := hn.signQuery[0]; q != "partNumber=2&uploadId=U%2F1" {
		t.Fatalf("SignS3 saw query %q", q)
	}
	if hn.s3.count() != 1 {
		t.Fatalf("S3 calls = %d", hn.s3.count())
	}
	got := hn.s3.request()
	if got.Method != http.MethodPut || got.URL.Path != "/photos/docs/café.txt" {
		t.Fatalf("forwarded %s %q", got.Method, got.URL.Path)
	}
	if got.URL.RawQuery != "partNumber=2&uploadId=U%2F1&X-Jay-Signature=fake" || strings.Contains(got.URL.RawQuery, "as_token") {
		t.Fatalf("forwarded query %q", got.URL.RawQuery)
	}
	for _, name := range []string{"Authorization", "Cookie", "X-Forwarded-For", "X-Amz-Content-Sha256", "X-Amz-Decoded-Content-Length", csrfHeader} {
		if v := got.Header.Get(name); v != "" {
			t.Fatalf("header %s reached the S3 handler: %q", name, v)
		}
	}
	want := map[string]string{
		"X-Amz-Meta-A": "1", "X-Amz-Meta-Other": "2", "Content-Type": "text/plain",
		"Content-Md5": "abc", "Range": "bytes=0-1", "X-Amz-Copy-Source": "/a/b",
	}
	for k, v := range want {
		if got.Header.Get(k) != v {
			t.Fatalf("header %s = %q, want %q", k, got.Header.Get(k), v)
		}
	}
	if len(got.Header) != len(want) {
		t.Fatalf("S3 handler saw headers %v, want exactly %d allowed ones", got.Header, len(want))
	}
	if got.RemoteAddr != "198.51.100.7:4242" {
		t.Fatalf("RemoteAddr = %q", got.RemoteAddr)
	}
	if string(hn.s3.lastBody) != "payload" || got.ContentLength != 7 {
		t.Fatalf("body %q len %d", hn.s3.lastBody, got.ContentLength)
	}
}

func TestS3ProxyPreservesBareSubresources(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	c.do(http.MethodPost, "/console/api/s3/b/k?uploads&as_token=tok1", "")
	if q := hn.signQuery[0]; q != "uploads=" {
		t.Fatalf("SignS3 saw %q", q)
	}
}

func TestS3ProxyResponseHeaders(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	hn.s3.respond(http.StatusOK, http.Header{
		"Content-Type":            {"text/html"},
		"Content-Disposition":     {"inline"},
		"Content-Length":          {"5"},
		"Etag":                    {`"abc"`},
		"Last-Modified":           {"Wed, 07 Oct 2026 12:00:00 GMT"},
		"Accept-Ranges":           {"bytes"},
		"X-Amz-Meta-Owner":        {"ivan"},
		"X-Amz-Request-Id":        {"s3-req-1"},
		"Set-Cookie":              {"s3=leak"},
		"Cache-Control":           {"public, max-age=999"},
		"Content-Security-Policy": {"default-src *"},
		"X-Debug":                 {"1"},
	}, "hello")

	wrap := httptest.NewRecorder()
	wrap.Header().Set("X-Amz-Request-Id", "console-req")
	r := c.newReq(http.MethodGet, "/console/api/s3/photos/docs/caf%C3%A9.txt?as_token=tok1", nil)
	hn.h.ServeHTTP(wrap, r)

	h := wrap.Header()
	if wrap.Code != http.StatusOK || wrap.Body.String() != "hello" {
		t.Fatalf("%d %q", wrap.Code, wrap.Body)
	}
	if h.Get("Set-Cookie") != "" || h.Get("X-Debug") != "" {
		t.Fatalf("a header outside the allowlist reached the browser: %v", h)
	}
	if h.Get("X-Amz-Request-Id") != "console-req" || h.Get("X-Jay-S3-Request-Id") != "s3-req-1" {
		t.Fatalf("request ids: x-amz-request-id=%q X-Jay-S3-Request-Id=%q", h.Get("X-Amz-Request-Id"), h.Get("X-Jay-S3-Request-Id"))
	}
	if h.Get("Content-Disposition") != "attachment; filename*=UTF-8''caf%C3%A9.txt" {
		t.Fatalf("Content-Disposition = %q", h.Get("Content-Disposition"))
	}
	if h.Get("Content-Security-Policy") != "sandbox; default-src 'none'" ||
		h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("CSP=%q nosniff=%q cache=%q", h.Get("Content-Security-Policy"), h.Get("X-Content-Type-Options"), h.Get("Cache-Control"))
	}
	for k, v := range map[string]string{
		"Content-Type": "text/html", "Content-Length": "5", "Etag": `"abc"`,
		"Accept-Ranges": "bytes", "X-Amz-Meta-Owner": "ivan",
	} {
		if h.Get(k) != v {
			t.Fatalf("%s = %q, want %q", k, h.Get(k), v)
		}
	}
}

func TestS3ProxyDispositionRules(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	hn.s3.respond(http.StatusOK, http.Header{"Content-Disposition": {"inline"}}, "x")

	cases := []struct {
		name, method, target string
		status               int
		want                 string // "" = no Content-Disposition at all
	}{
		{"object get", http.MethodGet, "/b/k.bin", 200, "attachment; filename*=UTF-8''k.bin"},
		{"object head", http.MethodHead, "/b/dir/k.bin", 200, "attachment; filename*=UTF-8''k.bin"},
		{"ranged get", http.MethodGet, "/b/k.bin", 206, "attachment; filename*=UTF-8''k.bin"},
		{"key with spaces and quotes", http.MethodGet, `/b/a%20%22b%22.txt`, 200, "attachment; filename*=UTF-8''a%20%22b%22.txt"},
		{"listing has no key", http.MethodGet, "/b?list-type=2", 200, ""},
		{"listing with trailing slash", http.MethodGet, "/b/?list-type=2", 200, ""},
		{"list parts", http.MethodGet, "/b/k?uploadId=U", 200, ""},
		{"error response", http.MethodGet, "/b/k", 404, ""},
		{"put", http.MethodPut, "/b/k", 200, ""},
	}
	for _, tc := range cases {
		hn.s3.respond(tc.status, http.Header{"Content-Disposition": {"inline"}}, "x")
		r := c.newReq(tc.method, "/console/api/s3"+withToken(tc.target), nil)
		rec := hn.serve(r)
		if got := rec.Header().Get("Content-Disposition"); got != tc.want {
			t.Fatalf("%s: Content-Disposition = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func withToken(target string) string {
	if strings.Contains(target, "?") {
		return target + "&as_token=tok1"
	}
	return target + "?as_token=tok1"
}

func TestS3ProxyAuditsOnlySuccessfulMutations(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	hn.s3.respond(http.StatusOK, http.Header{"X-Amz-Request-Id": {"s3-req-9"}}, "")

	// 2xx mutation: audited, with names of query keys but never their values.
	c.do(http.MethodPut, "/console/api/s3/photos/a/b.txt?as_token=tok1&uploadId=SECRETUPLOAD&partNumber=2", "x")
	lines := hn.logs.auditLines("console.s3")
	if len(lines) != 1 {
		t.Fatalf("audit lines = %d, want 1", len(lines))
	}
	l := lines[0]
	if l["method"] != "PUT" || l["bucket"] != "photos" || l["key"] != "a/b.txt" || l["as_token"] != "tok1" ||
		l["status"] != float64(200) || l["s3_request_id"] != "s3-req-9" || l["remote_ip"] != "192.0.2.10" {
		t.Fatalf("audit line = %v", l)
	}
	keys, _ := l["query_keys"].([]any)
	if len(keys) != 2 || keys[0] != "partNumber" || keys[1] != "uploadId" {
		t.Fatalf("query_keys = %v", l["query_keys"])
	}
	if strings.Contains(hn.logs.String(), "SECRETUPLOAD") {
		t.Fatal("a query value reached the logs")
	}

	// Reads are not audited.
	c.do(http.MethodGet, "/console/api/s3/photos/a/b.txt?as_token=tok1", "")
	c.do(http.MethodHead, "/console/api/s3/photos/a/b.txt?as_token=tok1", "")
	// A refused mutation is not audited.
	hn.s3.respond(http.StatusForbidden, nil, "")
	c.do(http.MethodDelete, "/console/api/s3/photos/a/b.txt?as_token=tok1", "")
	// Neither is one the console refused itself.
	c.do(http.MethodPut, "/console/api/s3/photos/a/b.txt", "x")

	if n := len(hn.logs.auditLines("console.s3")); n != 1 {
		t.Fatalf("audit lines = %d after reads and refusals, want still 1", n)
	}
}

func TestS3ProxyImplicitOKIsAuditedAsOK(t *testing.T) {
	hn := newHarness(t, func(c *Config) {
		c.S3 = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}) // writes nothing
	})
	c := hn.login()
	rec := c.do(http.MethodDelete, "/console/api/s3/b/k?as_token=tok1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if lines := hn.logs.auditLines("console.s3"); len(lines) != 1 || lines[0]["status"] != float64(200) {
		t.Fatalf("audit = %v", lines)
	}
}

func TestS3ProxyMethods(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	rec := c.do(http.MethodPatch, "/console/api/s3/b/k?as_token=tok1", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rec.Code)
	}
	hn.assertS3Untouched("PATCH")
}

func TestAttachmentEncoding(t *testing.T) {
	for key, want := range map[string]string{
		"a.txt":      "attachment; filename*=UTF-8''a.txt",
		"x/y/z.tar":  "attachment; filename*=UTF-8''z.tar",
		"café.txt":   "attachment; filename*=UTF-8''caf%C3%A9.txt",
		"a b;c\".d":  "attachment; filename*=UTF-8''a%20b%3Bc%22.d",
		"dir/":       "attachment",
		"line\nfeed": "attachment; filename*=UTF-8''line%0Afeed",
	} {
		if got := attachment(key); got != want {
			t.Errorf("attachment(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestTokenSourceSatisfiedByMeta(t *testing.T) {
	var _ TokenSource = (*meta.DB)(nil)
}
