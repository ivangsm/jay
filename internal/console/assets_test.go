package console

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

func TestIndexIsServedWithADocumentPolicy(t *testing.T) {
	hn := newHarness(t)
	rec := hn.serve(httptest.NewRequest(http.MethodGet, "/console/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	if rec.Header().Get("Content-Security-Policy") != cspDocument {
		t.Fatalf("CSP = %q", rec.Header().Get("Content-Security-Policy"))
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
	body := rec.Body.String()
	base := "/console/static/" + hn.h.assets.hash + "/"
	if !strings.Contains(body, `href="`+base+`console.css"`) || !strings.Contains(body, `src="`+base+`js/app.js"`) {
		t.Fatalf("index does not point at %s: %s", base, body)
	}
	if !strings.Contains(body, "<p>9.9.9</p>") {
		t.Fatalf("version was not rendered: %s", body)
	}
	if strings.Contains(cspDocument, "unsafe-inline") || strings.Contains(cspDocument, "unsafe-eval") {
		t.Fatal("document CSP allows inline or eval")
	}

	head := hn.serve(httptest.NewRequest(http.MethodHead, "/console/", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD: %d with %d body bytes", head.Code, head.Body.Len())
	}
	if rec := hn.serve(httptest.NewRequest(http.MethodPost, "/console/", nil)); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /console/: status %d", rec.Code)
	}
}

func TestHashIsTwelveHexAndStable(t *testing.T) {
	a := newHarness(t).h.assets.hash
	b := newHarness(t).h.assets.hash
	if !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(a) || a != b {
		t.Fatalf("hashes %q, %q", a, b)
	}
}

func TestHashTracksContentButNotIndex(t *testing.T) {
	hashOf := func(mutate func(fstest.MapFS)) string {
		fsys := testAssets()
		mutate(fsys)
		return newHarness(t, func(c *Config) { c.Assets = fsys }).h.assets.hash
	}
	base := hashOf(func(fstest.MapFS) {})
	if h := hashOf(func(m fstest.MapFS) { m["js/app.js"] = &fstest.MapFile{Data: []byte("export {};//")} }); h == base {
		t.Fatal("changing an asset did not change the hash")
	}
	if h := hashOf(func(m fstest.MapFS) {
		m["new.js"] = &fstest.MapFile{Data: []byte("x")}
	}); h == base {
		t.Fatal("adding an asset did not change the hash")
	}
	if h := hashOf(func(m fstest.MapFS) { m["index.html"] = &fstest.MapFile{Data: []byte("<p>{{.Base}}</p>")} }); h != base {
		t.Fatal("index.html participates in the hash it embeds")
	}
}

func TestAssetsAreImmutableWithExplicitTypes(t *testing.T) {
	hn := newHarness(t)
	prefix := "/console/static/" + hn.h.assets.hash + "/"
	for path, ct := range map[string]string{
		"js/app.js":     "text/javascript; charset=utf-8",
		"console.css":   "text/css; charset=utf-8",
		"fonts/x.woff2": "font/woff2",
		"favicon.svg":   "image/svg+xml",
		"fonts/OFL.txt": "text/plain; charset=utf-8",
	} {
		rec := hn.serve(httptest.NewRequest(http.MethodGet, prefix+path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		if rec.Header().Get("Content-Type") != ct {
			t.Fatalf("%s: Content-Type = %q, want %q", path, rec.Header().Get("Content-Type"), ct)
		}
		if rec.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
			t.Fatalf("%s: Cache-Control = %q", path, rec.Header().Get("Cache-Control"))
		}
		if rec.Header().Get("Content-Security-Policy") != cspLocked || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: CSP %q nosniff %q", path, rec.Header().Get("Content-Security-Policy"), rec.Header().Get("X-Content-Type-Options"))
		}
	}
	head := hn.serve(httptest.NewRequest(http.MethodHead, prefix+"js/app.js", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD: %d with %d body bytes", head.Code, head.Body.Len())
	}
}

func TestAssetRefusals(t *testing.T) {
	hn := newHarness(t)
	good := "/console/static/" + hn.h.assets.hash + "/"
	for name, target := range map[string]string{
		"old hash":       "/console/static/000000000000/js/app.js",
		"no hash":        "/console/static/js/app.js",
		"hash only":      "/console/static/" + hn.h.assets.hash,
		"dot dot":        good + "../index.html",
		"nested dot dot": good + "fonts/../../secret",
		"missing":        good + "js/missing.js",
		"directory":      good + "js",
		"trailing slash": good + "js/app.js/",
		"index raw":      good + "index.html",
		"backslash":      good + `js\app.js`,
	} {
		rec := hn.serve(httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status %d", name, rec.Code)
		}
	}
	if rec := hn.serve(httptest.NewRequest(http.MethodPost, good+"js/app.js", nil)); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST asset: status %d", rec.Code)
	}
}

func TestUnknownExtensionIsOctetStream(t *testing.T) {
	fsys := testAssets()
	fsys["data.bin"] = &fstest.MapFile{Data: []byte{1, 2}}
	hn := newHarness(t, func(c *Config) { c.Assets = fsys })
	rec := hn.serve(httptest.NewRequest(http.MethodGet, "/console/static/"+hn.h.assets.hash+"/data.bin", nil))
	if rec.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}
}

// The embedded tree is what ships: New must accept it, and the page it renders
// must point at assets that really are served.
func TestEmbeddedTreeServes(t *testing.T) {
	hn := newHarness(t, func(c *Config) { c.Assets = nil })
	rec := hn.serve(httptest.NewRequest(http.MethodGet, "/console/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	refs := regexp.MustCompile(`(?:src|href)="(/console/static/[^"]+)"`).FindAllStringSubmatch(rec.Body.String(), -1)
	if len(refs) == 0 {
		t.Fatalf("index references no assets: %s", rec.Body)
	}
	for _, m := range refs {
		if got := hn.serve(httptest.NewRequest(http.MethodGet, m[1], nil)); got.Code != http.StatusOK {
			t.Fatalf("%s: status %d", m[1], got.Code)
		}
	}
}
