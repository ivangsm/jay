package console

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
)

//go:embed static
var embeddedStatic embed.FS

// embeddedAssets is the UI tree compiled into the binary.
func embeddedAssets() (fs.FS, error) {
	sub, err := fs.Sub(embeddedStatic, "static")
	if err != nil {
		return nil, fmt.Errorf("console: embedded assets: %w", err)
	}
	return sub, nil
}

const indexFile = "index.html"

// assetSet is the UI tree plus what is derived from it once, at New.
type assetSet struct {
	fsys fs.FS
	// hash is the content hash that prefixes every asset URL. Every asset is
	// therefore immutable for its URL, and a new build is a new URL.
	hash  string
	index []byte
}

// contentTypes is explicit on purpose: the system mime table differs between
// hosts and a wrong type under nosniff breaks scripts and fonts.
var contentTypes = map[string]string{
	".js":    "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".svg":   "image/svg+xml",
	".woff2": "font/woff2",
	".txt":   "text/plain; charset=utf-8",
	".json":  "application/json",
	".png":   "image/png",
	".ico":   "image/x-icon",
}

// hashAssets hashes every file except index.html (path, NUL, bytes, in
// lexical order). index.html is excluded because it embeds the hash.
func hashAssets(fsys fs.FS) (string, error) {
	sum := sha256.New()
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || p == indexFile {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		sum.Write([]byte(p))
		sum.Write([]byte{0})
		sum.Write(b)
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil))[:12], nil
}

// loadAssets hashes the tree and renders index.html once.
func loadAssets(fsys fs.FS, version string) (assetSet, error) {
	hash, err := hashAssets(fsys)
	if err != nil {
		return assetSet{}, fmt.Errorf("console: hash assets: %w", err)
	}
	src, err := fs.ReadFile(fsys, indexFile)
	if err != nil {
		return assetSet{}, fmt.Errorf("console: read %s: %w", indexFile, err)
	}
	tmpl, err := template.New(indexFile).Parse(string(src))
	if err != nil {
		return assetSet{}, fmt.Errorf("console: parse %s: %w", indexFile, err)
	}
	var buf bytes.Buffer
	data := struct{ Base, Version string }{Base: pathStatic + hash + "/", Version: version}
	if err := tmpl.Execute(&buf, data); err != nil {
		return assetSet{}, fmt.Errorf("console: render %s: %w", indexFile, err)
	}
	return assetSet{fsys: fsys, hash: hash, index: buf.Bytes()}, nil
}

// serveIndex answers GET /console/. It is the only revalidated response: it
// is what hands the browser the current asset hash.
func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request) {
	if !safeMethod(r.Method) {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	hd := w.Header()
	hd.Set("Content-Type", "text/html; charset=utf-8")
	hd.Set("Content-Security-Policy", cspDocument)
	hd.Set("Cache-Control", "no-cache")
	hd.Set("Content-Length", strconv.Itoa(len(h.assets.index)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(h.assets.index)
	}
}

// serveAsset answers GET /console/static/<hash>/<path>. A stale hash is a 404:
// the page that references it is itself stale and reloads.
func (h *Handler) serveAsset(w http.ResponseWriter, r *http.Request) {
	if !safeMethod(r.Method) {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, pathStatic)
	hash, rel, ok := strings.Cut(rest, "/")
	if !ok || hash != h.assets.hash || rel == indexFile || !fs.ValidPath(rel) || strings.ContainsAny(rel, "\\\x00") {
		http.NotFound(w, r)
		return
	}
	info, err := fs.Stat(h.assets.fsys, rel)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	body, err := fs.ReadFile(h.assets.fsys, rel)
	if err != nil {
		h.log.Error("read console asset", "asset", rel, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	ct, known := contentTypes[strings.ToLower(path.Ext(rel))]
	if !known {
		ct = "application/octet-stream"
	}
	hd := w.Header()
	hd.Set("Content-Type", ct)
	hd.Set("Content-Security-Policy", cspLocked)
	hd.Set("Cache-Control", "public, max-age=31536000, immutable")
	hd.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
