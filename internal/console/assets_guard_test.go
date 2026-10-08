package console

import (
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

// uiComplete flips to true when the UI is finished (T8): from then on a stub
// marker or a missing font fails the build. Before that the shell ships stubs
// and no fonts, on purpose.
const uiComplete = true

const docsURL = "https://ivangsm.github.io/jay/"

// svgNamespace is the one http:// string a file may carry: an XML namespace
// identifier, which no browser ever fetches.
const svgNamespace = "http://www.w3.org/2000/svg"

// Banned in every .js file. The call-shaped ones must not be glued to an
// identifier, so "retrieval(" is not "eval(" but "x.confirm(" is "confirm(".
var (
	bannedLiterals = []string{
		"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
		"new Function", "setAttribute('on", `setAttribute("on`, "javascript:",
		"sessionStorage", "window.confirm", "window.alert", "window.prompt",
	}
	bannedCalls = regexp.MustCompile(`(?:^|[^\w$])(eval|confirm|alert|prompt)\(`)
)

func checkJS(name, src string) []string {
	var out []string
	for _, b := range bannedLiterals {
		if strings.Contains(src, b) {
			out = append(out, name+": contains banned "+b)
		}
	}
	if m := bannedCalls.FindStringSubmatch(src); m != nil {
		out = append(out, name+": calls banned "+m[1]+"(")
	}
	if strings.Contains(src, "localStorage") && name != "js/prefs.js" {
		out = append(out, name+": uses localStorage outside js/prefs.js")
	}
	return out
}

var (
	scriptTag = regexp.MustCompile(`(?is)<script\b([^>]*)>`)
	styleAttr = regexp.MustCompile(`(?is)<[a-z][^>]*\sstyle\s*=`)
	onAttr    = regexp.MustCompile(`(?is)<[a-z][^>]*\son[a-z]+\s*=`)
	urlAttr   = regexp.MustCompile(`(?is)\s(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

func checkIndex(src string) []string {
	var out []string
	for _, m := range scriptTag.FindAllStringSubmatch(src, -1) {
		if !strings.Contains(strings.ToLower(m[1]), "src=") {
			out = append(out, "index.html: inline <script>")
		}
	}
	if styleAttr.MatchString(src) {
		out = append(out, "index.html: style= attribute")
	}
	if onAttr.MatchString(src) {
		out = append(out, "index.html: on*= event attribute")
	}
	for _, m := range urlAttr.FindAllStringSubmatch(src, -1) {
		v := m[1] + m[2]
		if !strings.HasPrefix(v, "{{.Base}}") && v != docsURL {
			out = append(out, "index.html: src/href "+v+" is neither {{.Base}}... nor the docs link")
		}
	}
	return out
}

var cssBanned = regexp.MustCompile(`(?i)url\(\s*['"]?https?:|@import`)

func checkCSS(name, src string) []string {
	if cssBanned.MatchString(src) {
		return []string{name + ": external url() or @import"}
	}
	return nil
}

// checkExternal flags any absolute URL other than the allowed ones.
func checkExternal(name, src string) []string {
	if name == "fonts/OFL.txt" {
		return nil
	}
	src = strings.ReplaceAll(src, docsURL, "")
	if strings.HasSuffix(name, ".svg") {
		src = strings.ReplaceAll(src, svgNamespace, "")
	}
	if strings.Contains(src, "http://") || strings.Contains(src, "https://") {
		return []string{name + ": contains an absolute http(s) URL"}
	}
	return nil
}

var importSpec = regexp.MustCompile(`(?:\bfrom\s*|\bimport\s*\(?\s*)['"]([^'"]+)['"]`)

// moduleImports resolves every import of a module. External or bare specifiers
// are violations: the console loads nothing it did not ship.
func moduleImports(fsys fs.FS, name, src string) (resolved, violations []string) {
	for _, m := range importSpec.FindAllStringSubmatch(src, -1) {
		spec := m[1]
		if !strings.HasPrefix(spec, "./") && !strings.HasPrefix(spec, "../") {
			violations = append(violations, name+": non-relative import "+spec)
			continue
		}
		target := path.Join(path.Dir(name), spec)
		if _, err := fs.Stat(fsys, target); err != nil {
			violations = append(violations, name+": import "+spec+" resolves to "+target+", which is not in the FS")
			continue
		}
		resolved = append(resolved, target)
	}
	return resolved, violations
}

// unreachableViews lists modules under js/views/ that app.js never reaches,
// directly or through other modules.
func unreachableViews(graph map[string][]string, modules []string) []string {
	seen := map[string]bool{"js/app.js": true}
	queue := []string{"js/app.js"}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range graph[cur] {
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
	var out []string
	for _, m := range modules {
		if strings.HasPrefix(m, "js/views/") && !seen[m] {
			out = append(out, m+": never imported from js/app.js")
		}
	}
	return out
}

// checkTree runs every guard over fsys and returns all violations, sorted.
func checkTree(fsys fs.FS) ([]string, error) {
	var violations []string
	var jsModules []string
	graph := map[string][]string{}

	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasSuffix(p, ".woff2") {
			return nil // binary: nothing textual to inspect
		}
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		src := string(raw)
		violations = append(violations, checkExternal(p, src)...)
		if uiComplete && strings.Contains(src, "CONSOLE-STUB") {
			violations = append(violations, p+": still carries the CONSOLE-STUB marker")
		}
		switch path.Ext(p) {
		case ".js":
			jsModules = append(jsModules, p)
			violations = append(violations, checkJS(p, src)...)
			resolved, bad := moduleImports(fsys, p, src)
			violations = append(violations, bad...)
			graph[p] = resolved
		case ".css":
			violations = append(violations, checkCSS(p, src)...)
		}
		if p == "index.html" {
			violations = append(violations, checkIndex(src)...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	violations = append(violations, unreachableViews(graph, jsModules)...)

	if uiComplete {
		for _, f := range []string{
			"fonts/IBMPlexSans-400.woff2", "fonts/IBMPlexSans-600.woff2",
			"fonts/IBMPlexMono-400.woff2", "fonts/IBMPlexMono-500.woff2", "fonts/OFL.txt",
		} {
			if _, err := fs.Stat(fsys, f); err != nil {
				violations = append(violations, f+": missing")
			}
		}
	}
	sort.Strings(violations)
	return violations, nil
}

// The shipped tree is the subject.
func TestEmbeddedAssetsPassEveryGuard(t *testing.T) {
	fsys, err := embeddedAssets()
	if err != nil {
		t.Fatal(err)
	}
	violations, err := checkTree(fsys)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range violations {
		t.Error(v)
	}
}

// A guard that cannot fail guards nothing: each one is shown a tree that breaks
// exactly its rule.
func TestGuardsCatchViolations(t *testing.T) {
	cleanIndex := `<!doctype html><link href="{{.Base}}console.css"><script type="module" src="{{.Base}}js/app.js"></script><a href="` + docsURL + `">docs</a>`
	file := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
	tree := func(extra fstest.MapFS) fstest.MapFS {
		m := fstest.MapFS{"index.html": file(cleanIndex), "js/app.js": file("export {};")}
		// With uiComplete the guard also demands the shipped fonts, so a clean
		// tree has to carry them or every case would fail for the wrong reason.
		for _, p := range []string{
			"fonts/IBMPlexSans-400.woff2", "fonts/IBMPlexSans-600.woff2",
			"fonts/IBMPlexMono-400.woff2", "fonts/IBMPlexMono-500.woff2", "fonts/OFL.txt",
		} {
			m[p] = file("x")
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	clean, err := checkTree(tree(nil))
	if err != nil || len(clean) != 0 {
		t.Fatalf("a clean tree must pass: %v, %v", clean, err)
	}

	cases := []struct {
		name string
		fsys fstest.MapFS
		want string
	}{
		{"innerHTML", tree(fstest.MapFS{"js/app.js": file("el.innerHTML = x")}), "innerHTML"},
		{"outerHTML", tree(fstest.MapFS{"js/app.js": file("el.outerHTML = x")}), "outerHTML"},
		{"insertAdjacentHTML", tree(fstest.MapFS{"js/app.js": file("el.insertAdjacentHTML('a', x)")}), "insertAdjacentHTML"},
		{"document.write", tree(fstest.MapFS{"js/app.js": file("document.write(x)")}), "document.write"},
		{"eval", tree(fstest.MapFS{"js/app.js": file("eval(x)")}), "eval("},
		{"new Function", tree(fstest.MapFS{"js/app.js": file("new Function('x')")}), "new Function"},
		{"setAttribute on", tree(fstest.MapFS{"js/app.js": file(`el.setAttribute('onclick', x)`)}), "setAttribute('on"},
		{"javascript url", tree(fstest.MapFS{"js/app.js": file(`a.href = "javascript:x"`)}), "javascript:"},
		{"sessionStorage", tree(fstest.MapFS{"js/app.js": file("sessionStorage.x")}), "sessionStorage"},
		{"window.confirm", tree(fstest.MapFS{"js/app.js": file("window.confirm('x')")}), "window.confirm"},
		{"bare confirm", tree(fstest.MapFS{"js/app.js": file("if (confirm('x')) {}")}), "confirm("},
		{"bare alert", tree(fstest.MapFS{"js/app.js": file("alert('x')")}), "alert("},
		{"bare prompt", tree(fstest.MapFS{"js/app.js": file("prompt('x')")}), "prompt("},
		{"localStorage outside prefs", tree(fstest.MapFS{"js/app.js": file("localStorage.x")}), "localStorage"},
		{"inline script", tree(fstest.MapFS{"index.html": file(cleanIndex + `<script>x()</script>`)}), "inline <script>"},
		{"style attribute", tree(fstest.MapFS{"index.html": file(cleanIndex + `<p style="color:red">`)}), "style="},
		{"event attribute", tree(fstest.MapFS{"index.html": file(cleanIndex + `<body onload="x()">`)}), "on*="},
		{"foreign href", tree(fstest.MapFS{"index.html": file(cleanIndex + `<a href="https://evil.example/">`)}), "evil.example"},
		{"relative href", tree(fstest.MapFS{"index.html": file(cleanIndex + `<link href="app.css">`)}), "app.css"},
		{"css import", tree(fstest.MapFS{"console.css": file(`@import "x.css";`)}), "@import"},
		{"css external url", tree(fstest.MapFS{"console.css": file(`a{background:url(https://x/y.png)}`)}), "url()"},
		{"absolute url in js", tree(fstest.MapFS{"js/app.js": file(`fetch("https://evil.example/x")`)}), "absolute http(s)"},
		{"absolute url in svg", tree(fstest.MapFS{"x.svg": file(`<image href="http://evil.example/x"/>`)}), "absolute http(s)"},
		{"missing import", tree(fstest.MapFS{"js/app.js": file(`import { a } from './nope.js';`)}), "not in the FS"},
		{"external import", tree(fstest.MapFS{"js/app.js": file(`import { a } from 'https://cdn.example/a.js';`)}), "non-relative"},
		{"dynamic missing import", tree(fstest.MapFS{"js/app.js": file(`const m = await import('./nope.js');`)}), "not in the FS"},
		{"orphan view", tree(fstest.MapFS{"js/views/orphan.js": file("export {};")}), "never imported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := checkTree(tc.fsys)
			if err != nil {
				t.Fatal(err)
			}
			if !containsSub(got, tc.want) {
				t.Fatalf("no violation mentioning %q in %v", tc.want, got)
			}
		})
	}

	// Things that must NOT trip a guard.
	ok := map[string]fstest.MapFS{
		"identifier ending in eval": tree(fstest.MapFS{"js/app.js": file("retrieval(x); const confirmDestructive = 1;")}),
		"localStorage in prefs":     tree(fstest.MapFS{"js/prefs.js": file("localStorage.x"), "js/app.js": file("import './prefs.js';")}),
		"view reached via a module": tree(fstest.MapFS{"js/app.js": file("import './views/a.js';"), "js/views/a.js": file("import './b.js';"), "js/views/b.js": file("export {};")}),
		"svg namespace":             tree(fstest.MapFS{"favicon.svg": file(`<svg xmlns="` + svgNamespace + `"/>`)}),
		"license text with urls":    tree(fstest.MapFS{"fonts/OFL.txt": file("see http://scripts.sil.org/OFL")}),
		"relative url in css":       tree(fstest.MapFS{"console.css": file(`@font-face{src:url("fonts/a.woff2")}`)}),
		"parent-relative import":    tree(fstest.MapFS{"js/app.js": file("import '../js/x.js';"), "js/x.js": file("export {};")}),
		"docs link":                 tree(nil),
	}
	for name, fsys := range ok {
		t.Run("allows "+name, func(t *testing.T) {
			got, err := checkTree(fsys)
			if err != nil || len(got) != 0 {
				t.Fatalf("unexpected violations: %v (%v)", got, err)
			}
		})
	}
}

func containsSub(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
