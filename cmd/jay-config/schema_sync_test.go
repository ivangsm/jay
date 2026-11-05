package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// bindingsSource is the server's canonical binding table. fieldSpecs here is a
// hand-maintained copy of it; a key present in one and not the other makes
// yaml-to-env drop a setting the server reads, so drift fails the build.
const bindingsSource = "../jay/config_loader.go"

func envKeysInBindings(t *testing.T) map[string]bool {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, bindingsSource, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", bindingsSource, err)
	}

	keys := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		v, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if strings.HasPrefix(v, "JAY_") {
			keys[v] = true
		}
		return true
	})

	if len(keys) == 0 {
		t.Fatalf("no JAY_* literals found in %s; the test can no longer see the bindings", bindingsSource)
	}
	return keys
}

func TestFieldSpecsCoverEveryBinding(t *testing.T) {
	inBindings := envKeysInBindings(t)

	inSpecs := map[string]bool{}
	for _, s := range fieldSpecs {
		inSpecs[s.envKey] = true
	}

	for key := range inBindings {
		if !inSpecs[key] {
			t.Errorf("%s is bound by the server but missing from fieldSpecs: jay-config would drop it", key)
		}
	}
	for key := range inSpecs {
		if !inBindings[key] {
			t.Errorf("%s is in fieldSpecs but the server does not bind it", key)
		}
	}
}

// Every YAML path in fieldSpecs must also be reachable by the known-key
// checks, or validate/yaml-to-env warn about a key they themselves define.
func TestKnownKeysCoverEverySpec(t *testing.T) {
	for _, s := range fieldSpecs {
		if !topLevelKnownKeys[s.yamlPath[0]] {
			t.Errorf("%s: top-level key %q not in topLevelKnownKeys", s.yamlKey, s.yamlPath[0])
		}
		if len(s.yamlPath) == 2 {
			sub := nestedKnownKeys[s.yamlPath[0]]
			if sub == nil {
				t.Errorf("%s: no nested key set for section %q", s.yamlKey, s.yamlPath[0])
				continue
			}
			if !sub[s.yamlPath[1]] {
				t.Errorf("%s: %q not in nestedKnownKeys[%q]", s.yamlKey, s.yamlPath[1], s.yamlPath[0])
			}
		}
	}
}
