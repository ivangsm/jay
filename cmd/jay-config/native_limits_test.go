package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// jay-config validate must refuse what the server refuses, or it approves a
// file the server will not boot with.
func TestValidate_NativeLimits(t *testing.T) {
	cases := []struct {
		line    string
		wantErr string
	}{
		{"native_max_conns: 0", "native_max_conns must be > 0"},
		{"native_max_conns: -3", "native_max_conns must be > 0"},
		{"native_token_bytes_per_sec: -1", "native_token_bytes_per_sec must be >= 0"},
		{"native_max_conns: many", "expected int for native_max_conns"},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			in := filepath.Join(t.TempDir(), "config.yml")
			writeFile(t, in, validYAML()+tc.line+"\n")
			code, _, stderrOut := runCLI(t, "validate", "--input", in)
			if code == 0 {
				t.Fatalf("%q validated; the server would not boot with it", tc.line)
			}
			if !strings.Contains(stderrOut, tc.wantErr) {
				t.Errorf("stderr does not name the problem %q: %s", tc.wantErr, stderrOut)
			}
		})
	}

	t.Run("valid values pass", func(t *testing.T) {
		in := filepath.Join(t.TempDir(), "config.yml")
		writeFile(t, in, validYAML()+"native_max_conns: 200\nnative_token_bytes_per_sec: 0\n")
		if code, _, stderrOut := runCLI(t, "validate", "--input", in); code != 0 {
			t.Fatalf("valid native limits were rejected: %s", stderrOut)
		}
	})
}

// The keys survive both conversions, as ints.
func TestNativeLimits_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "config.yml")
	envOut := filepath.Join(dir, ".env")
	yamlOut := filepath.Join(dir, "back.yml")
	writeFile(t, in, validYAML()+"native_max_conns: 200\nnative_token_bytes_per_sec: 1048576\n")

	if code, _, stderrOut := runCLI(t, "yaml-to-env", "--input", in, "--output", envOut); code != 0 {
		t.Fatalf("yaml-to-env: %s", stderrOut)
	}
	if code, _, stderrOut := runCLI(t, "env-to-yaml", "--input", envOut, "--output", yamlOut); code != 0 {
		t.Fatalf("env-to-yaml: %s", stderrOut)
	}
	if code, _, stderrOut := runCLI(t, "validate", "--input", yamlOut); code != 0 {
		t.Fatalf("the round-tripped file does not validate: %s", stderrOut)
	}
	for _, path := range []string{envOut, yamlOut} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		content := string(raw)
		for _, want := range []string{"200", "1048576"} {
			if !strings.Contains(content, want) {
				t.Errorf("%s lost %s: %s", filepath.Base(path), want, content)
			}
		}
	}
}
