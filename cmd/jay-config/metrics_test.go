package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// jay-config validate refuses the metrics configurations the server refuses to
// boot with (checkMetricsAccess), so a file it approves is one that starts.
func TestValidate_Metrics(t *testing.T) {
	cases := []struct {
		name, block, wantErr string
	}{
		{"a short token", "metrics:\n  token: short\n", "metrics.token must be >= 32 characters"},
		{"the admin token", "metrics:\n  token: " + longSecret + "\n", "metrics.token must differ from admin_token"},
		{"token and public", "metrics:\n  token: another-secret-that-is-long-enough-00\n  public: true\n", "mutually exclusive"},
		{"public as a quoted string", "metrics:\n  token: another-secret-that-is-long-enough-00\n  public: \"1\"\n", "mutually exclusive"},
		{"public that is not a bool", "metrics:\n  public: maybe\n", "expected bool for metrics.public"},
		{"a section that is not a mapping", "metrics: on\n", "metrics must be a mapping"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := filepath.Join(t.TempDir(), "config.yml")
			writeFile(t, in, validYAML()+c.block)
			code, _, stderrOut := runCLI(t, "validate", "--input", in)
			if code == 0 {
				t.Fatalf("validated; the server would not boot with:\n%s", c.block)
			}
			if !strings.Contains(stderrOut, c.wantErr) {
				t.Errorf("stderr does not name the problem %q: %s", c.wantErr, stderrOut)
			}
		})
	}

	for _, ok := range []struct{ name, block, wantWarn string }{
		{"a proper token", "metrics:\n  token: another-secret-that-is-long-enough-00\n", ""},
		{"an interpolated token", "metrics:\n  token: ${JAY_METRICS_TOKEN:-}\n  public: false\n", ""},
		{"public", "metrics:\n  public: true\n", "answers without authentication"},
		{"an unknown key", "metrics:\n  tokn: x\n", `unknown metrics key "tokn"`},
	} {
		t.Run(ok.name, func(t *testing.T) {
			in := filepath.Join(t.TempDir(), "config.yml")
			writeFile(t, in, validYAML()+ok.block)
			code, _, stderrOut := runCLI(t, "validate", "--input", in)
			if code != 0 {
				t.Fatalf("rejected:\n%s\n%s", ok.block, stderrOut)
			}
			if ok.wantWarn != "" && !strings.Contains(stderrOut, ok.wantWarn) {
				t.Errorf("no warning %q: %s", ok.wantWarn, stderrOut)
			}
		})
	}
}

// Both keys survive both conversions, with their types.
func TestMetricsKeys_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "config.yml")
	writeFile(t, in, "metrics:\n  token: ${JAY_METRICS_TOKEN}\n  public: false\n")

	envOut := filepath.Join(dir, "out.env")
	if code, _, stderrOut := runCLI(t, "yaml-to-env", "--input", in, "--output", envOut); code != 0 {
		t.Fatalf("yaml-to-env: %s", stderrOut)
	}
	env, err := os.ReadFile(envOut)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"JAY_METRICS_TOKEN=${JAY_METRICS_TOKEN}", "JAY_METRICS_PUBLIC=false"} {
		if !strings.Contains(string(env), want) {
			t.Errorf("env output lacks %q:\n%s", want, env)
		}
	}

	yamlOut := filepath.Join(dir, "back.yml")
	if code, _, stderrOut := runCLI(t, "env-to-yaml", "--input", envOut, "--output", yamlOut); code != 0 {
		t.Fatalf("env-to-yaml: %s", stderrOut)
	}
	back, err := os.ReadFile(yamlOut)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"metrics:", "token: ${JAY_METRICS_TOKEN}", "public: false"} {
		if !strings.Contains(string(back), want) {
			t.Errorf("yaml output lacks %q:\n%s", want, back)
		}
	}
}
