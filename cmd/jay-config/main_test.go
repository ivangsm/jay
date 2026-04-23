package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

const longSecret = "abcdefghijklmnopqrstuvwxyz0123456" // 33 chars

func validYAML() string {
	return `data_dir: ./data
listen_addr: ":4010"
admin_addr: ":4011"
native_addr: ":4012"
admin_token: ` + longSecret + `
signing_secret: ` + longSecret + `
log_level: info
rate_limit: 100
rate_burst: 200
trust_proxy_headers: true
scrub:
  interval_hours: 6
  sample_rate: 0.1
  bytes_per_sec: 52428800
  max_per_run: 100
seed_token:
  account: acct_123
  id: tok_123
  secret: s3cret
`
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestYAMLToEnv_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "config.yml")
	out := filepath.Join(dir, ".env")
	writeFile(t, in, validYAML())

	code, _, stderrOut := runCLI(t, "yaml-to-env", "--input", in, "--output", out)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderrOut)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	content := string(data)

	wants := map[string]string{
		"JAY_DATA_DIR":             "./data",
		"JAY_LISTEN_ADDR":          ":4010",
		"JAY_ADMIN_TOKEN":          longSecret,
		"JAY_LOG_LEVEL":            "info",
		"JAY_RATE_LIMIT":           "100",
		"JAY_RATE_BURST":           "200",
		"JAY_TRUST_PROXY_HEADERS":  "true",
		"JAY_SCRUB_INTERVAL_HOURS": "6",
		"JAY_SCRUB_SAMPLE_RATE":    "0.1",
		"JAY_SCRUB_BYTES_PER_SEC":  "52428800",
		"JAY_SCRUB_MAX_PER_RUN":    "100",
		"JAY_SEED_TOKEN_ACCOUNT":   "acct_123",
		"JAY_SEED_TOKEN_ID":        "tok_123",
		"JAY_SEED_TOKEN_SECRET":    "s3cret",
	}
	for k, v := range wants {
		needle := k + "=" + v
		if !strings.Contains(content, needle) {
			t.Errorf("expected %q in output, got:\n%s", needle, content)
		}
	}
}

func TestYAMLToEnv_PreservesInterpolation(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "config.yml")
	out := filepath.Join(dir, ".env")
	writeFile(t, in, `admin_token: ${MY_ADMIN_TOKEN}
signing_secret: ${MY_SIGNING_SECRET}
`)

	code, _, stderrOut := runCLI(t, "yaml-to-env", "--input", in, "--output", out)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderrOut)
	}
	data, _ := os.ReadFile(out)
	content := string(data)
	if !strings.Contains(content, "JAY_ADMIN_TOKEN=${MY_ADMIN_TOKEN}") {
		t.Errorf("interpolation not preserved: %s", content)
	}
	if !strings.Contains(content, "JAY_SIGNING_SECRET=${MY_SIGNING_SECRET}") {
		t.Errorf("interpolation not preserved: %s", content)
	}
}

func TestYAMLToEnv_NestedNamespaces(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "config.yml")
	out := filepath.Join(dir, ".env")
	writeFile(t, in, `scrub:
  interval_hours: 12
  sample_rate: 0.25
seed_token:
  account: a
  id: i
  secret: s
`)
	code, _, _ := runCLI(t, "yaml-to-env", "--input", in, "--output", out)
	if code != 0 {
		t.Fatal("non-zero exit")
	}
	data, _ := os.ReadFile(out)
	content := string(data)
	wants := []string{
		"JAY_SCRUB_INTERVAL_HOURS=12",
		"JAY_SCRUB_SAMPLE_RATE=0.25",
		"JAY_SEED_TOKEN_ACCOUNT=a",
		"JAY_SEED_TOKEN_ID=i",
		"JAY_SEED_TOKEN_SECRET=s",
	}
	for _, w := range wants {
		if !strings.Contains(content, w) {
			t.Errorf("missing %q in %s", w, content)
		}
	}
}

func TestYAMLToEnv_UnknownKey(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "config.yml")
	out := filepath.Join(dir, ".env")
	writeFile(t, in, `data_dir: ./data
mystery_key: 42
scrub:
  interval_hours: 6
  bogus_nested: yes
`)
	code, _, stderrOut := runCLI(t, "yaml-to-env", "--input", in, "--output", out)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderrOut)
	}
	if !strings.Contains(stderrOut, "mystery_key") {
		t.Errorf("expected warning about mystery_key, got: %s", stderrOut)
	}
	if !strings.Contains(stderrOut, "scrub.bogus_nested") {
		t.Errorf("expected warning about scrub.bogus_nested, got: %s", stderrOut)
	}
	data, _ := os.ReadFile(out)
	if !strings.Contains(string(data), "JAY_DATA_DIR=./data") {
		t.Errorf("expected JAY_DATA_DIR to be written")
	}
}

func TestEnvToYAML_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, ".env")
	out := filepath.Join(dir, "config.yml")
	writeFile(t, in, `# comment
JAY_DATA_DIR=./data
JAY_LISTEN_ADDR=:4010
JAY_ADMIN_TOKEN=`+longSecret+`
JAY_SIGNING_SECRET=`+longSecret+`
JAY_LOG_LEVEL=info
JAY_RATE_LIMIT=100
JAY_RATE_BURST=200
JAY_TRUST_PROXY_HEADERS=true
JAY_SCRUB_INTERVAL_HOURS=6
JAY_SCRUB_SAMPLE_RATE=0.1
JAY_SCRUB_BYTES_PER_SEC=52428800
JAY_SCRUB_MAX_PER_RUN=100
JAY_SEED_TOKEN_ACCOUNT=acct
JAY_SEED_TOKEN_ID=id
JAY_SEED_TOKEN_SECRET=secret
`)

	code, _, stderrOut := runCLI(t, "env-to-yaml", "--input", in, "--output", out)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderrOut)
	}
	data, _ := os.ReadFile(out)
	content := string(data)
	for _, w := range []string{
		"data_dir: ./data",
		"scrub:",
		"  interval_hours: 6",
		"seed_token:",
		"  account: acct",
	} {
		if !strings.Contains(content, w) {
			t.Errorf("missing %q in output:\n%s", w, content)
		}
	}
}

func TestEnvToYAML_TypeInference(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, ".env")
	out := filepath.Join(dir, "config.yml")
	writeFile(t, in, `JAY_DATA_DIR=./data
JAY_RATE_LIMIT=100
JAY_RATE_BURST=200
JAY_TRUST_PROXY_HEADERS=true
JAY_SCRUB_SAMPLE_RATE=0.5
`)
	code, _, _ := runCLI(t, "env-to-yaml", "--input", in, "--output", out)
	if code != 0 {
		t.Fatal("non-zero exit")
	}
	data, _ := os.ReadFile(out)
	content := string(data)

	if !strings.Contains(content, "rate_burst: 200") {
		t.Errorf("rate_burst should render as int: %s", content)
	}
	if !strings.Contains(content, "trust_proxy_headers: true") {
		t.Errorf("trust_proxy_headers should render as bool: %s", content)
	}
	if !strings.Contains(content, "sample_rate: 0.5") {
		t.Errorf("sample_rate should render as float: %s", content)
	}
	if !strings.Contains(content, "data_dir: ./data") {
		t.Errorf("data_dir should render as string: %s", content)
	}
}

func TestEnvToYAML_NestedNamespaces(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, ".env")
	out := filepath.Join(dir, "config.yml")
	writeFile(t, in, `JAY_SCRUB_INTERVAL_HOURS=6
JAY_SCRUB_MAX_PER_RUN=50
JAY_SEED_TOKEN_ACCOUNT=a
JAY_SEED_TOKEN_ID=i
JAY_SEED_TOKEN_SECRET=s
`)
	code, _, _ := runCLI(t, "env-to-yaml", "--input", in, "--output", out)
	if code != 0 {
		t.Fatal("non-zero exit")
	}
	data, _ := os.ReadFile(out)
	content := string(data)
	for _, w := range []string{"scrub:", "  interval_hours: 6", "  max_per_run: 50", "seed_token:", "  account: a", "  id: i", "  secret: s"} {
		if !strings.Contains(content, w) {
			t.Errorf("missing %q in:\n%s", w, content)
		}
	}
}

func TestValidate_Valid(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "config.yml")
	writeFile(t, in, validYAML())

	code, stdoutOut, stderrOut := runCLI(t, "validate", "--input", in)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d, stderr=%s", code, stderrOut)
	}
	if !strings.Contains(stdoutOut, "OK:") {
		t.Errorf("expected OK in stdout, got: %s", stdoutOut)
	}
}

func TestValidate_MissingSecret(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "config.yml")
	writeFile(t, in, `data_dir: ./data
signing_secret: `+longSecret+`
`)
	code, _, stderrOut := runCLI(t, "validate", "--input", in)
	if code == 0 {
		t.Fatal("expected non-zero exit")
	}
	if !strings.Contains(stderrOut, "admin_token") {
		t.Errorf("expected error mentioning admin_token: %s", stderrOut)
	}
}

func TestValidate_ShortSecret(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "config.yml")
	writeFile(t, in, `admin_token: short
signing_secret: `+longSecret+`
`)
	code, _, stderrOut := runCLI(t, "validate", "--input", in)
	if code == 0 {
		t.Fatalf("expected non-zero exit, stderr=%s", stderrOut)
	}
	if !strings.Contains(stderrOut, "32 characters") {
		t.Errorf("expected length error: %s", stderrOut)
	}
}

func TestValidate_InterpolatedSecret(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "config.yml")
	writeFile(t, in, `admin_token: ${ADMIN_TOKEN}
signing_secret: ${SIGNING_SECRET}
`)
	code, _, stderrOut := runCLI(t, "validate", "--input", in)
	if code != 0 {
		t.Fatalf("expected exit 0 for interpolated secrets, got %d, stderr=%s", code, stderrOut)
	}
}

func TestValidate_PartialSeedToken(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "config.yml")
	writeFile(t, in, `admin_token: `+longSecret+`
signing_secret: `+longSecret+`
seed_token:
  account: a
  id: i
`)
	code, _, stderrOut := runCLI(t, "validate", "--input", in)
	if code == 0 {
		t.Fatal("expected non-zero exit")
	}
	if !strings.Contains(stderrOut, "seed_token") || !strings.Contains(stderrOut, "secret") {
		t.Errorf("expected seed_token partial error mentioning missing 'secret': %s", stderrOut)
	}
}

func TestValidate_InvalidSampleRate(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "config.yml")
	writeFile(t, in, `admin_token: `+longSecret+`
signing_secret: `+longSecret+`
scrub:
  sample_rate: 2.0
`)
	code, _, stderrOut := runCLI(t, "validate", "--input", in)
	if code == 0 {
		t.Fatal("expected non-zero exit")
	}
	if !strings.Contains(stderrOut, "sample_rate") {
		t.Errorf("expected sample_rate error: %s", stderrOut)
	}
}

func TestValidate_UnknownKey(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "config.yml")
	writeFile(t, in, `admin_token: `+longSecret+`
signing_secret: `+longSecret+`
mystery_top_level: hello
`)
	code, stdoutOut, stderrOut := runCLI(t, "validate", "--input", in)
	if code != 0 {
		t.Fatalf("expected exit 0 (warning only), got %d, stderr=%s", code, stderrOut)
	}
	if !strings.Contains(stderrOut, "mystery_top_level") {
		t.Errorf("expected warning for unknown key: stderr=%s", stderrOut)
	}
	if !strings.Contains(stdoutOut, "OK:") {
		t.Errorf("expected OK stdout, got: %s", stdoutOut)
	}
}

func TestCLI_NoArgs(t *testing.T) {
	code, _, stderrOut := runCLI(t)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !strings.Contains(stderrOut, "Usage") {
		t.Errorf("expected usage in stderr: %s", stderrOut)
	}
}

func TestCLI_UnknownSubcommand(t *testing.T) {
	code, _, stderrOut := runCLI(t, "bogus")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !strings.Contains(stderrOut, "unknown subcommand") {
		t.Errorf("expected unknown subcommand message: %s", stderrOut)
	}
}

func TestYAMLToEnv_ToStdout(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "config.yml")
	writeFile(t, in, `data_dir: ./data
`)
	code, stdoutOut, _ := runCLI(t, "yaml-to-env", "--input", in)
	if code != 0 {
		t.Fatal("non-zero exit")
	}
	if !strings.Contains(stdoutOut, "JAY_DATA_DIR=./data") {
		t.Errorf("expected stdout to contain JAY_DATA_DIR, got: %s", stdoutOut)
	}
}

func TestEnvToYAML_Interpolated(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, ".env")
	out := filepath.Join(dir, "config.yml")
	writeFile(t, in, `JAY_ADMIN_TOKEN=${ADMIN_TOKEN}
JAY_SCRUB_INTERVAL_HOURS=${INTERVAL}
`)
	code, _, _ := runCLI(t, "env-to-yaml", "--input", in, "--output", out)
	if code != 0 {
		t.Fatal("non-zero exit")
	}
	data, _ := os.ReadFile(out)
	content := string(data)
	if !strings.Contains(content, "${ADMIN_TOKEN}") {
		t.Errorf("interpolation not preserved in yaml: %s", content)
	}
	if !strings.Contains(content, "${INTERVAL}") {
		t.Errorf("interpolation on int field not preserved: %s", content)
	}
}

