package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// captureLogger returns a slog.Logger whose JSON output is accumulated into
// the returned buffer. Tests assert on the buffer contents to verify
// Warn/Error emissions.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return log, buf
}

// --- InterpolateEnvVars -----------------------------------------------------

func TestInterpolateEnvVars_PlainString(t *testing.T) {
	got := InterpolateEnvVars("just plain text")
	if got != "just plain text" {
		t.Fatalf("want unchanged, got %q", got)
	}
}

func TestInterpolateEnvVars_SetVar(t *testing.T) {
	t.Setenv("JAY_TEST_FOO", "hello")
	got := InterpolateEnvVars("x=${JAY_TEST_FOO}")
	if got != "x=hello" {
		t.Fatalf("want x=hello, got %q", got)
	}
}

func TestInterpolateEnvVars_UnsetVarNoDefault(t *testing.T) {
	// Explicitly unset to avoid leakage from the host env.
	os.Unsetenv("JAY_TEST_UNSET")
	got := InterpolateEnvVars("x=${JAY_TEST_UNSET}")
	if got != "x=" {
		t.Fatalf("want x=, got %q", got)
	}
}

func TestInterpolateEnvVars_UnsetVarWithDefault(t *testing.T) {
	os.Unsetenv("JAY_TEST_UNSET")
	got := InterpolateEnvVars("x=${JAY_TEST_UNSET:-fallback}")
	if got != "x=fallback" {
		t.Fatalf("want x=fallback, got %q", got)
	}
}

func TestInterpolateEnvVars_SetVarWithDefaultIgnored(t *testing.T) {
	t.Setenv("JAY_TEST_SET", "real")
	got := InterpolateEnvVars("x=${JAY_TEST_SET:-fallback}")
	if got != "x=real" {
		t.Fatalf("want x=real, got %q", got)
	}
}

func TestInterpolateEnvVars_MultipleAndNested(t *testing.T) {
	t.Setenv("JAY_TEST_A", "alpha")
	t.Setenv("JAY_TEST_B", "beta")
	os.Unsetenv("JAY_TEST_C")
	got := InterpolateEnvVars("${JAY_TEST_A}-${JAY_TEST_B}-${JAY_TEST_C:-gamma}")
	if got != "alpha-beta-gamma" {
		t.Fatalf("want alpha-beta-gamma, got %q", got)
	}
}

// --- ReadYAMLFile -----------------------------------------------------------

const validYAML = `
data_dir: /var/lib/jay
listen_addr: ":4010"
admin_addr: ":4011"
native_addr: ":4012"
admin_token: very-long-admin-token-for-yaml-test-32
signing_secret: very-long-signing-secret-for-yaml-32
log_level: debug
rate_limit: 250.0
rate_burst: 500
trust_proxy_headers: true
scrub:
  interval_hours: 12
  sample_rate: 0.25
  bytes_per_sec: 104857600
  max_per_run: 200
seed_token:
  account: falco
  id: falco-native
  secret: seed-secret-value
`

func TestReadYAMLFile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jay.yaml")
	if err := os.WriteFile(path, []byte(validYAML), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	got, err := ReadYAMLFile(path)
	if err != nil {
		t.Fatalf("ReadYAMLFile: %v", err)
	}

	checks := map[string]any{
		"data_dir":             "/var/lib/jay",
		"listen_addr":          ":4010",
		"log_level":            "debug",
		"rate_limit":           250.0,
		"rate_burst":           500,
		"trust_proxy_headers":  true,
		"scrub.interval_hours": 12,
		"scrub.sample_rate":    0.25,
		"scrub.max_per_run":    200,
		"seed_token.account":   "falco",
		"seed_token.id":        "falco-native",
		"seed_token.secret":    "seed-secret-value",
	}
	for k, want := range checks {
		gv, ok := got[k]
		if !ok {
			t.Errorf("missing key %q", k)
			continue
		}
		if !equalAny(gv, want) {
			t.Errorf("key %q: want %v (%T), got %v (%T)", k, want, want, gv, gv)
		}
	}
}

func TestReadYAMLFile_Missing(t *testing.T) {
	_, err := ReadYAMLFile("/definitely/not/there/jay.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadYAMLFile_Malformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("::\n  - not: [valid"), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	_, err := ReadYAMLFile(path)
	if err == nil {
		t.Fatal("expected error for malformed yaml")
	}
}

// --- LoadConfigFromSources --------------------------------------------------

func TestLoadConfigFromSources_YAMLOnly(t *testing.T) {
	// Clear every env var this test touches so YAML wins by default.
	clearJAYEnv(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "jay.yaml")
	if err := os.WriteFile(path, []byte(validYAML), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	log, buf := captureLogger()
	cfg, err := LoadConfigFromSources(path, log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}

	if cfg.DataDir != "/var/lib/jay" {
		t.Errorf("DataDir: want /var/lib/jay, got %q", cfg.DataDir)
	}
	if cfg.ListenAddr != ":4010" {
		t.Errorf("ListenAddr: want :4010, got %q", cfg.ListenAddr)
	}
	if cfg.AdminToken != "very-long-admin-token-for-yaml-test-32" {
		t.Errorf("AdminToken: wrong value: %q", cfg.AdminToken)
	}
	if cfg.RateLimit != 250 {
		t.Errorf("RateLimit: want 250, got %v", cfg.RateLimit)
	}
	if cfg.RateBurst != 500 {
		t.Errorf("RateBurst: want 500, got %v", cfg.RateBurst)
	}
	if !cfg.TrustProxyHeaders {
		t.Error("TrustProxyHeaders: want true")
	}
	if cfg.ScrubInterval != 12*time.Hour {
		t.Errorf("ScrubInterval: want 12h, got %v", cfg.ScrubInterval)
	}
	if cfg.ScrubSampleRate != 0.25 {
		t.Errorf("ScrubSampleRate: want 0.25, got %v", cfg.ScrubSampleRate)
	}
	if cfg.ScrubBytesPerSec != 104857600 {
		t.Errorf("ScrubBytesPerSec: want 104857600, got %v", cfg.ScrubBytesPerSec)
	}
	if cfg.ScrubMaxPerRun != 200 {
		t.Errorf("ScrubMaxPerRun: want 200, got %v", cfg.ScrubMaxPerRun)
	}
	if cfg.SeedTokenAccount != "falco" || cfg.SeedTokenID != "falco-native" || cfg.SeedTokenSecret != "seed-secret-value" {
		t.Errorf("seed token mismatch: %+v", cfg)
	}

	// No env overrides, so no conflict warnings.
	if strings.Contains(buf.String(), "env var overrides YAML value") {
		t.Errorf("unexpected conflict warning: %s", buf.String())
	}
}

func TestLoadConfigFromSources_EnvOnly(t *testing.T) {
	clearJAYEnv(t)

	t.Setenv("JAY_DATA_DIR", "/env/data")
	t.Setenv("JAY_LISTEN_ADDR", ":5000")
	t.Setenv("JAY_ADMIN_TOKEN", "a-32-char-admin-token-for-testing!!")
	t.Setenv("JAY_SIGNING_SECRET", "a-32-char-signing-secret-for-test!!")
	t.Setenv("JAY_RATE_LIMIT", "42.5")
	t.Setenv("JAY_RATE_BURST", "80")
	t.Setenv("JAY_TRUST_PROXY_HEADERS", "true")
	t.Setenv("JAY_SCRUB_INTERVAL_HOURS", "3")

	log, _ := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.DataDir != "/env/data" {
		t.Errorf("DataDir: got %q", cfg.DataDir)
	}
	if cfg.ListenAddr != ":5000" {
		t.Errorf("ListenAddr: got %q", cfg.ListenAddr)
	}
	if cfg.AdminToken != "a-32-char-admin-token-for-testing!!" {
		t.Errorf("AdminToken: got %q", cfg.AdminToken)
	}
	if cfg.SigningSecret != "a-32-char-signing-secret-for-test!!" {
		t.Errorf("SigningSecret: got %q", cfg.SigningSecret)
	}
	if cfg.RateLimit != 42.5 {
		t.Errorf("RateLimit: got %v", cfg.RateLimit)
	}
	if cfg.RateBurst != 80 {
		t.Errorf("RateBurst: got %v", cfg.RateBurst)
	}
	if !cfg.TrustProxyHeaders {
		t.Error("TrustProxyHeaders: want true")
	}
	if cfg.ScrubInterval != 3*time.Hour {
		t.Errorf("ScrubInterval: got %v", cfg.ScrubInterval)
	}
	// Untouched fields should still be defaults.
	if cfg.AdminAddr != ":9001" {
		t.Errorf("AdminAddr default not preserved: %q", cfg.AdminAddr)
	}
}

func TestLoadConfigFromSources_EnvOverridesYAML(t *testing.T) {
	clearJAYEnv(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "jay.yaml")
	if err := os.WriteFile(path, []byte(validYAML), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	t.Setenv("JAY_DATA_DIR", "/env/wins")
	t.Setenv("JAY_LISTEN_ADDR", ":9999")

	log, buf := captureLogger()
	cfg, err := LoadConfigFromSources(path, log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.DataDir != "/env/wins" {
		t.Errorf("DataDir: want /env/wins, got %q", cfg.DataDir)
	}
	if cfg.ListenAddr != ":9999" {
		t.Errorf("ListenAddr: want :9999, got %q", cfg.ListenAddr)
	}
	// YAML-only fields still come through.
	if cfg.AdminToken != "very-long-admin-token-for-yaml-test-32" {
		t.Errorf("AdminToken (yaml-only): got %q", cfg.AdminToken)
	}

	out := buf.String()
	if !strings.Contains(out, `"key":"data_dir"`) || !strings.Contains(out, `"env_var":"JAY_DATA_DIR"`) {
		t.Errorf("missing data_dir conflict warning in log: %s", out)
	}
	if !strings.Contains(out, `"key":"listen_addr"`) {
		t.Errorf("missing listen_addr conflict warning in log: %s", out)
	}
}

func TestLoadConfigFromSources_InterpolationFromEnv(t *testing.T) {
	clearJAYEnv(t)

	t.Setenv("MY_ADMIN_TOKEN", "interpolated-admin-token-32-chars!")

	dir := t.TempDir()
	path := filepath.Join(dir, "jay.yaml")
	yamlBody := `
admin_token: ${MY_ADMIN_TOKEN}
signing_secret: ${MY_SIGNING_SECRET:-fallback-signing-secret-32-chars!}
log_level: ${MY_LOG:-warn}
`
	if err := os.WriteFile(path, []byte(yamlBody), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	log, _ := captureLogger()
	cfg, err := LoadConfigFromSources(path, log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.AdminToken != "interpolated-admin-token-32-chars!" {
		t.Errorf("AdminToken: want interpolated, got %q", cfg.AdminToken)
	}
	if cfg.SigningSecret != "fallback-signing-secret-32-chars!" {
		t.Errorf("SigningSecret: want fallback, got %q", cfg.SigningSecret)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel: want warn, got %q", cfg.LogLevel)
	}
}

func TestLoadConfigFromSources_Defaults(t *testing.T) {
	clearJAYEnv(t)

	log, _ := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	want := defaultConfig()
	if cfg != want {
		t.Errorf("defaults mismatch:\nwant %+v\ngot  %+v", want, cfg)
	}
}

// --- helpers ----------------------------------------------------------------

// clearJAYEnv unsets every env var the config loader consumes so the test's
// baseline is known. t.Setenv restores the original value on cleanup.
func clearJAYEnv(t *testing.T) {
	t.Helper()
	vars := []string{
		"JAY_DATA_DIR", "JAY_LISTEN_ADDR", "JAY_ADMIN_ADDR", "JAY_NATIVE_ADDR",
		"JAY_ADMIN_TOKEN", "JAY_SIGNING_SECRET", "JAY_LOG_LEVEL",
		"JAY_TLS_CERT", "JAY_TLS_KEY",
		"JAY_RATE_LIMIT", "JAY_RATE_BURST", "JAY_TRUST_PROXY_HEADERS",
		"JAY_SCRUB_INTERVAL_HOURS", "JAY_SCRUB_SAMPLE_RATE",
		"JAY_SCRUB_BYTES_PER_SEC", "JAY_SCRUB_MAX_PER_RUN",
		"JAY_SEED_TOKEN_ACCOUNT", "JAY_SEED_TOKEN_ID", "JAY_SEED_TOKEN_SECRET",
		"JAY_CONFIG_FILE",
	}
	for _, v := range vars {
		t.Setenv(v, "")
		os.Unsetenv(v)
	}
}

// equalAny compares two values for test assertions, tolerating int/float
// coercions (YAML decodes small ints as int, but tests may use untyped
// literals that land as int).
func equalAny(got, want any) bool {
	switch w := want.(type) {
	case int:
		if g, ok := got.(int); ok {
			return g == w
		}
		if g, ok := got.(int64); ok {
			return g == int64(w)
		}
		if g, ok := got.(float64); ok {
			return g == float64(w)
		}
	case float64:
		if g, ok := got.(float64); ok {
			return g == w
		}
		if g, ok := got.(int); ok {
			return float64(g) == w
		}
	case string:
		if g, ok := got.(string); ok {
			return g == w
		}
	case bool:
		if g, ok := got.(bool); ok {
			return g == w
		}
	}
	return got == want
}
