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
	_ = os.Unsetenv("JAY_TEST_UNSET")
	got := InterpolateEnvVars("x=${JAY_TEST_UNSET}")
	if got != "x=" {
		t.Fatalf("want x=, got %q", got)
	}
}

func TestInterpolateEnvVars_UnsetVarWithDefault(t *testing.T) {
	_ = os.Unsetenv("JAY_TEST_UNSET")
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
	_ = os.Unsetenv("JAY_TEST_C")
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
  bytes_per_sec: 104857600
  max_per_run: 200
backup:
  dir: /mnt/dr/jay-backups
min_free_bytes: 1073741824
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
		"scrub.max_per_run":    200,
		"backup.dir":           "/mnt/dr/jay-backups",
		"min_free_bytes":       1073741824,
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
	if cfg.ScrubBytesPerSec != 104857600 {
		t.Errorf("ScrubBytesPerSec: want 104857600, got %v", cfg.ScrubBytesPerSec)
	}
	if cfg.ScrubMaxPerRun != 200 {
		t.Errorf("ScrubMaxPerRun: want 200, got %v", cfg.ScrubMaxPerRun)
	}
	if cfg.SeedTokenAccount != "falco" || cfg.SeedTokenID != "falco-native" || cfg.SeedTokenSecret != "seed-secret-value" {
		t.Errorf("seed token mismatch: %+v", cfg)
	}
	if cfg.MetadataBackupDir != "/mnt/dr/jay-backups" {
		t.Errorf("MetadataBackupDir: want /mnt/dr/jay-backups, got %q", cfg.MetadataBackupDir)
	}
	if cfg.MinFreeBytes != 1073741824 {
		t.Errorf("MinFreeBytes: want 1073741824, got %d", cfg.MinFreeBytes)
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
	// BackupDir is a derived default resolved by LoadConfigFromSources after
	// all overlays, so defaultConfig leaves it empty.
	want.MetadataBackupDir = filepath.Join(want.DataDir, "backups")
	if cfg != want {
		t.Errorf("defaults mismatch:\nwant %+v\ngot  %+v", want, cfg)
	}
}

// --- backup dir + min free bytes ---------------------------------------------

func TestLoadConfigFromSources_BackupDirDefaultFollowsDataDir(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_DATA_DIR", "/env/data")

	log, _ := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if want := filepath.Join("/env/data", "backups"); cfg.MetadataBackupDir != want {
		t.Errorf("MetadataBackupDir: want %q, got %q", want, cfg.MetadataBackupDir)
	}
}

func TestLoadConfigFromSources_BackupDirEnvOverridesYAML(t *testing.T) {
	clearJAYEnv(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "jay.yaml")
	if err := os.WriteFile(path, []byte("backup:\n  dir: /yaml/backups\n"), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	t.Setenv("JAY_BACKUP_DIR", "/env/backups")

	log, _ := captureLogger()
	cfg, err := LoadConfigFromSources(path, log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.MetadataBackupDir != "/env/backups" {
		t.Errorf("MetadataBackupDir: want /env/backups, got %q", cfg.MetadataBackupDir)
	}
}

// --- the metadata_backup.dir rename ------------------------------------------
//
// backup.dir became metadata_backup.dir because the old name promised a copy of
// the objects and jay only ever copied the metadata. The old spelling has to
// keep working — a deployment that pointed JAY_BACKUP_DIR at a separate volume
// must not silently start writing snapshots back onto the data disk — and it
// has to say that it is the old spelling, or the rename never reaches anyone.

func TestLoadConfigFromSources_MetadataBackupDirCanonicalEnv(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_METADATA_BACKUP_DIR", "/mnt/dr/snapshots")

	log, buf := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.MetadataBackupDir != "/mnt/dr/snapshots" {
		t.Errorf("MetadataBackupDir: want /mnt/dr/snapshots, got %q", cfg.MetadataBackupDir)
	}
	if strings.Contains(buf.String(), "deprecated") {
		t.Errorf("the canonical name must not warn: %s", buf.String())
	}
}

func TestLoadConfigFromSources_DeprecatedBackupDirEnvStillWorksAndWarns(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_BACKUP_DIR", "/mnt/dr/snapshots")

	log, buf := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.MetadataBackupDir != "/mnt/dr/snapshots" {
		t.Errorf("the old spelling must keep working: got %q", cfg.MetadataBackupDir)
	}
	logged := buf.String()
	if !strings.Contains(logged, "deprecated environment variable") ||
		!strings.Contains(logged, "JAY_METADATA_BACKUP_DIR") {
		t.Errorf("expected a deprecation warning naming the replacement, got: %s", logged)
	}
}

func TestLoadConfigFromSources_DeprecatedBackupDirYAMLStillWorksAndWarns(t *testing.T) {
	clearJAYEnv(t)

	path := filepath.Join(t.TempDir(), "jay.yaml")
	if err := os.WriteFile(path, []byte("backup:\n  dir: /yaml/snapshots\n"), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	log, buf := captureLogger()
	cfg, err := LoadConfigFromSources(path, log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.MetadataBackupDir != "/yaml/snapshots" {
		t.Errorf("the old YAML key must keep working: got %q", cfg.MetadataBackupDir)
	}
	if !strings.Contains(buf.String(), "deprecated YAML key") {
		t.Errorf("expected a deprecation warning, got: %s", buf.String())
	}
}

// With both spellings set, the canonical one wins. The ordering in bindings()
// is what decides this, so it is asserted rather than trusted.
func TestLoadConfigFromSources_CanonicalBackupDirBeatsDeprecated(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_BACKUP_DIR", "/old/snapshots")
	t.Setenv("JAY_METADATA_BACKUP_DIR", "/new/snapshots")

	log, _ := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.MetadataBackupDir != "/new/snapshots" {
		t.Errorf("MetadataBackupDir: want /new/snapshots, got %q", cfg.MetadataBackupDir)
	}
}

func TestLoadConfigFromSources_MinFreeBytesDefault(t *testing.T) {
	clearJAYEnv(t)

	log, _ := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if want := int64(500 << 20); cfg.MinFreeBytes != want {
		t.Errorf("MinFreeBytes default: want %d, got %d", want, cfg.MinFreeBytes)
	}
}

func TestLoadConfigFromSources_MinFreeBytesFromEnv(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_MIN_FREE_BYTES", "0") // 0 = check disabled

	log, _ := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.MinFreeBytes != 0 {
		t.Errorf("MinFreeBytes: want 0, got %d", cfg.MinFreeBytes)
	}
}

func TestLoadConfigFromSources_MinFreeBytesInvalidEnvKeepsDefault(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_MIN_FREE_BYTES", "-42")

	log, buf := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if want := int64(500 << 20); cfg.MinFreeBytes != want {
		t.Errorf("MinFreeBytes: want default %d, got %d", want, cfg.MinFreeBytes)
	}
	if !strings.Contains(buf.String(), "JAY_MIN_FREE_BYTES") {
		t.Errorf("expected error log for invalid JAY_MIN_FREE_BYTES, got: %s", buf.String())
	}
}

func TestLoadConfigFromSources_MaxObjectSizeDefault(t *testing.T) {
	clearJAYEnv(t)

	log, _ := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if want := int64(5 << 30); cfg.MaxObjectSize != want {
		t.Errorf("MaxObjectSize default: want %d, got %d", want, cfg.MaxObjectSize)
	}
}

func TestLoadConfigFromSources_MaxObjectSizeFromEnv(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_MAX_OBJECT_SIZE", "0") // 0 = unlimited

	log, _ := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.MaxObjectSize != 0 {
		t.Errorf("MaxObjectSize: want 0, got %d", cfg.MaxObjectSize)
	}
}

func TestLoadConfigFromSources_MaxObjectSizeFromYAML(t *testing.T) {
	clearJAYEnv(t)

	path := filepath.Join(t.TempDir(), "jay.yaml")
	if err := os.WriteFile(path, []byte("max_object_size: 1048576\n"), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	log, _ := captureLogger()
	cfg, err := LoadConfigFromSources(path, log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.MaxObjectSize != 1048576 {
		t.Errorf("MaxObjectSize: want 1048576, got %d", cfg.MaxObjectSize)
	}
}

func TestLoadConfigFromSources_MaxObjectSizeInvalidEnvKeepsDefault(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_MAX_OBJECT_SIZE", "-1")

	log, buf := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if want := int64(5 << 30); cfg.MaxObjectSize != want {
		t.Errorf("MaxObjectSize: want default %d, got %d", want, cfg.MaxObjectSize)
	}
	if !strings.Contains(buf.String(), "JAY_MAX_OBJECT_SIZE") {
		t.Errorf("expected error log for invalid JAY_MAX_OBJECT_SIZE, got: %s", buf.String())
	}
}

// --- helpers ----------------------------------------------------------------

// clearJAYEnv unsets every env var the config loader consumes so the test's
// baseline is known. t.Setenv restores the original value on cleanup.
//
// The list comes from bindings() rather than being written out again. A
// hand-copied one had already gone stale — JAY_NATIVE_TLS_CERT and its key were
// missing — and a variable the suite forgets to clear makes every test that
// asserts a default depend on the developer's shell.
func clearJAYEnv(t *testing.T) {
	t.Helper()
	// JAY_CONFIG_FILE is read directly by main, not through a binding.
	vars := []string{"JAY_CONFIG_FILE"}
	for _, b := range bindings() {
		vars = append(vars, b.envVar)
	}
	for _, v := range vars {
		t.Setenv(v, "")
		_ = os.Unsetenv(v)
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

// --- empty values: "unset" for every key but native_addr ---------------------

// An empty JAY_NATIVE_ADDR is the documented off switch. It used to be
// discarded as "unset", so the native protocol came up on the :4444 default.
func TestLoadConfigFromSources_EmptyNativeAddrEnvDisablesNative(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_NATIVE_ADDR", "")

	log, _ := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.NativeAddr != "" {
		t.Errorf("NativeAddr = %q, want empty", cfg.NativeAddr)
	}
}

// Both doors, same answer: an asymmetry here is the same defect through the
// other one.
func TestLoadConfigFromSources_EmptyNativeAddrYAMLDisablesNative(t *testing.T) {
	clearJAYEnv(t)

	for _, body := range []string{"native_addr: \"\"\n", "native_addr:\n"} {
		path := filepath.Join(t.TempDir(), "jay.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write yaml: %v", err)
		}
		log, _ := captureLogger()
		cfg, err := LoadConfigFromSources(path, log)
		if err != nil {
			t.Fatalf("LoadConfigFromSources(%q): %v", body, err)
		}
		if cfg.NativeAddr != "" {
			t.Errorf("%q: NativeAddr = %q, want empty", body, cfg.NativeAddr)
		}
	}
}

// An env var explicitly set to "" still wins over a YAML address: the operator
// asked for the listener to be off.
func TestLoadConfigFromSources_EmptyNativeAddrEnvOverridesYAML(t *testing.T) {
	clearJAYEnv(t)
	path := filepath.Join(t.TempDir(), "jay.yaml")
	if err := os.WriteFile(path, []byte("native_addr: \":4012\"\n"), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	t.Setenv("JAY_NATIVE_ADDR", "")

	log, buf := captureLogger()
	cfg, err := LoadConfigFromSources(path, log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.NativeAddr != "" {
		t.Errorf("NativeAddr = %q, want empty", cfg.NativeAddr)
	}
	if !strings.Contains(buf.String(), "env var overrides YAML value") {
		t.Errorf("expected an override warning, got: %s", buf.String())
	}
}

// Every other key keeps treating empty as "not configured". Honouring it
// literally would make an unset compose variable relocate the store or serve
// on :80.
func TestLoadConfigFromSources_EmptyEnvKeepsDefaults(t *testing.T) {
	clearJAYEnv(t)
	for _, v := range []string{"JAY_DATA_DIR", "JAY_LISTEN_ADDR", "JAY_ADMIN_ADDR", "JAY_LOG_LEVEL"} {
		t.Setenv(v, "")
	}

	log, buf := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	def := defaultConfig()
	if cfg.DataDir != def.DataDir || cfg.ListenAddr != def.ListenAddr ||
		cfg.AdminAddr != def.AdminAddr || cfg.LogLevel != def.LogLevel {
		t.Errorf("empty env vars changed the defaults: %+v", cfg)
	}
	if strings.Contains(buf.String(), "level\":\"ERROR") {
		t.Errorf("empty env vars must not log parse errors, got: %s", buf.String())
	}
}

// Same for numeric keys: an empty value is not a parse error to shout about.
func TestLoadConfigFromSources_EmptyNumericEnvKeepsDefaultsQuietly(t *testing.T) {
	clearJAYEnv(t)
	for _, v := range []string{"JAY_RATE_LIMIT", "JAY_RATE_BURST", "JAY_MIN_FREE_BYTES", "JAY_MAX_OBJECT_SIZE"} {
		t.Setenv(v, "")
	}

	log, buf := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	def := defaultConfig()
	if cfg.RateLimit != def.RateLimit || cfg.RateBurst != def.RateBurst ||
		cfg.MinFreeBytes != def.MinFreeBytes || cfg.MaxObjectSize != def.MaxObjectSize {
		t.Errorf("empty numeric env vars changed the defaults: %+v", cfg)
	}
	if strings.Contains(buf.String(), "invalid JAY_") {
		t.Errorf("empty numeric env vars must not log an invalid-value error, got: %s", buf.String())
	}
}

// The YAML side follows the same rule, and says so instead of silently
// applying an empty string that would have moved the listener to :80.
func TestLoadConfigFromSources_EmptyYAMLValueIgnoredAndWarned(t *testing.T) {
	clearJAYEnv(t)
	path := filepath.Join(t.TempDir(), "jay.yaml")
	if err := os.WriteFile(path, []byte("listen_addr: \"\"\ndata_dir: \"\"\n"), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	log, buf := captureLogger()
	cfg, err := LoadConfigFromSources(path, log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	def := defaultConfig()
	if cfg.ListenAddr != def.ListenAddr || cfg.DataDir != def.DataDir {
		t.Errorf("empty YAML values changed the defaults: %+v", cfg)
	}
	if !strings.Contains(buf.String(), "empty YAML value ignored") {
		t.Errorf("expected a warning for the ignored keys, got: %s", buf.String())
	}
}

// The secrets fail-fast lives in mustLoadConfig, which reads what the loader
// returns: an empty JAY_ADMIN_TOKEN must never resolve to something that
// passes the length check, and must not wipe a YAML-provided one either.
func TestLoadConfigFromSources_EmptySecretEnvDoesNotDefeatFailFast(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_ADMIN_TOKEN", "")
	t.Setenv("JAY_SIGNING_SECRET", "")

	log, _ := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if len(cfg.AdminToken) >= minSecretLen || len(cfg.SigningSecret) >= minSecretLen {
		t.Fatalf("empty secret env vars produced acceptable secrets: %q / %q",
			cfg.AdminToken, cfg.SigningSecret)
	}
}

func TestLoadConfigFromSources_EmptySecretEnvKeepsYAMLSecret(t *testing.T) {
	clearJAYEnv(t)
	const token = "yaml-admin-token-with-enough-characters"
	path := filepath.Join(t.TempDir(), "jay.yaml")
	if err := os.WriteFile(path, []byte("admin_token: \""+token+"\"\n"), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	t.Setenv("JAY_ADMIN_TOKEN", "")

	log, _ := captureLogger()
	cfg, err := LoadConfigFromSources(path, log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.AdminToken != token {
		t.Fatalf("AdminToken = %q, want the YAML value", cfg.AdminToken)
	}
}

// The documented YAML template is written with ${VAR:-} on the optional keys,
// so an ordinary boot interpolates several of them to "". Those must load
// without a single warning: an empty tls_cert is the same as no tls_cert, and
// seven lines of noise per boot is how operators learn to skip the one warning
// that means something.
func TestLoadConfigFromSources_EmptyYAMLValueOnOptionalKeysIsSilent(t *testing.T) {
	clearJAYEnv(t)
	path := filepath.Join(t.TempDir(), "jay.yaml")
	// backup.dir is in here on purpose alongside its replacement: an empty
	// deprecated key is a template that interpolated to nothing, and warning
	// "you used the old name" about a value that did nothing is the same noise
	// this test exists to keep out.
	body := "tls_cert: \"\"\ntls_key: \"\"\nbackup:\n  dir: \"\"\nmetadata_backup:\n  dir: \"\"\nseed_token:\n  account: \"\"\n  id: \"\"\n  secret: \"\"\nclient:\n  token_id: \"\"\n  token_secret: \"\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	log, buf := captureLogger()
	if _, err := LoadConfigFromSources(path, log); err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("optional empty keys must load silently, got: %s", buf.String())
	}
}

// Same on the env side: an unset variable passed through by a compose file
// must not warn when the key would have been empty anyway.
func TestLoadConfigFromSources_EmptyEnvOnOptionalKeysIsSilent(t *testing.T) {
	clearJAYEnv(t)
	for _, v := range []string{
		"JAY_TLS_CERT", "JAY_TLS_KEY",
		"JAY_BACKUP_DIR", "JAY_METADATA_BACKUP_DIR", "JAY_TOKEN_ID",
	} {
		t.Setenv(v, "")
	}

	log, buf := captureLogger()
	if _, err := LoadConfigFromSources("", log); err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("optional empty env vars must load silently, got: %s", buf.String())
	}
}

// But an empty value that DOES override something says so, through either
// door, with the same predicate.
func TestLoadConfigFromSources_IgnoredEmptyIsReportedOnBothDoors(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_LISTEN_ADDR", "")
	logEnv, bufEnv := captureLogger()
	if _, err := LoadConfigFromSources("", logEnv); err != nil {
		t.Fatalf("LoadConfigFromSources (env): %v", err)
	}
	if !strings.Contains(bufEnv.String(), "empty env var ignored") {
		t.Errorf("expected a warning for the ignored env var, got: %s", bufEnv.String())
	}

	clearJAYEnv(t)
	path := filepath.Join(t.TempDir(), "jay.yaml")
	if err := os.WriteFile(path, []byte("listen_addr: \"\"\n"), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	logYAML, bufYAML := captureLogger()
	if _, err := LoadConfigFromSources(path, logYAML); err != nil {
		t.Fatalf("LoadConfigFromSources (yaml): %v", err)
	}
	if !strings.Contains(bufYAML.String(), "empty YAML value ignored") {
		t.Errorf("expected a warning for the ignored YAML key, got: %s", bufYAML.String())
	}
}

// A burst of zero or less is not a small burst: rate.NewLimiter rejects every
// request with it, so the value has to stop the boot instead of turning the
// rate limiter into a total outage.
func TestLoadConfigFromSources_NonPositiveRateBurstYAMLRejected(t *testing.T) {
	clearJAYEnv(t)
	for _, body := range []string{"rate_burst: 0\n", "rate_burst: -1\n"} {
		path := filepath.Join(t.TempDir(), "jay.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write yaml: %v", err)
		}
		log, _ := captureLogger()
		if _, err := LoadConfigFromSources(path, log); err == nil {
			t.Errorf("%q was accepted; want a boot failure", strings.TrimSpace(body))
		}
	}
}

// An out-of-range value must not be truncated into a valid-looking one.
func TestLoadConfigFromSources_OversizedRateBurstYAMLRejected(t *testing.T) {
	clearJAYEnv(t)
	path := filepath.Join(t.TempDir(), "jay.yaml")
	if err := os.WriteFile(path, []byte("rate_burst: 4294967296\n"), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	log, _ := captureLogger()
	if _, err := LoadConfigFromSources(path, log); err == nil {
		t.Error("rate_burst: 4294967296 was accepted; want a boot failure")
	}
}

// The env door keeps the loader's policy for bad values: log and hold the
// previous value, which here is the default burst — never a burst <= 0.
func TestLoadConfigFromSources_NonPositiveRateBurstEnvKeepsDefault(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_RATE_BURST", "-1")

	log, buf := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatalf("LoadConfigFromSources: %v", err)
	}
	if cfg.RateBurst != defaultConfig().RateBurst {
		t.Errorf("RateBurst = %d, want the default %d", cfg.RateBurst, defaultConfig().RateBurst)
	}
	if !strings.Contains(buf.String(), "invalid JAY_RATE_BURST") {
		t.Errorf("expected an invalid-value error in the log, got: %s", buf.String())
	}
}
