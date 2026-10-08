package main

import (
	"io"
	"log/slog"
	"time"
)

type Config struct {
	DataDir       string
	ListenAddr    string
	AdminAddr     string
	NativeAddr    string
	AdminToken    string
	LogLevel      string
	SigningSecret string
	TLSCert       string
	TLSKey        string

	// Native protocol TLS. Not defaulted to TLSCert/TLSKey: inheriting the S3
	// certificate would switch the native transport as a side effect of an
	// unrelated setting and break every client speaking to it in the clear.
	// Both or neither: one without the other aborts startup.
	NativeTLSCert     string  // JAY_NATIVE_TLS_CERT / native_tls_cert
	NativeTLSKey      string  // JAY_NATIVE_TLS_KEY / native_tls_key
	RateLimit         float64 // requests per second per token (0 = disabled)
	RateBurst         int     // burst size
	SeedTokenAccount  string  // JAY_SEED_TOKEN_ACCOUNT
	SeedTokenID       string  // JAY_SEED_TOKEN_ID
	SeedTokenSecret   string  // JAY_SEED_TOKEN_SECRET
	TrustProxyHeaders bool    // JAY_TRUST_PROXY_HEADERS — if true, trust X-Forwarded-For / X-Real-IP
	ScrubInterval     time.Duration
	ScrubBytesPerSec  int64
	ScrubMaxPerRun    int
	// MetadataBackupDir is where the hourly bbolt snapshots land
	// (JAY_METADATA_BACKUP_DIR / metadata_backup.dir; the deprecated
	// JAY_BACKUP_DIR / backup.dir still works and warns). It defaults to
	// <DataDir>/backups, which is the same disk — point it at a separate volume
	// for real DR. Only metadata goes there: jay never copies object bytes.
	MetadataBackupDir string
	MinFreeBytes      int64 // JAY_MIN_FREE_BYTES / min_free_bytes — readiness fails when the DataDir filesystem has less free space; 0 disables the check

	// Who may scrape GET /metrics on the admin listener. With neither set, it
	// takes JAY_ADMIN_TOKEN like every other admin route.
	MetricsToken  string // JAY_METRICS_TOKEN / metrics.token — read-only bearer for /metrics only; a secret: >= 32 bytes, never equal to AdminToken
	MetricsPublic bool   // JAY_METRICS_PUBLIC / metrics.public — serve /metrics with no auth at all; explicit opt-in, excludes MetricsToken
	MaxObjectSize int64  // JAY_MAX_OBJECT_SIZE / max_object_size — largest accepted object body (and multipart part), in bytes; 0 disables the limit

	// ConsoleEnabled serves the web console under /console/ on the admin
	// listener. Off by default: an unset or empty value is false, and /console/**
	// answers 404 saying how to turn it on. It adds no secret; it signs in with
	// JAY_ADMIN_TOKEN.
	ConsoleEnabled bool // JAY_CONSOLE_ENABLED / console.enabled

	// Client credentials for the `jay` subcommands (ls, cp, rm, sync). The
	// server itself never reads them; they live here so they go through
	// bindings() like every other setting and stay visible to jay-config.
	ClientTokenID     string // JAY_TOKEN_ID / client.token_id
	ClientTokenSecret string // JAY_TOKEN_SECRET / client.token_secret

	// Native back-pressure limits. The S3 API has neither.
	NativeMaxConns         int   // JAY_NATIVE_MAX_CONNS / native_max_conns — connections held at once; the next one is refused with ServerBusy
	NativeTokenBytesPerSec int64 // JAY_NATIVE_TOKEN_BYTES_PER_SEC / native_token_bytes_per_sec — body bytes per second per token, both directions; 0 = no cap
}

// LoadConfig is the env-only form of LoadConfigFromSources: no YAML, so the
// precedence collapses to env > defaults. Prefer LoadConfigFromSources, which
// takes a --config-file value and a logger.
func LoadConfig() Config {
	// The signature has no logger, so the loader's own lines (invalid env
	// values) are discarded; only the impossible-error guard below logs.
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		// Impossible when yamlPath == "" — but guard anyway so a future
		// change doesn't silently lose the error.
		slog.Error("LoadConfig: unexpected error from LoadConfigFromSources", "err", err)
		return defaultConfig()
	}
	return cfg
}
