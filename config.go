package main

import (
	"io"
	"log/slog"
	"time"
)

type Config struct {
	DataDir           string
	ListenAddr        string
	AdminAddr         string
	NativeAddr        string
	AdminToken        string
	LogLevel          string
	SigningSecret     string
	TLSCert           string
	TLSKey            string
	RateLimit         float64 // requests per second per token (0 = disabled)
	RateBurst         int     // burst size
	SeedTokenAccount  string  // JAY_SEED_TOKEN_ACCOUNT
	SeedTokenID       string  // JAY_SEED_TOKEN_ID
	SeedTokenSecret   string  // JAY_SEED_TOKEN_SECRET
	TrustProxyHeaders bool    // JAY_TRUST_PROXY_HEADERS — if true, trust X-Forwarded-For / X-Real-IP
	ScrubInterval     time.Duration
	ScrubBytesPerSec  int64
	ScrubMaxPerRun    int
	BackupDir         string // JAY_BACKUP_DIR / backup.dir — where hourly bbolt snapshots land; defaults to <DataDir>/backups, point it at a separate volume for real DR
	MinFreeBytes      int64  // JAY_MIN_FREE_BYTES / min_free_bytes — readiness fails when the DataDir filesystem has less free space; 0 disables the check
	MaxObjectSize     int64  // JAY_MAX_OBJECT_SIZE / max_object_size — largest accepted object body (and multipart part), in bytes; 0 disables the limit

	// Client credentials for the `jay` subcommands (ls, cp, rm, sync). The
	// server itself never reads them; they live here so they go through
	// bindings() like every other setting and stay visible to jay-config.
	ClientTokenID     string // JAY_TOKEN_ID / client.token_id
	ClientTokenSecret string // JAY_TOKEN_SECRET / client.token_secret
}

// LoadConfig keeps the legacy env-only contract. It delegates to
// LoadConfigFromSources with an empty YAML path so the precedence rules
// (env > YAML > defaults) collapse to the pre-existing "env > defaults"
// behaviour.
//
// New callers should prefer LoadConfigFromSources directly so they can pass
// a --config-file value.
func LoadConfig() Config {
	// The env-only path never surfaces YAML conflicts, so the logger only
	// ever receives parse-error messages. Route them to a discard handler
	// to preserve the original LoadConfig signature (no logger parameter,
	// no error return) without losing the slog.Error calls the legacy
	// implementation emitted for invalid env values.
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
