package main

import (
	"io"
	"log/slog"
	"os"
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
	ScrubSampleRate   float64
	ScrubBytesPerSec  int64
	ScrubMaxPerRun    int
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

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// parseBoolEnv returns true only for "1" or "true" (case-insensitive). Anything
// else — including empty — is false. Defaults to false for safety.
func parseBoolEnv(key string) bool {
	v := os.Getenv(key)
	if v == "" {
		return false
	}
	switch v {
	case "1", "true", "TRUE", "True":
		return true
	}
	return false
}
