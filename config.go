package main

import (
	"log/slog"
	"os"
	"strconv"
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

func LoadConfig() Config {
	rateLimit := float64(100)
	if v := os.Getenv("JAY_RATE_LIMIT"); v != "" {
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			slog.Error("invalid JAY_RATE_LIMIT, using default", "value", v, "err", err)
		} else {
			rateLimit = parsed
		}
	}
	rateBurst := 200
	if v := os.Getenv("JAY_RATE_BURST"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			slog.Error("invalid JAY_RATE_BURST, using default", "value", v, "err", err)
		} else {
			rateBurst = parsed
		}
	}

	scrubInterval := 6 * time.Hour
	if v := os.Getenv("JAY_SCRUB_INTERVAL_HOURS"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed <= 0 {
			slog.Error("invalid JAY_SCRUB_INTERVAL_HOURS, using default", "value", v, "err", err)
		} else {
			scrubInterval = time.Duration(parsed) * time.Hour
		}
	}
	scrubSampleRate := 0.1
	if v := os.Getenv("JAY_SCRUB_SAMPLE_RATE"); v != "" {
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil || parsed <= 0 || parsed > 1.0 {
			slog.Error("invalid JAY_SCRUB_SAMPLE_RATE (must be in (0.0, 1.0]), using default 0.1", "value", v, "err", err)
		} else {
			scrubSampleRate = parsed
		}
	}
	scrubBytesPerSec := int64(50 << 20)
	if v := os.Getenv("JAY_SCRUB_BYTES_PER_SEC"); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			slog.Error("invalid JAY_SCRUB_BYTES_PER_SEC, using default", "value", v, "err", err)
		} else {
			scrubBytesPerSec = parsed
		}
	}
	scrubMaxPerRun := 100
	if v := os.Getenv("JAY_SCRUB_MAX_PER_RUN"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil || parsed <= 0 {
			slog.Error("invalid JAY_SCRUB_MAX_PER_RUN, using default", "value", v, "err", err)
		} else {
			scrubMaxPerRun = parsed
		}
	}

	cfg := Config{
		DataDir:           envOr("JAY_DATA_DIR", "./data"),
		ListenAddr:        envOr("JAY_LISTEN_ADDR", ":9000"),
		AdminAddr:         envOr("JAY_ADMIN_ADDR", ":9001"),
		NativeAddr:        envOr("JAY_NATIVE_ADDR", ":4444"),
		AdminToken:        os.Getenv("JAY_ADMIN_TOKEN"),
		LogLevel:          envOr("JAY_LOG_LEVEL", "info"),
		SigningSecret:     os.Getenv("JAY_SIGNING_SECRET"),
		TLSCert:           os.Getenv("JAY_TLS_CERT"),
		TLSKey:            os.Getenv("JAY_TLS_KEY"),
		RateLimit:         rateLimit,
		RateBurst:         rateBurst,
		SeedTokenAccount:  os.Getenv("JAY_SEED_TOKEN_ACCOUNT"),
		SeedTokenID:       os.Getenv("JAY_SEED_TOKEN_ID"),
		SeedTokenSecret:   os.Getenv("JAY_SEED_TOKEN_SECRET"),
		TrustProxyHeaders: parseBoolEnv("JAY_TRUST_PROXY_HEADERS"),
		ScrubInterval:     scrubInterval,
		ScrubSampleRate:   scrubSampleRate,
		ScrubBytesPerSec:  scrubBytesPerSec,
		ScrubMaxPerRun:    scrubMaxPerRun,
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
