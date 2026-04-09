package main

import (
	"log/slog"
	"os"
	"strconv"
)

type Config struct {
	DataDir          string
	ListenAddr       string
	AdminAddr        string
	NativeAddr       string
	AdminToken       string
	LogLevel         string
	SigningSecret    string
	TLSCert          string
	TLSKey           string
	RateLimit        float64 // requests per second per token (0 = disabled)
	RateBurst        int     // burst size
	SeedTokenAccount string  // JAY_SEED_TOKEN_ACCOUNT
	SeedTokenID      string  // JAY_SEED_TOKEN_ID
	SeedTokenSecret  string  // JAY_SEED_TOKEN_SECRET
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

	if adminToken := os.Getenv("JAY_ADMIN_TOKEN"); adminToken != "" && len(adminToken) < 16 {
		slog.Warn("JAY_ADMIN_TOKEN is too short, minimum 16 characters recommended")
	}
	if signingSecret := os.Getenv("JAY_SIGNING_SECRET"); signingSecret != "" && len(signingSecret) < 32 {
		slog.Warn("JAY_SIGNING_SECRET is too short, minimum 32 characters recommended")
	}

	cfg := Config{
		DataDir:          envOr("JAY_DATA_DIR", "./data"),
		ListenAddr:       envOr("JAY_LISTEN_ADDR", ":9000"),
		AdminAddr:        envOr("JAY_ADMIN_ADDR", ":9001"),
		NativeAddr:       envOr("JAY_NATIVE_ADDR", ":4444"),
		AdminToken:       os.Getenv("JAY_ADMIN_TOKEN"),
		LogLevel:         envOr("JAY_LOG_LEVEL", "info"),
		SigningSecret:    os.Getenv("JAY_SIGNING_SECRET"),
		TLSCert:          os.Getenv("JAY_TLS_CERT"),
		TLSKey:           os.Getenv("JAY_TLS_KEY"),
		RateLimit:        rateLimit,
		RateBurst:        rateBurst,
		SeedTokenAccount: os.Getenv("JAY_SEED_TOKEN_ACCOUNT"),
		SeedTokenID:      os.Getenv("JAY_SEED_TOKEN_ID"),
		SeedTokenSecret:  os.Getenv("JAY_SEED_TOKEN_SECRET"),
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
