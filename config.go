package main

import (
	"os"
	"strconv"
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
	RateLimit     float64 // requests per second per token (0 = disabled)
	RateBurst     int     // burst size
}

func LoadConfig() Config {
	rateLimit, _ := strconv.ParseFloat(envOr("JAY_RATE_LIMIT", "0"), 64)
	rateBurst, _ := strconv.Atoi(envOr("JAY_RATE_BURST", "200"))

	cfg := Config{
		DataDir:       envOr("JAY_DATA_DIR", "./data"),
		ListenAddr:    envOr("JAY_LISTEN_ADDR", ":9000"),
		AdminAddr:     envOr("JAY_ADMIN_ADDR", ":9001"),
		NativeAddr:    envOr("JAY_NATIVE_ADDR", ":4444"),
		AdminToken:    os.Getenv("JAY_ADMIN_TOKEN"),
		LogLevel:      envOr("JAY_LOG_LEVEL", "info"),
		SigningSecret: os.Getenv("JAY_SIGNING_SECRET"),
		TLSCert:       os.Getenv("JAY_TLS_CERT"),
		TLSKey:        os.Getenv("JAY_TLS_KEY"),
		RateLimit:     rateLimit,
		RateBurst:     rateBurst,
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
