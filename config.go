package main

import (
	"os"
)

type Config struct {
	DataDir       string
	ListenAddr    string
	AdminAddr     string
	NativeAddr    string
	AdminToken    string
	LogLevel      string
	SigningSecret string
}

func LoadConfig() Config {
	cfg := Config{
		DataDir:    envOr("JAY_DATA_DIR", "./data"),
		ListenAddr: envOr("JAY_LISTEN_ADDR", ":9000"),
		AdminAddr:  envOr("JAY_ADMIN_ADDR", ":9001"),
		NativeAddr: envOr("JAY_NATIVE_ADDR", ":4444"),
		AdminToken:    os.Getenv("JAY_ADMIN_TOKEN"),
		LogLevel:      envOr("JAY_LOG_LEVEL", "info"),
		SigningSecret: os.Getenv("JAY_SIGNING_SECRET"),
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
