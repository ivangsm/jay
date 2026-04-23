package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ivangsm/jay/admin"
	"github.com/ivangsm/jay/api"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	jayproto "github.com/ivangsm/jay/proto"
	"github.com/ivangsm/jay/recovery"
	"github.com/ivangsm/jay/store"
)

// minSecretLen is the minimum acceptable length (in bytes) for sensitive env
// secrets. 32 chars of high-entropy input (e.g. `openssl rand -base64 32`)
// leaves comfortable margin against online brute force even if the hash ever
// leaks. The monorepo policy forbids defaults for secrets, so anything shorter
// than this is treated as operator error and the process refuses to boot.
const minSecretLen = 32

// Backup retention policy: keep 24 backups, prune those older than 7 days.
const backupRetentionDays = 7
const backupPruneMinCount = 3

func main() {
	// Parse --config-file flag. An empty value preserves the legacy env-only
	// path. The JAY_CONFIG_FILE env var is honored as a fallback so
	// container runtimes that only inject env vars can still point jay at a
	// mounted YAML file.
	var configFile string
	flag.StringVar(&configFile, "config-file", "", "Path to YAML config file (optional)")
	flag.Parse()
	if configFile == "" {
		configFile = os.Getenv("JAY_CONFIG_FILE")
	}

	// Bootstrap logger: info-level JSON to stdout. Needed because
	// LoadConfigFromSources emits slog.Warn on YAML/env conflicts, so we
	// have to hand it a real logger before we know cfg.LogLevel.
	bootstrapLog := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := LoadConfigFromSources(configFile, bootstrapLog)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Fail-fast on missing or weak secrets AFTER config load so YAML-provided
	// secrets are honored. Monorepo rule: "Ninguna variable de entorno
	// sensible tiene valor por defecto. Si falta, el servicio debe fallar al
	// arrancar."
	if len(cfg.AdminToken) < minSecretLen {
		log.Fatalf("JAY_ADMIN_TOKEN (or admin_token in YAML) must be set and at least %d chars", minSecretLen)
	}
	if len(cfg.SigningSecret) < minSecretLen {
		log.Fatalf("JAY_SIGNING_SECRET (or signing_secret in YAML) must be set and at least %d chars", minSecretLen)
	}

	// Validate seed token config: all three fields or none. Partial
	// configuration is operator error and must not boot.
	seedSet := 0
	if cfg.SeedTokenAccount != "" {
		seedSet++
	}
	if cfg.SeedTokenID != "" {
		seedSet++
	}
	if cfg.SeedTokenSecret != "" {
		seedSet++
	}
	if seedSet != 0 && seedSet != 3 {
		log.Fatalf("seed token config must have all three fields (account, id, secret) or none")
	}

	// Setup structured logging at the configured level. Replaces the
	// bootstrap logger for the rest of the process lifetime.
	level := slog.LevelInfo
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	log.Info("jay: starting",
		"data_dir", cfg.DataDir,
		"listen", cfg.ListenAddr,
		"admin", cfg.AdminAddr,
		"native", cfg.NativeAddr,
	)

	// Open metadata database
	dbPath := filepath.Join(cfg.DataDir, "meta", "jay.db")
	db, err := meta.Open(dbPath)
	if err != nil {
		log.Error("failed to open metadata db", "err", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	// JAY_SIGNING_SECRET is guaranteed non-empty and >= minSecretLen by the
	// fail-fast at the top of main().
	db.SetSigningSecret(cfg.SigningSecret)
	migrated, err := db.MigrateTokenSecrets()
	if err != nil {
		log.Error("failed to migrate token secrets", "err", err)
		os.Exit(1)
	}
	if migrated > 0 {
		log.Info("migrated token secrets to encrypted format", "count", migrated)
	}

	// Initialize object store
	st, err := store.New(cfg.DataDir)
	if err != nil {
		log.Error("failed to initialize store", "err", err)
		os.Exit(1)
	}

	// Health checker (not ready until recovery completes)
	hc := NewHealthChecker(db)

	au := auth.New(db)
	metrics := maintenance.NewMetrics()

	// Admin API handler (on separate port)
	adminMux := http.NewServeMux()
	tlsEnabled := cfg.TLSCert != "" && cfg.TLSKey != ""
	adminHandler := admin.NewHandler(admin.AdminConfig{
		DB:            db,
		Store:         st,
		Auth:          au,
		AdminToken:    cfg.AdminToken,
		Log:           log,
		Metrics:       metrics,
		SigningSecret: cfg.SigningSecret,
		ListenAddr:    cfg.ListenAddr,
		TLSEnabled:    tlsEnabled,
	})
	defer func() { _ = adminHandler.Close() }()
	adminMux.Handle("/_jay/", adminHandler)

	adminMux.HandleFunc("/health", hc.ReadinessHandler)
	adminMux.HandleFunc("/health/live", hc.LivenessHandler)
	adminMux.HandleFunc("/health/ready", hc.ReadinessHandler)

	// Bind admin listener BEFORE recovery so probes get 503 (not
	// ECONNREFUSED) while recovery is in flight on a large store.
	shutdownAdmin := startServer(cfg.AdminAddr, adminMux, log, "admin", cfg.TLSCert, cfg.TLSKey)

	// Run startup recovery
	if err := recovery.Run(db, st, log); err != nil {
		log.Error("recovery failed", "err", err)
		os.Exit(1)
	}

	// Seed token from env vars (idempotent)
	if err := runSeed(cfg, db, log); err != nil {
		log.Error("seed failed", "err", err)
		os.Exit(1)
	}

	// Invalidate auth cache whenever a token is revoked/updated at the meta
	// layer so the 5-minute cache TTL can't keep a killed token alive.
	db.SetTokenInvalidateHook(au.InvalidateToken)

	// Surface fsync failures to the metrics counter so operators can alert on
	// durability loss without grepping logs.
	st.SetFsyncErrorHook(func(err error) { metrics.RecordFsyncFailure() })

	scrubber := maintenance.NewScrubber(db, st, log, cfg.ScrubInterval, cfg.ScrubSampleRate, cfg.ScrubBytesPerSec, cfg.ScrubMaxPerRun)
	scrubber.Start()
	defer scrubber.Stop()

	// Start background GC (every 15 minutes). Wire deletion notifications so
	// GC wakes immediately on delete instead of waiting for the next tick.
	gc := maintenance.NewGC(cfg.DataDir, log, 15*time.Minute)
	db.SetDeletionHook(gc.NotifyDeletion)
	gc.Start()
	defer gc.Stop()

	// Start background backup (every 1 hour, keep 24, prune after 7 days)
	backupMgr := maintenance.NewBackupManager(db, filepath.Join(cfg.DataDir, "backups"), log)
	backupDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-backupDone:
				return
			case <-ticker.C:
				if _, err := backupMgr.Run(); err != nil {
					log.Error("backup failed", "err", err)
				}
				if _, err := backupMgr.Prune(backupRetentionDays*24*time.Hour, backupPruneMinCount); err != nil {
					log.Error("backup prune failed", "err", err)
				}
			}
		}
	}()

	// S3 API handler
	var rlCfg *api.RateLimiterConfig
	if cfg.RateLimit > 0 {
		rlCfg = &api.RateLimiterConfig{Rate: cfg.RateLimit, Burst: cfg.RateBurst}
	}
	s3Handler := api.NewHandler(db, st, au, log, metrics, cfg.SigningSecret, rlCfg)
	s3Handler.SetTrustProxyHeaders(cfg.TrustProxyHeaders)

	shutdownS3 := startServer(cfg.ListenAddr, s3Handler, log, "s3", cfg.TLSCert, cfg.TLSKey)

	// Start native TCP server
	var shutdownNative func() error
	if cfg.NativeAddr != "" {
		nativeServer := jayproto.NewServer(db, st, au, log, metrics, int(cfg.RateLimit), cfg.RateBurst)
		var err error
		shutdownNative, err = nativeServer.ListenAndServe(cfg.NativeAddr)
		if err != nil {
			log.Error("failed to start native server", "err", err)
			os.Exit(1)
		}
	}

	// All listeners are bound — mark the service as ready
	hc.SetReady(true)

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Info("jay: shutting down")

	// Stop backup loop before the deferred db.Close so no Run() is in
	// flight when bbolt.Close fires.
	close(backupDone)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := shutdownS3(ctx); err != nil {
		log.Error("s3 server shutdown error", "err", err)
	}
	if err := shutdownAdmin(ctx); err != nil {
		log.Error("admin server shutdown error", "err", err)
	}
	if shutdownNative != nil {
		done := make(chan struct{})
		go func() {
			if err := shutdownNative(); err != nil {
				log.Error("native server shutdown error", "err", err)
			}
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			log.Warn("native server shutdown timed out")
		}
	}

	log.Info("jay: stopped")
}
