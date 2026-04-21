package main

import (
	"context"
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

func main() {
	// Fail-fast on missing or weak secrets BEFORE touching disk, opening the
	// metadata DB, or binding any listener. Monorepo rule: "Ninguna variable de
	// entorno sensible tiene valor por defecto. Si falta, el servicio debe
	// fallar al arrancar."
	if v := os.Getenv("JAY_ADMIN_TOKEN"); len(v) < minSecretLen {
		log.Fatalf("JAY_ADMIN_TOKEN must be set and at least %d chars", minSecretLen)
	}
	if v := os.Getenv("JAY_SIGNING_SECRET"); len(v) < minSecretLen {
		log.Fatalf("JAY_SIGNING_SECRET must be set and at least %d chars", minSecretLen)
	}

	cfg := LoadConfig()

	// Setup structured logging
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

	// Build shared components
	au := auth.New(db)
	metrics := maintenance.NewMetrics()

	// Invalidate auth cache whenever a token is revoked/updated at the meta
	// layer so the 5-minute cache TTL can't keep a killed token alive.
	db.SetTokenInvalidateHook(au.InvalidateToken)

	// Surface fsync failures to the metrics counter so operators can alert on
	// durability loss without grepping logs.
	st.SetFsyncErrorHook(func(err error) { metrics.RecordFsyncFailure() })

	// Start background scrubber (10% sample every 6 hours, capped at 50 MiB/s
	// so integrity work can't starve production reads).
	scrubber := maintenance.NewScrubber(db, st, log, 6*time.Hour, 0.1, 50<<20)
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
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if _, err := backupMgr.Run(); err != nil {
				log.Error("backup failed", "err", err)
			}
			if _, err := backupMgr.Prune(7*24*time.Hour, 3); err != nil {
				log.Error("backup prune failed", "err", err)
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

	// Health checks
	adminMux.HandleFunc("/health", hc.ReadinessHandler)
	adminMux.HandleFunc("/health/live", hc.LivenessHandler)
	adminMux.HandleFunc("/health/ready", hc.ReadinessHandler)

	// Start servers
	shutdownS3 := startServer(cfg.ListenAddr, s3Handler, log, "s3", cfg.TLSCert, cfg.TLSKey)
	shutdownAdmin := startServer(cfg.AdminAddr, adminMux, log, "admin", cfg.TLSCert, cfg.TLSKey)

	// Start native TCP server
	var shutdownNative func() error
	if cfg.NativeAddr != "" {
		nativeServer := jayproto.NewServer(db, st, au, log, int(cfg.RateLimit), cfg.RateBurst)
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
