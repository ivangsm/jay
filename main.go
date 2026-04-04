package main

import (
	"context"
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

func main() {
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
	defer db.Close()

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
	hc.SetReady(true)

	// Build shared components
	au := auth.New(db)
	metrics := maintenance.NewMetrics()

	// Start background scrubber (10% sample every 6 hours)
	scrubber := maintenance.NewScrubber(db, st, log, 6*time.Hour, 0.1)
	scrubber.Start()
	defer scrubber.Stop()

	// Start background GC (every 15 minutes)
	gc := maintenance.NewGC(cfg.DataDir, log, 15*time.Minute)
	gc.Start()
	defer gc.Stop()

	// Start background backup (every 1 hour, keep 24, prune after 7 days)
	backupMgr := maintenance.NewBackupManager(dbPath, filepath.Join(cfg.DataDir, "backups"), log)
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if _, err := backupMgr.Run(); err != nil {
					log.Error("backup failed", "err", err)
				}
				backupMgr.Prune(7*24*time.Hour, 3)
			}
		}
	}()

	// S3 API handler
	s3Handler := api.NewHandler(db, st, au, log, metrics, cfg.SigningSecret)

	// Admin API handler (on separate port)
	adminMux := http.NewServeMux()
	adminHandler := admin.NewHandler(db, cfg.AdminToken, log, metrics, st, cfg.SigningSecret, cfg.ListenAddr)
	adminMux.Handle("/_jay/", adminHandler)

	// Health checks
	adminMux.HandleFunc("/health", hc.ReadinessHandler)
	adminMux.HandleFunc("/health/live", hc.LivenessHandler)
	adminMux.HandleFunc("/health/ready", hc.ReadinessHandler)

	// Start servers
	shutdownS3 := startServer(cfg.ListenAddr, s3Handler, log, "s3")
	shutdownAdmin := startServer(cfg.AdminAddr, adminMux, log, "admin")

	// Start native TCP server
	var shutdownNative func() error
	if cfg.NativeAddr != "" {
		nativeServer := jayproto.NewServer(db, st, au, log)
		var err error
		shutdownNative, err = nativeServer.ListenAndServe(cfg.NativeAddr)
		if err != nil {
			log.Error("failed to start native server", "err", err)
			os.Exit(1)
		}
	}

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
		if err := shutdownNative(); err != nil {
			log.Error("native server shutdown error", "err", err)
		}
	}

	log.Info("jay: stopped")
}
