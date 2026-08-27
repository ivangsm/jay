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
	"sync"
	"syscall"
	"time"

	"github.com/ivangsm/jay/admin"
	"github.com/ivangsm/jay/api"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/internal/version"
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

// Background loop cadences and the shutdown budget.
const (
	backupInterval  = 1 * time.Hour
	gcInterval      = 15 * time.Minute
	shutdownTimeout = 30 * time.Second

	// abortShutdownTimeout is the shorter budget used when a listener fails to
	// bind and the process is exiting anyway.
	abortShutdownTimeout = 5 * time.Second
)

func main() {
	cfg := mustLoadConfig()

	log := setupLogging(cfg.LogLevel)

	// version and commit come from -ldflags (see the Dockerfile). Without this
	// log line nothing imported internal/version at all, so the injection was
	// letra muerta y no había forma de saber qué binario estaba corriendo.
	log.Info("jay: starting",
		"version", version.Version,
		"commit", version.Commit,
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

	// Health checker (not ready until recovery completes). Beyond the ready
	// flag it probes bbolt and free disk space on every readiness request.
	hc := NewHealthChecker(db, cfg.DataDir, cfg.MinFreeBytes)

	au := auth.New(db)
	metrics := maintenance.NewMetrics()

	// meta cannot import maintenance — that would be a cycle — so the
	// unreadable-record counter is wired up from here. Without it, a jay.db
	// quietly degrading would only ever show up in the logs.
	db.SetDecodeFailureHook(func(bucket, key string) {
		metrics.RecordMetadataDecodeFailure()
	})

	adminMux, adminHandler := buildAdminMux(cfg, db, st, au, metrics, hc, log)
	defer func() { _ = adminHandler.Close() }()

	// The admin listener binds BEFORE recovery so probes get a 503 rather than
	// ECONNREFUSED while recovery is in flight on a large store.
	shutdownAdmin, err := startServer(cfg.AdminAddr, adminMux, log, "admin", cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		log.Error("failed to start admin server", "err", err)
		os.Exit(1)
	}

	// Run startup recovery
	if err := recovery.RunWithMetrics(db, st, log, metrics); err != nil {
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

	stopMaintenance := startMaintenance(cfg, db, st, log, metrics)
	defer stopMaintenance()

	backupDone, backupWG := startBackupLoop(db, cfg.BackupDir, log)

	shutdownS3, shutdownNative := startDataListeners(cfg, db, st, au, log, metrics, shutdownAdmin)

	// All listeners are bound — mark the service as ready
	hc.SetReady(true)

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	shutdownAll(log, shutdownAdmin, shutdownS3, shutdownNative, backupDone, backupWG)
}

// mustLoadConfig reads the configuration and refuses to continue if anything about
// it is unsafe.
//
// Every check here is fail-fast on purpose: a jay that boots with a weak admin
// token, or with two of the three seed-token fields set, is worse than one that
// does not boot — the first looks healthy while handing out credentials that do
// not work.
func mustLoadConfig() Config {
	// An empty --config-file preserves the legacy env-only path. JAY_CONFIG_FILE
	// is honoured as a fallback so container runtimes that only inject env vars
	// can still point jay at a mounted YAML file; the flag wins over the env var.
	var configFile string
	flag.StringVar(&configFile, "config-file", "", "Path to YAML config file (optional)")
	flag.Parse()
	if configFile == "" {
		configFile = os.Getenv("JAY_CONFIG_FILE")
	}

	// Bootstrap logger: LoadConfigFromSources emits slog.Warn on YAML/env
	// conflicts, so it needs a real logger before cfg.LogLevel is even known.
	bootstrapLog := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := LoadConfigFromSources(configFile, bootstrapLog)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Secrets are checked AFTER the load so YAML-provided ones are honoured.
	// Monorepo rule: no sensitive environment variable has a default; if one is
	// missing, the service must fail to start.
	if len(cfg.AdminToken) < minSecretLen {
		log.Fatalf("JAY_ADMIN_TOKEN (or admin_token in YAML) must be set and at least %d chars", minSecretLen)
	}
	if len(cfg.SigningSecret) < minSecretLen {
		log.Fatalf("JAY_SIGNING_SECRET (or signing_secret in YAML) must be set and at least %d chars", minSecretLen)
	}

	// All three seed fields or none. A partial configuration is operator error:
	// it would seed nothing while looking like it seeded something.
	seedSet := 0
	for _, field := range []string{cfg.SeedTokenAccount, cfg.SeedTokenID, cfg.SeedTokenSecret} {
		if field != "" {
			seedSet++
		}
	}
	if seedSet != 0 && seedSet != 3 {
		log.Fatalf("seed token config must have all three fields (account, id, secret) or none")
	}

	return cfg
}

// setupLogging builds the process logger, replacing the bootstrap one for the
// rest of the process lifetime. An unrecognised level falls back to info rather
// than aborting: running without logs is worse than running at the wrong level.
func setupLogging(logLevel string) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

// startBackupLoop runs hourly bbolt snapshots and prunes the old ones.
//
// Returns the stop channel and its WaitGroup: closing the channel only signals
// the goroutine, and the caller has to wait for it to actually exit — an
// in-flight Run() would otherwise race the deferred bbolt.Close.
func startBackupLoop(db *meta.DB, backupDir string, log *slog.Logger) (chan struct{}, *sync.WaitGroup) {
	backupMgr := maintenance.NewBackupManager(db, backupDir, log)
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Go(func() {
		ticker := time.NewTicker(backupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
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
	})
	return done, &wg
}

// shutdownAll tears the process down in order.
//
// The backup loop stops first, before the deferred db.Close: a snapshot in
// flight when bbolt closes underneath it is a corrupt backup, which is worse
// than no backup because it satisfies retention silently.
func shutdownAll(
	log *slog.Logger,
	shutdownAdmin, shutdownS3 func(context.Context) error,
	shutdownNative func() error,
	backupDone chan struct{},
	backupWG *sync.WaitGroup,
) {
	log.Info("jay: shutting down")

	close(backupDone)
	backupWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := shutdownS3(ctx); err != nil {
		log.Error("s3 server shutdown error", "err", err)
	}
	if err := shutdownAdmin(ctx); err != nil {
		log.Error("admin server shutdown error", "err", err)
	}

	// The native server's shutdown takes no context, so it gets its own timeout
	// rather than being able to hang the process forever.
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
		case <-time.After(shutdownTimeout):
			log.Warn("native server shutdown timed out")
		}
	}

	log.Info("jay: stopped")
}

// buildAdminMux assembles the admin API, its health probes and pprof, all on the
// admin port.
//
// Health lives here rather than on the S3 port on purpose: the readiness probe
// reports internal state — bbolt responsiveness and free disk — and that is not
// something to expose on a listener meant for object traffic.
func buildAdminMux(
	cfg Config, db *meta.DB, st *store.Store, au *auth.Auth,
	metrics *maintenance.Metrics, hc *HealthChecker, log *slog.Logger,
) (*http.ServeMux, *admin.Handler) {
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

	mux := http.NewServeMux()
	mux.Handle("/_jay/", adminHandler)
	mountPprof(mux, adminHandler.RequireAdmin)
	mux.HandleFunc("/health", hc.ReadinessHandler)
	mux.HandleFunc("/health/live", hc.LivenessHandler)
	mux.HandleFunc("/health/ready", hc.ReadinessHandler)

	return mux, adminHandler
}

// startMaintenance starts the background jobs that keep the store honest:
// integrity scrubbing and garbage collection.
//
// Returns the function that stops them, which the caller must defer.
func startMaintenance(
	cfg Config, db *meta.DB, st *store.Store, log *slog.Logger, metrics *maintenance.Metrics,
) func() {
	scrubber := maintenance.NewScrubber(db, st, log, cfg.ScrubInterval, cfg.ScrubBytesPerSec, cfg.ScrubMaxPerRun)
	// Must be set before Start: the scrub goroutines read the field without
	// synchronisation.
	scrubber.SetMetrics(metrics)
	scrubber.Start()

	// The GC also reclaims expired multipart uploads — both the bbolt record and
	// the parts on disk. Deletion notifications wake it immediately instead of
	// leaving freed bytes until the next tick.
	gc := maintenance.NewGC(cfg.DataDir, db, st, log, gcInterval)
	db.SetDeletionHook(gc.NotifyDeletion)
	gc.Start()

	return func() {
		gc.Stop()
		scrubber.Stop()
	}
}

// startDataListeners binds the two surfaces that serve object traffic: the
// S3-compatible HTTP API and the native TCP protocol.
//
// The native listener is optional — an empty JAY_NATIVE_ADDR disables it — and
// its shutdown function comes back nil in that case.
//
// If either fails to bind, the admin listener that is already up is torn down
// before exiting: leaving it accepting probes for a process that is about to die
// would report a service that does not exist.
func startDataListeners(
	cfg Config, db *meta.DB, st *store.Store, au *auth.Auth,
	log *slog.Logger, metrics *maintenance.Metrics,
	shutdownAdmin func(context.Context) error,
) (shutdownS3 func(context.Context) error, shutdownNative func() error) {
	var rlCfg *api.RateLimiterConfig
	if cfg.RateLimit > 0 {
		rlCfg = &api.RateLimiterConfig{Rate: cfg.RateLimit, Burst: cfg.RateBurst}
	}

	s3Handler := api.NewHandler(db, st, au, log, metrics, cfg.SigningSecret, rlCfg)
	s3Handler.SetTrustProxyHeaders(cfg.TrustProxyHeaders)
	s3Handler.SetMaxObjectSize(cfg.MaxObjectSize)

	shutdownS3, err := startServer(cfg.ListenAddr, s3Handler, log, "s3", cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		log.Error("failed to start s3 server", "err", err)
		abortStartup(shutdownAdmin)
	}

	if cfg.NativeAddr == "" {
		return shutdownS3, nil
	}

	nativeServer := jayproto.NewServer(db, st, au, log, metrics, int(cfg.RateLimit), cfg.RateBurst)
	nativeServer.SetMaxObjectSize(cfg.MaxObjectSize)
	shutdownNative, err = nativeServer.ListenAndServe(cfg.NativeAddr)
	if err != nil {
		log.Error("failed to start native server", "err", err)
		abortStartup(shutdownAdmin, func(ctx context.Context) error { return shutdownS3(ctx) })
	}

	return shutdownS3, shutdownNative
}

// abortStartup closes whatever listeners are already up and exits. Used when a
// later listener fails to bind: a half-started jay must not stay half-up.
func abortStartup(shutdowns ...func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), abortShutdownTimeout)
	for _, shutdown := range shutdowns {
		_ = shutdown(ctx)
	}
	cancel()
	os.Exit(1)
}
