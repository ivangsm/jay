package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

// nativeTLSConfig builds the TLS config for the native listener, or nil when
// the transport is meant to stay in the clear.
//
// Supplying one half of the pair is an error, never a fallback to plaintext.
// The native handshake sends "token_id:secret" unencrypted, so an operator who
// typed only JAY_NATIVE_TLS_CERT and got a working-looking server would be
// publishing the credential of every client that connects. This is the config
// case where degrading quietly is worse than not starting.
func nativeTLSConfig(cfg Config) (*tls.Config, error) {
	switch {
	case cfg.NativeTLSCert == "" && cfg.NativeTLSKey == "":
		return nil, nil
	case cfg.NativeTLSCert == "":
		return nil, errors.New("native_tls_key is set without native_tls_cert")
	case cfg.NativeTLSKey == "":
		return nil, errors.New("native_tls_cert is set without native_tls_key")
	}

	cert, err := tls.LoadX509KeyPair(cfg.NativeTLSCert, cfg.NativeTLSKey)
	if err != nil {
		return nil, fmt.Errorf("load native TLS key pair: %w", err)
	}
	// Loaded here rather than through the listener so a bad path or an
	// unreadable key fails at startup, not on the first client to connect.
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// startServer starts an HTTP server and returns a shutdown function.
// If certFile and keyFile are non-empty, it starts with TLS.
func startServer(addr string, handler http.Handler, log *slog.Logger, name, certFile, keyFile string) (shutdown func(context.Context) error, err error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
		// ReadTimeout covers headers plus body, and a 5 GiB PUT needs those
		// five minutes. ReadHeaderTimeout bounds the header phase separately:
		// without it, a slowloris dribbling one header byte at a time held the
		// connection for the full five minutes.
		ReadHeaderTimeout: 20 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20, // 1 MB
		// Being S3-compatible, jay parses arbitrary client headers
		// (`x-amz-meta-*`) and SignedHeaders lists. A byte cap alone does not
		// stop a client from sending tens of thousands of tiny headers, each
		// with its own map entry. 500 is the stdlib default and is plenty for
		// any real S3 client.
		MaxHeaderValueCount: http.DefaultMaxHeaderValueCount,
		// Everything net/http reports on its own — the stack of a panic it
		// recovered outside jay's middleware, a rejected TLS handshake, a write
		// that failed after the headers went out — goes through a *log.Logger.
		// Left unset that is the package-level default: plain text on stderr, in
		// the middle of a stream that is JSON everywhere else, which a collector
		// that parses JSON drops. This routes it through the same slog handler
		// as every other line, so nothing the process emits leaves the format.
		//
		// It covers the admin listener too (health probes, the admin API,
		// pprof), which has no middleware chain of its own.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelError),
	}

	go func() {
		var err error
		if certFile != "" && keyFile != "" {
			log.Info("server listening (TLS)", "name", name, "addr", addr)
			err = srv.ServeTLS(ln, certFile, keyFile)
		} else {
			log.Info("server listening", "name", name, "addr", addr)
			err = srv.Serve(ln)
		}
		if err != nil && err != http.ErrServerClosed {
			log.Error("server error", "name", name, "err", err)
		}
	}()

	return srv.Shutdown, nil
}

// mountPprof hangs net/http/pprof off mux under /debug/pprof/, wrapped in
// guard. In jay the mux is the admin listener's (:4011) and the guard is
// JAY_ADMIN_TOKEN authentication: profiles leak function names and the process's
// memory layout, and /debug/pprof/profile burns CPU on demand, so they are never
// served unauthenticated.
//
// Note: net/http/pprof's init() registers the same handlers on
// http.DefaultServeMux, unauthenticated, merely by being imported — there is no
// way to prevent that. It is harmless as long as jay NEVER serves the
// DefaultServeMux, and today it does not: startServer always receives an
// explicit mux. If anyone ever passes nil or http.DefaultServeMux to
// startServer, pprof is open to the internet. Registering the handlers by hand
// here is what keeps the authenticated copy the only reachable one.
//
// The profile that justifies all of this is /debug/pprof/goroutineleak, new in
// Go 1.27: it lists goroutines that are stuck forever. Two known candidates in
// jay — health.go's readiness probe leaves one goroutine per check for as long
// as bbolt does not answer, and main.go's shutdown watchdog abandons its own
// whenever the time.After wins.
func mountPprof(mux *http.ServeMux, guard func(http.Handler) http.Handler) {
	pprofMux := http.NewServeMux()
	pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
	pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.Handle("/debug/pprof/", guard(pprofMux))
}
