package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

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
		// ReadTimeout cubre headers + body, y un PUT de 5 GiB necesita esos 5
		// minutes. ReadHeaderTimeout bounds the header phase separately:
		// without it, a slowloris dribbling one header byte at a time held the
		// connection for the full five minutes.
		ReadHeaderTimeout: 20 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20, // 1 MB
		// Being S3-compatible, jay parses arbitrary client headers
		// (`x-amz-meta-*`) and SignedHeaders lists. A byte cap alone
		// solo no impide mandar decenas de miles de cabeceras diminutas, cada
		// each with its own map entry. 500 is the stdlib default and is plenty
		// for any real S3 client.
		MaxHeaderValueCount: http.DefaultMaxHeaderValueCount,
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

// mountPprof cuelga net/http/pprof de mux bajo /debug/pprof/, envuelto en
// guard. In jay the mux is the admin listener's (:4011) and the guard is
// JAY_ADMIN_TOKEN authentication: profiles leak function names and the process's
// memory layout, and /debug/pprof/profile burns CPU on demand, so they are never
// served unauthenticated.
//
// Note: net/http/pprof's init() registers the same handlers on
// http.DefaultServeMux, unauthenticated, merely by being imported — there is no
// way to prevent that. It is harmless as long as jay NEVER serves the
// DefaultServeMux, and today it does not: startServer always receives an
// explicit mux
// explícito. Si algún día alguien pasa nil o http.DefaultServeMux a
// startServer, pprof queda abierto a internet. Registrarlos a mano acá es lo
// which keeps the authenticated copy the only reachable one.
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
