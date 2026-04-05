package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// startServer starts an HTTP server and returns a shutdown function.
// If certFile and keyFile are non-empty, it starts with TLS.
func startServer(addr string, handler http.Handler, log *slog.Logger, name, certFile, keyFile string) (shutdown func(context.Context) error) {
	srv := &http.Server{
		Addr:           addr,
		Handler:        handler,
		ReadTimeout:    5 * time.Minute,
		WriteTimeout:   5 * time.Minute,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	go func() {
		var err error
		if certFile != "" && keyFile != "" {
			log.Info("server listening (TLS)", "name", name, "addr", addr)
			err = srv.ListenAndServeTLS(certFile, keyFile)
		} else {
			log.Info("server listening", "name", name, "addr", addr)
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Error("server error", "name", name, "err", err)
		}
	}()

	return srv.Shutdown
}
