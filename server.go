package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// startServer starts an HTTP server and returns a shutdown function.
func startServer(addr string, handler http.Handler, log *slog.Logger, name string) (shutdown func(context.Context) error) {
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  2 * time.Minute,
	}

	go func() {
		log.Info("server listening", "name", name, "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server error", "name", name, "err", err)
		}
	}()

	return srv.Shutdown
}
