package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestStartServerReturnsBindError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	shutdown, err := startServer(ln.Addr().String(), http.NewServeMux(), log, "test", "", "")
	if err == nil {
		if shutdown != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = shutdown(ctx)
			cancel()
		}
		t.Fatal("expected bind error")
	}
	if shutdown != nil {
		t.Fatal("shutdown function should be nil when bind fails")
	}
}

func TestStartServerBindsSynchronously(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	shutdown, err := startServer("127.0.0.1:0", http.NewServeMux(), log, "test", "", "")
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	if shutdown == nil {
		t.Fatal("missing shutdown function")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}
