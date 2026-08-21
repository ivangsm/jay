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
		// minutos. ReadHeaderTimeout acota aparte la fase de headers: sin él,
		// un slowloris que manda un byte de header cada tanto retenía la
		// conexión los 5 minutos completos.
		ReadHeaderTimeout: 20 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20, // 1 MB
		// Siendo S3-compatible, jay parsea cabeceras arbitrarias del cliente
		// (`x-amz-meta-*`) y listas de `SignedHeaders`. El tope de bytes por sí
		// solo no impide mandar decenas de miles de cabeceras diminutas, cada
		// una con su entrada en el mapa. 500 es el default del stdlib y sobra
		// para cualquier cliente S3 real.
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
// guard. En jay el mux es el del listener admin (:4011) y el guard es la
// autenticación por JAY_ADMIN_TOKEN: los perfiles filtran nombres de funciones
// y layout de memoria del proceso, y /debug/pprof/profile además quema CPU a
// pedido, así que nunca van sin autenticar.
//
// Ojo: el `init()` de net/http/pprof registra los mismos handlers en el
// http.DefaultServeMux, sin autenticación, con solo importar el paquete — no
// hay forma de evitarlo. Eso es inofensivo mientras jay NUNCA sirva el
// DefaultServeMux, y hoy no lo hace: startServer siempre recibe un mux
// explícito. Si algún día alguien pasa nil o http.DefaultServeMux a
// startServer, pprof queda abierto a internet. Registrarlos a mano acá es lo
// que mantiene la copia autenticada bajo nuestro control.
//
// El perfil que motiva todo esto es /debug/pprof/goroutineleak, nuevo en Go
// 1.27: lista las goroutines que quedaron colgadas para siempre. Dos objetivos
// conocidos en jay — el probe de readiness de health.go deja una goroutine por
// chequeo mientras bbolt no conteste, y el watchdog de apagado de main.go
// abandona la suya cuando gana el time.After.
func mountPprof(mux *http.ServeMux, guard func(http.Handler) http.Handler) {
	pprofMux := http.NewServeMux()
	pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
	pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.Handle("/debug/pprof/", guard(pprofMux))
}
