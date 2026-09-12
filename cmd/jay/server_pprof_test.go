package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ivangsm/jay/admin"
)

// TestMountPprof_RequiresAdminToken comprueba las dos mitades del contrato de
// pprof: que está montado de verdad (incluido el perfil goroutineleak de Go
// 1.27) y que sin el token de admin no se llega a nada.
func TestMountPprof_RequiresAdminToken(t *testing.T) {
	const token = "token-de-admin-de-prueba-con-32-chars"

	adminHandler := admin.NewHandler(admin.AdminConfig{AdminToken: token})
	t.Cleanup(func() { _ = adminHandler.Close() })

	mux := http.NewServeMux()
	mountPprof(mux, adminHandler.RequireAdmin)

	srv := httptest.NewTestServer(t, mux)

	paths := []string{
		"/debug/pprof/",
		"/debug/pprof/goroutine?debug=1",
		"/debug/pprof/goroutineleak?debug=1", // nuevo en Go 1.27
		"/debug/pprof/cmdline",
	}

	for _, p := range paths {
		t.Run("sin-token"+p, func(t *testing.T) {
			resp, err := srv.Client().Get(srv.URL + p)
			if err != nil {
				t.Fatalf("GET %s: %v", p, err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("GET %s sin token: quiero 401, tengo %d", p, resp.StatusCode)
			}
		})

		t.Run("con-token"+p, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, srv.URL+p, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("GET %s: %v", p, err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s con token: quiero 200, tengo %d", p, resp.StatusCode)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("leer body de %s: %v", p, err)
			}
			if len(body) == 0 {
				t.Fatalf("GET %s devolvió un cuerpo vacío", p)
			}
		})
	}
}
