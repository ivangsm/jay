package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ivangsm/jay/admin"
	jayapi "github.com/ivangsm/jay/api"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/proto"
	"github.com/ivangsm/jay/proto/client"
	"github.com/ivangsm/jay/recovery"
	"github.com/ivangsm/jay/store"
)

// benchS3Env holds the S3 HTTP test environment for benchmarks.
type benchS3Env struct {
	s3Server    *httptest.Server
	adminServer *httptest.Server
	auth        string
}

// benchNativeEnv holds the native protocol test environment for benchmarks.
type benchNativeEnv struct {
	client   *client.Client
	shutdown func() error
}

var objectSizes = []struct {
	name string
	size int64
}{
	{"1KB", 1 << 10},
	{"64KB", 64 << 10},
	{"1MB", 1 << 20},
}

// setupS3Bench creates an S3 HTTP test server for benchmarks, reusing the
// same pattern as setup() in jay_test.go.
func setupS3Bench(b *testing.B) *benchS3Env {
	b.Helper()
	dir := b.TempDir()
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { db.Close() })

	st, err := store.New(dir)
	if err != nil {
		b.Fatal(err)
	}

	if err := recovery.Run(db, st, log); err != nil {
		b.Fatal(err)
	}

	au := auth.New(db)
	metrics := maintenance.NewMetrics()
	s3Handler := jayapi.NewHandler(db, st, au, log, metrics, "", nil)
	s3Srv := httptest.NewServer(s3Handler)
	b.Cleanup(s3Srv.Close)

	adminHandler := admin.NewHandler(db, "test-admin", log, metrics, st, "", "", false)
	adminSrv := httptest.NewServer(adminHandler)
	b.Cleanup(adminSrv.Close)

	// Create account via admin API
	acctBody := `{"name":"benchaccount"}`
	req, _ := http.NewRequest("POST", adminSrv.URL+"/_jay/accounts", strings.NewReader(acctBody))
	req.Header.Set("Authorization", "Bearer test-admin")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	var acctResult struct {
		AccountID string `json:"account_id"`
	}
	respBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(respBytes, &acctResult); err != nil {
		b.Fatalf("decode account response: %v (body: %s)", err, respBytes)
	}

	// Create token via admin API
	tokenBody := `{"account_id":"` + acctResult.AccountID + `","name":"bench"}`
	req, _ = http.NewRequest("POST", adminSrv.URL+"/_jay/tokens", strings.NewReader(tokenBody))
	req.Header.Set("Authorization", "Bearer test-admin")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	var tokenResult struct {
		TokenID string `json:"token_id"`
		Secret  string `json:"secret"`
	}
	respBytes, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(respBytes, &tokenResult); err != nil {
		b.Fatalf("decode token response: %v (body: %s)", err, respBytes)
	}

	authHeader := "Bearer " + tokenResult.TokenID + ":" + tokenResult.Secret

	// Create benchmark bucket
	req, _ = http.NewRequest("PUT", s3Srv.URL+"/benchbucket", nil)
	req.Header.Set("Authorization", authHeader)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	resp.Body.Close()

	return &benchS3Env{
		s3Server:    s3Srv,
		adminServer: adminSrv,
		auth:        authHeader,
	}
}

// setupNativeBench creates a native protocol server and client for benchmarks,
// reusing the same pattern as setup() in proto/proto_test.go.
func setupNativeBench(b *testing.B) *benchNativeEnv {
	b.Helper()
	dir := b.TempDir()
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { db.Close() })

	st, err := store.New(dir)
	if err != nil {
		b.Fatal(err)
	}

	au := auth.New(db)

	// Create account and token directly in the DB (same as proto_test.go)
	account := &meta.Account{AccountID: "bench-account", Name: "bench", Status: "active"}
	if err := db.CreateAccount(account); err != nil {
		b.Fatal(err)
	}

	secretBytes := make([]byte, 32)
	rand.Read(secretBytes)
	secret := hex.EncodeToString(secretBytes)
	hash, _ := auth.HashSecret(secret)

	token := &meta.Token{
		TokenID:        "bench-token",
		AccountID:      "bench-account",
		Name:           "bench",
		SecretHash:     hash,
		AllowedActions: meta.AllActions,
		Status:         "active",
	}
	if err := db.CreateToken(token); err != nil {
		b.Fatal(err)
	}

	srv := proto.NewServer(db, st, au, log)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	shutdown, err := srv.ListenAndServe(addr)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { shutdown() })

	c, err := client.Dial(addr, "bench-token", secret, 4)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { c.Close() })

	// Create benchmark bucket
	if _, err := c.CreateBucket("benchbucket"); err != nil {
		b.Fatal(err)
	}

	return &benchNativeEnv{
		client:   c,
		shutdown: shutdown,
	}
}

func makeData(size int64) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

// --- S3 HTTP Benchmarks ---

func BenchmarkS3PutObject(b *testing.B) {
	env := setupS3Bench(b)

	for _, sz := range objectSizes {
		data := makeData(sz.size)
		b.Run(sz.name, func(b *testing.B) {
			b.SetBytes(sz.size)
			b.ResetTimer()
			i := 0
			for b.Loop() {
				key := fmt.Sprintf("/benchbucket/obj-put-%d", i)
				req, _ := http.NewRequest("PUT", env.s3Server.URL+key, bytes.NewReader(data))
				req.Header.Set("Authorization", env.auth)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					b.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != 200 {
					b.Fatalf("put: status %d", resp.StatusCode)
				}
				i++
			}
		})
	}
}

func BenchmarkS3GetObject(b *testing.B) {
	env := setupS3Bench(b)

	for _, sz := range objectSizes {
		data := makeData(sz.size)
		// Seed the object for GET benchmarks
		key := fmt.Sprintf("/benchbucket/obj-get-%s", sz.name)
		req, _ := http.NewRequest("PUT", env.s3Server.URL+key, bytes.NewReader(data))
		req.Header.Set("Authorization", env.auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()

		b.Run(sz.name, func(b *testing.B) {
			b.SetBytes(sz.size)
			b.ResetTimer()
			for b.Loop() {
				req, _ := http.NewRequest("GET", env.s3Server.URL+key, nil)
				req.Header.Set("Authorization", env.auth)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					b.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 {
					b.Fatalf("get: status %d", resp.StatusCode)
				}
			}
		})
	}
}

func BenchmarkS3ListObjects(b *testing.B) {
	env := setupS3Bench(b)

	// Seed 50 objects for listing
	for i := range 50 {
		key := fmt.Sprintf("/benchbucket/list-obj-%03d", i)
		req, _ := http.NewRequest("PUT", env.s3Server.URL+key, strings.NewReader("x"))
		req.Header.Set("Authorization", env.auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		resp.Body.Close()
	}

	b.ResetTimer()
	for b.Loop() {
		req, _ := http.NewRequest("GET", env.s3Server.URL+"/benchbucket?list-type=2", nil)
		req.Header.Set("Authorization", env.auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			b.Fatalf("list: status %d", resp.StatusCode)
		}
	}
}

// --- Native Protocol Benchmarks ---

func BenchmarkNativePutObject(b *testing.B) {
	env := setupNativeBench(b)

	for _, sz := range objectSizes {
		data := makeData(sz.size)
		b.Run(sz.name, func(b *testing.B) {
			b.SetBytes(sz.size)
			b.ResetTimer()
			i := 0
			for b.Loop() {
				key := fmt.Sprintf("obj-put-%d", i)
				_, err := env.client.PutObject("benchbucket", key,
					bytes.NewReader(data), sz.size, nil)
				if err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	}
}

func BenchmarkNativeGetObject(b *testing.B) {
	env := setupNativeBench(b)

	for _, sz := range objectSizes {
		data := makeData(sz.size)
		// Seed the object for GET benchmarks
		key := fmt.Sprintf("obj-get-%s", sz.name)
		_, err := env.client.PutObject("benchbucket", key,
			bytes.NewReader(data), sz.size, nil)
		if err != nil {
			b.Fatal(err)
		}

		b.Run(sz.name, func(b *testing.B) {
			b.SetBytes(sz.size)
			b.ResetTimer()
			for b.Loop() {
				result, err := env.client.GetObject("benchbucket", key)
				if err != nil {
					b.Fatal(err)
				}
				io.Copy(io.Discard, result.Body)
				result.Body.Close()
			}
		})
	}
}

func BenchmarkNativeListObjects(b *testing.B) {
	env := setupNativeBench(b)

	// Seed 50 objects for listing
	for i := range 50 {
		key := fmt.Sprintf("list-obj-%03d", i)
		_, err := env.client.PutObject("benchbucket", key,
			strings.NewReader("x"), 1, nil)
		if err != nil {
			b.Fatal(err)
		}
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := env.client.ListObjects("benchbucket", nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
