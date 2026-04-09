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
	"sync"
	"sync/atomic"
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
	addr     string
	tokenID  string
	secret   string
	shutdown func() error
}

var objectSizes = []struct {
	name string
	size int64
}{
	{"1KB", 1 << 10},
	{"64KB", 64 << 10},
	{"1MB", 1 << 20},
	{"10MB", 10 << 20},
}

var concurrencyLevels = []int{1, 4, 16}

// setupS3Bench creates an S3 HTTP test server for benchmarks.
func setupS3Bench(b *testing.B) *benchS3Env {
	b.Helper()
	dir := b.TempDir()
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		b.Fatal(err)
	}
	db.SetSigningSecret("test-secret")
	b.Cleanup(func() { _ = db.Close() })

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

	adminHandler := admin.NewHandler(admin.AdminConfig{
		DB: db, Store: st, Auth: au, AdminToken: "test-admin",
		Log: log, Metrics: metrics,
	})
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
	_ = resp.Body.Close()
	if err := json.Unmarshal(respBytes, &acctResult); err != nil {
		b.Fatalf("decode account response: %v (body: %s)", err, respBytes)
	}

	// Create token via admin API (with all actions)
	tokenBody := `{"account_id":"` + acctResult.AccountID + `","name":"bench","allowed_actions":["bucket:list","bucket:read-meta","bucket:write-meta","object:get","object:put","object:delete","object:list","multipart:create","multipart:upload-part","multipart:complete","multipart:abort"]}`
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
	_ = resp.Body.Close()
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
	_ = resp.Body.Close()

	return &benchS3Env{
		s3Server:    s3Srv,
		adminServer: adminSrv,
		auth:        authHeader,
	}
}

// setupNativeBench creates a native protocol server and client for benchmarks.
func setupNativeBench(b *testing.B) *benchNativeEnv {
	b.Helper()
	dir := b.TempDir()
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		b.Fatal(err)
	}
	db.SetSigningSecret("test-secret")
	b.Cleanup(func() { _ = db.Close() })

	st, err := store.New(dir)
	if err != nil {
		b.Fatal(err)
	}

	au := auth.New(db)

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

	srv := proto.NewServer(db, st, au, log, 0, 0)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	shutdown, err := srv.ListenAndServe(addr)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = shutdown() })

	c, err := client.Dial(addr, "bench-token", secret, 16)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = c.Close() })

	if _, err := c.CreateBucket("benchbucket"); err != nil {
		b.Fatal(err)
	}

	return &benchNativeEnv{
		client:   c,
		addr:     addr,
		tokenID:  "bench-token",
		secret:   secret,
		shutdown: shutdown,
	}
}

func makeData(size int64) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

// ============================================================
// S3 HTTP Benchmarks
// ============================================================

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
				_ = resp.Body.Close()
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
		key := fmt.Sprintf("/benchbucket/obj-get-%s", sz.name)
		req, _ := http.NewRequest("PUT", env.s3Server.URL+key, bytes.NewReader(data))
		req.Header.Set("Authorization", env.auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()

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
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != 200 {
					b.Fatalf("get: status %d", resp.StatusCode)
				}
			}
		})
	}
}

func BenchmarkS3HeadObject(b *testing.B) {
	env := setupS3Bench(b)

	data := makeData(1 << 10)
	key := "/benchbucket/obj-head"
	req, _ := http.NewRequest("PUT", env.s3Server.URL+key, bytes.NewReader(data))
	req.Header.Set("Authorization", env.auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	_ = resp.Body.Close()

	b.ResetTimer()
	for b.Loop() {
		req, _ := http.NewRequest("HEAD", env.s3Server.URL+key, nil)
		req.Header.Set("Authorization", env.auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			b.Fatalf("head: status %d", resp.StatusCode)
		}
	}
}

func BenchmarkS3DeleteObject(b *testing.B) {
	env := setupS3Bench(b)

	data := makeData(1 << 10)

	b.ResetTimer()
	i := 0
	for b.Loop() {
		b.StopTimer()
		key := fmt.Sprintf("/benchbucket/obj-del-%d", i)
		req, _ := http.NewRequest("PUT", env.s3Server.URL+key, bytes.NewReader(data))
		req.Header.Set("Authorization", env.auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()
		b.StartTimer()

		req, _ = http.NewRequest("DELETE", env.s3Server.URL+key, nil)
		req.Header.Set("Authorization", env.auth)
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()
		i++
	}
}

func BenchmarkS3ListObjects(b *testing.B) {
	env := setupS3Bench(b)

	for i := range 100 {
		key := fmt.Sprintf("/benchbucket/list-obj-%03d", i)
		req, _ := http.NewRequest("PUT", env.s3Server.URL+key, strings.NewReader("x"))
		req.Header.Set("Authorization", env.auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()
	}

	b.ResetTimer()
	for b.Loop() {
		req, _ := http.NewRequest("GET", env.s3Server.URL+"/benchbucket?list-type=2", nil)
		req.Header.Set("Authorization", env.auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			b.Fatalf("list: status %d", resp.StatusCode)
		}
	}
}

func BenchmarkS3MultipartUpload(b *testing.B) {
	env := setupS3Bench(b)
	partSize := int64(5 << 20) // 5MB parts
	numParts := 3
	totalSize := partSize * int64(numParts)
	parts := make([][]byte, numParts)
	for i := range numParts {
		parts[i] = makeData(partSize)
	}

	b.SetBytes(totalSize)
	b.ResetTimer()
	i := 0
	for b.Loop() {
		key := fmt.Sprintf("/benchbucket/mp-obj-%d", i)

		// Initiate
		req, _ := http.NewRequest("POST", env.s3Server.URL+key+"?uploads", nil)
		req.Header.Set("Authorization", env.auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		// Parse upload ID from XML
		uploadID := extractXMLValue(string(body), "UploadId")
		if uploadID == "" {
			b.Fatalf("no upload ID in response: %s", body)
		}

		// Upload parts
		etags := make([]string, numParts)
		for p := range numParts {
			url := fmt.Sprintf("%s%s?partNumber=%d&uploadId=%s", env.s3Server.URL, key, p+1, uploadID)
			req, _ := http.NewRequest("PUT", url, bytes.NewReader(parts[p]))
			req.Header.Set("Authorization", env.auth)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				b.Fatal(err)
			}
			etags[p] = resp.Header.Get("ETag")
			_ = resp.Body.Close()
		}

		// Complete
		var xmlParts strings.Builder
		xmlParts.WriteString("<CompleteMultipartUpload>")
		for p := range numParts {
			fmt.Fprintf(&xmlParts, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>", p+1, etags[p])
		}
		xmlParts.WriteString("</CompleteMultipartUpload>")

		req, _ = http.NewRequest("POST", fmt.Sprintf("%s%s?uploadId=%s", env.s3Server.URL, key, uploadID), strings.NewReader(xmlParts.String()))
		req.Header.Set("Authorization", env.auth)
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			b.Fatalf("complete: status %d", resp.StatusCode)
		}
		i++
	}
}

// ============================================================
// S3 Concurrent Benchmarks
// ============================================================

func BenchmarkS3PutObjectConcurrent(b *testing.B) {
	env := setupS3Bench(b)

	for _, sz := range objectSizes[:3] { // skip 10MB for concurrent to keep bench time reasonable
		data := makeData(sz.size)
		for _, conc := range concurrencyLevels {
			b.Run(fmt.Sprintf("%s/conc%d", sz.name, conc), func(b *testing.B) {
				b.SetBytes(sz.size)
				b.SetParallelism(conc)
				var counter atomic.Int64
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						n := counter.Add(1)
						key := fmt.Sprintf("/benchbucket/conc-put-%d", n)
						req, _ := http.NewRequest("PUT", env.s3Server.URL+key, bytes.NewReader(data))
						req.Header.Set("Authorization", env.auth)
						resp, err := http.DefaultClient.Do(req)
						if err != nil {
							b.Fatal(err)
						}
						_ = resp.Body.Close()
					}
				})
			})
		}
	}
}

func BenchmarkS3GetObjectConcurrent(b *testing.B) {
	env := setupS3Bench(b)

	for _, sz := range objectSizes[:3] {
		data := makeData(sz.size)
		// Seed objects for concurrent reads
		for j := range 16 {
			key := fmt.Sprintf("/benchbucket/conc-get-%s-%d", sz.name, j)
			req, _ := http.NewRequest("PUT", env.s3Server.URL+key, bytes.NewReader(data))
			req.Header.Set("Authorization", env.auth)
			resp, _ := http.DefaultClient.Do(req)
			_ = resp.Body.Close()
		}

		for _, conc := range concurrencyLevels {
			b.Run(fmt.Sprintf("%s/conc%d", sz.name, conc), func(b *testing.B) {
				b.SetBytes(sz.size)
				b.SetParallelism(conc)
				var counter atomic.Int64
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						n := counter.Add(1)
						key := fmt.Sprintf("/benchbucket/conc-get-%s-%d", sz.name, n%16)
						req, _ := http.NewRequest("GET", env.s3Server.URL+key, nil)
						req.Header.Set("Authorization", env.auth)
						resp, err := http.DefaultClient.Do(req)
						if err != nil {
							b.Fatal(err)
						}
						_, _ = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
					}
				})
			})
		}
	}
}

// ============================================================
// Native Protocol Benchmarks
// ============================================================

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
				_, _ = io.Copy(io.Discard, result.Body)
				_ = result.Body.Close()
			}
		})
	}
}

func BenchmarkNativeHeadObject(b *testing.B) {
	env := setupNativeBench(b)

	data := makeData(1 << 10)
	_, err := env.client.PutObject("benchbucket", "obj-head",
		bytes.NewReader(data), int64(len(data)), nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := env.client.HeadObject("benchbucket", "obj-head")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNativeDeleteObject(b *testing.B) {
	env := setupNativeBench(b)

	data := makeData(1 << 10)

	b.ResetTimer()
	i := 0
	for b.Loop() {
		b.StopTimer()
		key := fmt.Sprintf("obj-del-%d", i)
		_, err := env.client.PutObject("benchbucket", key,
			bytes.NewReader(data), int64(len(data)), nil)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()

		if err := env.client.DeleteObject("benchbucket", key); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

func BenchmarkNativeListObjects(b *testing.B) {
	env := setupNativeBench(b)

	for i := range 100 {
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

func BenchmarkNativeMultipartUpload(b *testing.B) {
	env := setupNativeBench(b)
	partSize := int64(5 << 20) // 5MB parts
	numParts := 3
	totalSize := partSize * int64(numParts)
	parts := make([][]byte, numParts)
	for i := range numParts {
		parts[i] = makeData(partSize)
	}

	b.SetBytes(totalSize)
	b.ResetTimer()
	i := 0
	for b.Loop() {
		key := fmt.Sprintf("mp-obj-%d", i)

		uploadID, err := env.client.CreateMultipartUpload("benchbucket", key, nil)
		if err != nil {
			b.Fatal(err)
		}

		cparts := make([]client.CompletePart, numParts)
		for p := range numParts {
			etag, err := env.client.UploadPart("benchbucket", key, uploadID, p+1,
				bytes.NewReader(parts[p]), partSize)
			if err != nil {
				b.Fatal(err)
			}
			cparts[p] = client.CompletePart{PartNumber: p + 1, ETag: etag}
		}

		if _, err := env.client.CompleteMultipartUpload("benchbucket", key, uploadID, cparts); err != nil {
			b.Fatal(err)
		}
		i++
	}
}

// ============================================================
// Native Concurrent Benchmarks
// ============================================================

func BenchmarkNativePutObjectConcurrent(b *testing.B) {
	env := setupNativeBench(b)

	for _, sz := range objectSizes[:3] {
		data := makeData(sz.size)
		for _, conc := range concurrencyLevels {
			b.Run(fmt.Sprintf("%s/conc%d", sz.name, conc), func(b *testing.B) {
				b.SetBytes(sz.size)
				// Create per-goroutine clients so connections don't serialize
				clients := make([]*client.Client, conc)
				for i := range conc {
					c, err := client.Dial(env.addr, env.tokenID, env.secret, 2)
					if err != nil {
						b.Fatal(err)
					}
					clients[i] = c
				}
				b.Cleanup(func() {
					for _, c := range clients {
						_ = c.Close()
					}
				})

				var counter atomic.Int64
				var clientIdx atomic.Int64
				b.ResetTimer()

				var wg sync.WaitGroup
				wg.Add(conc)
				// Manually launch goroutines to control client assignment
				iterCh := make(chan struct{}, b.N)
				for range b.N {
					iterCh <- struct{}{}
				}
				close(iterCh)

				for g := range conc {
					go func(c *client.Client) {
						defer wg.Done()
						for range iterCh {
							n := counter.Add(1)
							key := fmt.Sprintf("conc-put-%d", n)
							_, err := c.PutObject("benchbucket", key,
								bytes.NewReader(data), sz.size, nil)
							if err != nil {
								b.Error(err)
								return
							}
						}
					}(clients[g])
				}
				wg.Wait()
				_ = clientIdx.Load() // suppress unused
			})
		}
	}
}

func BenchmarkNativeGetObjectConcurrent(b *testing.B) {
	env := setupNativeBench(b)

	for _, sz := range objectSizes[:3] {
		data := makeData(sz.size)
		for j := range 16 {
			key := fmt.Sprintf("conc-get-%s-%d", sz.name, j)
			_, err := env.client.PutObject("benchbucket", key,
				bytes.NewReader(data), sz.size, nil)
			if err != nil {
				b.Fatal(err)
			}
		}

		for _, conc := range concurrencyLevels {
			b.Run(fmt.Sprintf("%s/conc%d", sz.name, conc), func(b *testing.B) {
				b.SetBytes(sz.size)
				clients := make([]*client.Client, conc)
				for i := range conc {
					c, err := client.Dial(env.addr, env.tokenID, env.secret, 2)
					if err != nil {
						b.Fatal(err)
					}
					clients[i] = c
				}
				b.Cleanup(func() {
					for _, c := range clients {
						_ = c.Close()
					}
				})

				var counter atomic.Int64
				b.ResetTimer()

				var wg sync.WaitGroup
				wg.Add(conc)
				iterCh := make(chan struct{}, b.N)
				for range b.N {
					iterCh <- struct{}{}
				}
				close(iterCh)

				for g := range conc {
					go func(c *client.Client) {
						defer wg.Done()
						for range iterCh {
							n := counter.Add(1)
							key := fmt.Sprintf("conc-get-%s-%d", sz.name, n%16)
							result, err := c.GetObject("benchbucket", key)
							if err != nil {
								b.Error(err)
								return
							}
							_, _ = io.Copy(io.Discard, result.Body)
							_ = result.Body.Close()
						}
					}(clients[g])
				}
				wg.Wait()
			})
		}
	}
}

// ============================================================
// Helpers
// ============================================================

// extractXMLValue is a minimal helper to extract a value between XML tags.
func extractXMLValue(xml, tag string) string {
	start := strings.Index(xml, "<"+tag+">")
	if start == -1 {
		return ""
	}
	start += len(tag) + 2
	end := strings.Index(xml[start:], "</"+tag+">")
	if end == -1 {
		return ""
	}
	return xml[start : start+end]
}
