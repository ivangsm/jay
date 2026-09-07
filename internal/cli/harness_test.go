package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/proto"
	"github.com/ivangsm/jay/proto/client"
	"github.com/ivangsm/jay/store"
)

// testEnv is a real jay speaking the native protocol on a loopback port. The
// CLI tests drive the actual commands against it, so what they assert is the
// bytes that landed — never the confirmation line printed on the way.
type testEnv struct {
	opts   Options
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	dir    string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	dir := t.TempDir()
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetSigningSecret("signing-secret-for-tests-0123456789")
	t.Cleanup(func() { _ = db.Close() })

	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.CreateAccount(&meta.Account{AccountID: "acct", Name: "test", Status: "active"}); err != nil {
		t.Fatal(err)
	}

	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		t.Fatal(err)
	}
	secret := hex.EncodeToString(secretBytes)
	hash, err := auth.HashSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateToken(&meta.Token{
		TokenID:        "test-token",
		AccountID:      "acct",
		Name:           "test",
		SecretHash:     hash,
		AllowedActions: meta.AllActions,
		Status:         "active",
	}); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	shutdown, err := proto.NewServer(db, st, auth.New(db), log, nil, 0, 0).ListenAndServe(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shutdown() })

	env := &testEnv{
		stdout: &bytes.Buffer{},
		stderr: &bytes.Buffer{},
		dir:    dir,
	}
	env.opts = Options{
		Addr:        addr,
		TokenID:     "test-token",
		TokenSecret: secret,
		Stdout:      env.stdout,
		Stderr:      env.stderr,
	}
	return env
}

// run executes a subcommand exactly as the binary would and returns the exit code.
func (e *testEnv) run(args ...string) int {
	e.stdout.Reset()
	e.stderr.Reset()
	return Run(e.opts, args)
}

// mustRun fails the test when the command reports anything but success.
func (e *testEnv) mustRun(t *testing.T, args ...string) {
	t.Helper()
	if code := e.run(args...); code != 0 {
		t.Fatalf("jay %v: exit %d\nstdout: %s\nstderr: %s", args, code, e.stdout, e.stderr)
	}
}

// path builds a path inside the test's own temp tree.
func (e *testEnv) path(parts ...string) string {
	return filepath.Join(append([]string{e.dir}, parts...)...)
}

// writeFile creates a local file with the given contents.
func (e *testEnv) writeFile(t *testing.T, rel string, data []byte) string {
	t.Helper()
	p := e.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fetch reads an object back through the client, so assertions are about what
// the server actually stored.
func (e *testEnv) fetch(t *testing.T, bucket, key string) []byte {
	t.Helper()
	c, err := e.opts.dial()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	obj, err := c.GetObject(bucket, key)
	if err != nil {
		t.Fatalf("get %s/%s: %v", bucket, key, err)
	}
	defer func() { _ = obj.Body.Close() }()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(obj.Body); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// keys lists every key stored under a bucket.
func (e *testEnv) keys(t *testing.T, bucket string) []string {
	t.Helper()
	c, err := e.opts.dial()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	var out []string
	err = walkObjects(c, bucket, "", "", func(page *client.ListResult) error {
		for _, o := range page.Objects {
			out = append(out, o.Key)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// putObject stores a key directly through the client, bypassing the CLI's own
// key building. Keys are opaque bytes on the wire, so this is how a bucket
// ends up holding one no local command would have produced.
func (e *testEnv) putObject(t *testing.T, bucket, key string, data []byte) {
	t.Helper()
	c, err := e.opts.dial()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	if _, err := c.PutObject(bucket, key, bytes.NewReader(data), int64(len(data)), nil); err != nil {
		t.Fatalf("put %s/%s: %v", bucket, key, err)
	}
}
