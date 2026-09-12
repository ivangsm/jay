package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/proto"
	"github.com/ivangsm/jay/store"
)

// selfSignedCert builds a certificate valid for 127.0.0.1, plus a pool that
// trusts it. Generated per test rather than checked in: a committed test key
// is a key someone eventually reuses.
func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "jay-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// tlsEnv is a native server plus the credentials to reach it. Unlike setup()
// it does not dial: these tests care about how the connection is made.
type tlsEnv struct {
	addr    string
	tokenID string
	secret  string
	pool    *x509.CertPool
}

// startNativeServer boots a native protocol server, with TLS when serverTLS is
// non-nil, and returns everything needed to connect to it.
func startNativeServer(t *testing.T, serverTLS *tls.Config) *tlsEnv {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetSigningSecret("test-secret-for-signing-that-is-long-enough")
	t.Cleanup(func() { _ = db.Close() })

	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.CreateAccount(&meta.Account{AccountID: "acct", Name: "t", Status: "active"}); err != nil {
		t.Fatal(err)
	}

	// A recognisable secret so an interception test can look for it verbatim.
	const secret = "SUPERSECRETTOKENVALUE0123456789abcdef"
	hash, err := auth.HashSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateToken(&meta.Token{
		TokenID:        "tok",
		AccountID:      "acct",
		Name:           "t",
		SecretHash:     hash,
		AllowedActions: meta.AllActions,
		Status:         "active",
	}); err != nil {
		t.Fatal(err)
	}

	var metrics *maintenance.Metrics
	srv := proto.NewServer(db, st, auth.New(db), log, metrics, 0, 0)
	if serverTLS != nil {
		srv.SetTLSConfig(serverTLS)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	shutdown, err := srv.ListenAndServe(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shutdown() })

	return &tlsEnv{addr: addr, tokenID: "tok", secret: secret}
}

func TestNativeTLS_RoundTrip(t *testing.T) {
	cert, pool := selfSignedCert(t)
	env := startNativeServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	env.pool = pool

	c, err := Dial(context.Background(), env.addr, env.tokenID, env.secret, WithPoolSize(2), WithTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatalf("dial over TLS: %v", err)
	}
	defer func() { _ = c.Close() }()

	// A handshake proves authentication; a real object proves the framing and
	// the body copy survive the TLS wrapper — the GetObject path gives up
	// sendfile(2) under TLS and that is where a regression would land.
	if _, err := c.CreateBucket(context.Background(), "bucket"); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	body := bytes.Repeat([]byte("payload"), 1000)
	if _, err := c.PutObject(context.Background(), "bucket", "k", bytes.NewReader(body), int64(len(body)), nil); err != nil {
		t.Fatalf("put: %v", err)
	}
	obj, err := c.GetObject(context.Background(), "bucket", "k")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, err := io.ReadAll(obj.Body)
	_ = obj.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body round trip over TLS lost data: got %d bytes, want %d", len(got), len(body))
	}
}

// recordingProxy sits between a client and the server and keeps every byte the
// client sends. It is how these tests observe what is actually on the wire
// instead of trusting that a config flag did something.
type recordingProxy struct {
	addr string

	mu   sync.Mutex
	sent []byte
}

func newRecordingProxy(t *testing.T, target string) *recordingProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	p := &recordingProxy{addr: ln.Addr().String()}

	go func() {
		for {
			downstream, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(downstream, target)
		}
	}()

	return p
}

func (p *recordingProxy) handle(downstream net.Conn, target string) {
	defer func() { _ = downstream.Close() }()
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()

	go func() { _, _ = io.Copy(downstream, upstream) }()
	_, _ = io.Copy(io.MultiWriter(upstream, writerFunc(p.record)), downstream)
}

func (p *recordingProxy) record(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, b...)
	return len(b), nil
}

func (p *recordingProxy) captured() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.sent...)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

// TestNativeTLS_SecretIsNotReadableOnTheWire is the test PND-0163 is actually
// about. It asserts the property, not the setting: with TLS off the token
// secret is sitting in the bytes on the wire, and with TLS on it is not.
//
// Half of it is a control. Without the plaintext case proving the proxy can
// see a secret when one is there, the TLS case would pass just as happily
// against a proxy that captured nothing at all.
func TestNativeTLS_SecretIsNotReadableOnTheWire(t *testing.T) {
	t.Run("plaintext leaks the secret", func(t *testing.T) {
		env := startNativeServer(t, nil)
		proxy := newRecordingProxy(t, env.addr)

		c, err := Dial(context.Background(), proxy.addr, env.tokenID, env.secret, WithPoolSize(1))
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_ = c.Close()

		if !bytes.Contains(proxy.captured(), []byte(env.secret)) {
			t.Fatal("expected the secret to be visible in plaintext traffic; " +
				"if this fails the interception test itself is broken and the TLS case below proves nothing")
		}
	})

	t.Run("TLS hides the secret", func(t *testing.T) {
		cert, pool := selfSignedCert(t)
		env := startNativeServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		proxy := newRecordingProxy(t, env.addr)

		c, err := Dial(context.Background(), proxy.addr, env.tokenID, env.secret, WithPoolSize(1), WithTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
		if err != nil {
			t.Fatalf("dial over TLS: %v", err)
		}
		_ = c.Close()

		captured := proxy.captured()
		if len(captured) == 0 {
			t.Fatal("captured nothing; the proxy did not observe the connection")
		}
		if bytes.Contains(captured, []byte(env.secret)) {
			t.Fatal("the token secret appeared in TLS traffic")
		}
		if bytes.Contains(captured, []byte(env.tokenID+":")) {
			t.Fatal("the credential separator appeared in TLS traffic")
		}
	})
}

// TestNativeTLS_NoSilentDowngrade fixes the decision that a mismatched
// transport fails instead of falling back. A client that quietly accepted
// plaintext when TLS was unavailable would make the encryption unverifiable
// from its own side.
func TestNativeTLS_NoSilentDowngrade(t *testing.T) {
	t.Run("TLS client against a plaintext server", func(t *testing.T) {
		env := startNativeServer(t, nil)
		_, pool := selfSignedCert(t)

		_, err := Dial(context.Background(), env.addr, env.tokenID, env.secret, WithTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}))
		if err == nil {
			t.Fatal("a TLS client must not succeed against a plaintext listener")
		}
	})

	t.Run("plaintext client against a TLS server", func(t *testing.T) {
		cert, _ := selfSignedCert(t)
		env := startNativeServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

		_, err := Dial(context.Background(), env.addr, env.tokenID, env.secret, WithPoolSize(1))
		if err == nil {
			t.Fatal("a plaintext client must not succeed against a TLS listener")
		}
	})

	t.Run("untrusted certificate is refused", func(t *testing.T) {
		cert, _ := selfSignedCert(t)
		env := startNativeServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})

		// A pool that trusts a DIFFERENT certificate: verification must fail.
		_, otherPool := selfSignedCert(t)
		_, err := Dial(context.Background(), env.addr, env.tokenID, env.secret, WithTLS(&tls.Config{RootCAs: otherPool, MinVersion: tls.VersionTLS12}))
		if err == nil {
			t.Fatal("a certificate signed by an untrusted key must be refused")
		}
	})
}

// TestHandshakeErrors_AreDistinguishable covers the diagnosis half of the same
// work: a caller has to be able to tell "retry later" from "your token is
// wrong", and every failure used to report the same thing.
func TestHandshakeErrors_AreDistinguishable(t *testing.T) {
	env := startNativeServer(t, nil)

	_, err := Dial(context.Background(), env.addr, "tok", "wrong-secret", WithPoolSize(1))
	if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("bad secret: got %v, want ErrAuthFailed", err)
	}

	// A listener that answers with a status this client version does not know
	// must be reported as that status, not folded into a known one.
	ln, lnErr := net.Listen("tcp", "127.0.0.1:0")
	if lnErr != nil {
		t.Fatal(lnErr)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = proto.WriteHandshakeResponse(conn, 0x7F)
	}()

	_, err = Dial(context.Background(), ln.Addr().String(), "tok", "secret", WithPoolSize(1))
	if err == nil {
		t.Fatal("expected an error for an unknown handshake status")
	}
	if !strings.Contains(err.Error(), "127") { // 0x7F
		t.Errorf("an unknown status must be reported with its number, got %v", err)
	}
}

// TestDial_PoolSizeOption pins that WithPoolSize sizes the pool and that a
// Dial without WithTLS stays in the clear.
func TestDial_PoolSizeOption(t *testing.T) {
	env := startNativeServer(t, nil)

	c, err := Dial(context.Background(), env.addr, env.tokenID, env.secret, WithPoolSize(3))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	if cap(c.pool) != 3 {
		t.Errorf("pool size = %d, want 3", cap(c.pool))
	}
	if c.tlsConfig != nil {
		t.Error("Dial must not enable TLS")
	}
}

func TestDialWithOptions_ZeroPoolSizeDefaults(t *testing.T) {
	env := startNativeServer(t, nil)

	c, err := Dial(context.Background(), env.addr, env.tokenID, env.secret)
	if err != nil {
		t.Fatalf("DialWithOptions: %v", err)
	}
	defer func() { _ = c.Close() }()

	if cap(c.pool) != 4 {
		t.Errorf("pool size = %d, want the default of 4", cap(c.pool))
	}
}

// TestLastModified_SameFormatOnEveryPath fixes a divergence found while writing
// the protocol spec: ListObjects formatted last_modified with the literal
// layout "2006-01-02T15:04:05Z" while HeadObject and GetObject used
// time.RFC3339. That literal is not a timezone specifier — it stamps a "Z" on
// whatever zone the value happens to carry — so the two paths agreed only
// because meta stores UTC. One object reported its mtime two ways depending on
// how you asked for it, and the ListObjects form would have claimed UTC while
// printing local time.
func TestLastModified_SameFormatOnEveryPath(t *testing.T) {
	env := startNativeServer(t, nil)

	c, err := Dial(context.Background(), env.addr, env.tokenID, env.secret, WithPoolSize(1))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	if _, err := c.CreateBucket(context.Background(), "bucket"); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	body := []byte("hello")
	if _, err := c.PutObject(context.Background(), "bucket", "k", bytes.NewReader(body), int64(len(body)), nil); err != nil {
		t.Fatalf("put: %v", err)
	}

	head, err := c.HeadObject(context.Background(), "bucket", "k")
	if err != nil {
		t.Fatalf("head: %v", err)
	}

	list, err := c.ListObjects(context.Background(), "bucket", &ListOptions{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Objects) != 1 {
		t.Fatalf("got %d objects, want 1", len(list.Objects))
	}

	if head.LastModified != list.Objects[0].LastModified {
		t.Errorf("last_modified differs by path:\nHeadObject  %q\nListObjects %q",
			head.LastModified, list.Objects[0].LastModified)
	}

	// And it must actually be RFC 3339, which is what the spec promises.
	if _, err := time.Parse(time.RFC3339, head.LastModified); err != nil {
		t.Errorf("HeadObject last_modified %q is not RFC 3339: %v", head.LastModified, err)
	}
	if _, err := time.Parse(time.RFC3339, list.Objects[0].LastModified); err != nil {
		t.Errorf("ListObjects last_modified %q is not RFC 3339: %v", list.Objects[0].LastModified, err)
	}
}
