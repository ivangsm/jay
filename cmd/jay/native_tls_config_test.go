package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTestKeyPair writes a self-signed cert/key pair and returns their paths.
func writeTestKeyPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "jay-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// TestNativeTLSConfig_HalfConfiguredIsAnError is the point of the whole
// setting. The native handshake sends "token_id:secret" in the clear, so an
// operator who typed one of the two variables and got a running server would
// be publishing the credential of every client that connects — while the
// server looked, from outside, exactly like a working one.
//
// Failing to start is the correct outcome, not a warning and plaintext.
func TestNativeTLSConfig_HalfConfiguredIsAnError(t *testing.T) {
	certPath, keyPath := writeTestKeyPair(t)

	t.Run("cert without key", func(t *testing.T) {
		_, err := nativeTLSConfig(Config{NativeTLSCert: certPath})
		if err == nil {
			t.Fatal("a cert with no key must abort startup, not fall back to plaintext")
		}
		if !strings.Contains(err.Error(), "native_tls_key") {
			t.Errorf("the error must name the missing setting, got %v", err)
		}
	})

	t.Run("key without cert", func(t *testing.T) {
		_, err := nativeTLSConfig(Config{NativeTLSKey: keyPath})
		if err == nil {
			t.Fatal("a key with no cert must abort startup, not fall back to plaintext")
		}
		if !strings.Contains(err.Error(), "native_tls_cert") {
			t.Errorf("the error must name the missing setting, got %v", err)
		}
	})
}

func TestNativeTLSConfig_NeitherMeansPlaintext(t *testing.T) {
	cfg, err := nativeTLSConfig(Config{})
	if err != nil {
		t.Fatalf("an unset pair is not an error: %v", err)
	}
	if cfg != nil {
		t.Error("an unset pair must produce no TLS config")
	}
}

func TestNativeTLSConfig_BothLoads(t *testing.T) {
	certPath, keyPath := writeTestKeyPair(t)

	cfg, err := nativeTLSConfig(Config{NativeTLSCert: certPath, NativeTLSKey: keyPath})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected a TLS config")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("got %d certificates, want 1", len(cfg.Certificates))
	}
	if cfg.MinVersion < 0x0303 { // TLS 1.2
		t.Errorf("MinVersion = 0x%04X, want TLS 1.2 or higher", cfg.MinVersion)
	}
}

// TestNativeTLSConfig_BadPathFailsAtStartup: loading here rather than inside
// the listener is what turns a typo into a failed boot instead of a failure on
// the first client to connect, hours later.
func TestNativeTLSConfig_BadPathFailsAtStartup(t *testing.T) {
	_, err := nativeTLSConfig(Config{
		NativeTLSCert: filepath.Join(t.TempDir(), "missing-cert.pem"),
		NativeTLSKey:  filepath.Join(t.TempDir(), "missing-key.pem"),
	})
	if err == nil {
		t.Fatal("a nonexistent certificate path must fail at startup")
	}
}

// TestNativeTLSConfig_DoesNotInheritS3Certificate fixes the decision behind
// the separate variables: enabling TLS on the S3 port must not silently change
// the native transport, which would break every client already speaking to it
// in the clear.
func TestNativeTLSConfig_DoesNotInheritS3Certificate(t *testing.T) {
	certPath, keyPath := writeTestKeyPair(t)

	cfg, err := nativeTLSConfig(Config{TLSCert: certPath, TLSKey: keyPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Error("the native listener must not inherit the S3 certificate; " +
			"a transport switch cannot be a side effect of an unrelated setting")
	}
}
