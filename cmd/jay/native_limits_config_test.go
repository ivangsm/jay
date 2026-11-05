package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jayproto "github.com/ivangsm/jay/proto"
)

// The native back-pressure limits through both configuration doors, and
// through startDataListeners to a server that enforces them.

func TestNativeLimits_Defaults(t *testing.T) {
	clearJAYEnv(t)
	cfg, err := LoadConfigFromSources("", quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NativeMaxConns != 1000 {
		t.Errorf("NativeMaxConns default = %d, want 1000 (the cap the server always had)", cfg.NativeMaxConns)
	}
	if cfg.NativeTokenBytesPerSec != 0 {
		t.Errorf("NativeTokenBytesPerSec default = %d, want 0 (no cap)", cfg.NativeTokenBytesPerSec)
	}
}

func TestNativeLimits_FromEnv(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_NATIVE_MAX_CONNS", "50")
	t.Setenv("JAY_NATIVE_TOKEN_BYTES_PER_SEC", "1048576")
	cfg, err := LoadConfigFromSources("", quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NativeMaxConns != 50 || cfg.NativeTokenBytesPerSec != 1048576 {
		t.Errorf("got max_conns=%d bytes_per_sec=%d, want 50 and 1048576", cfg.NativeMaxConns, cfg.NativeTokenBytesPerSec)
	}
}

func TestNativeLimits_FromYAML(t *testing.T) {
	clearJAYEnv(t)
	path := filepath.Join(t.TempDir(), "jay.yaml")
	if err := os.WriteFile(path, []byte("native_max_conns: 20\nnative_token_bytes_per_sec: 2048\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigFromSources(path, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NativeMaxConns != 20 || cfg.NativeTokenBytesPerSec != 2048 {
		t.Errorf("got max_conns=%d bytes_per_sec=%d, want 20 and 2048", cfg.NativeMaxConns, cfg.NativeTokenBytesPerSec)
	}
}

// A cap of zero would refuse every client while the listener looks healthy.
// From YAML it stops the boot, like rate_burst.
func TestNativeLimits_NonPositiveMaxConnsYAMLRejected(t *testing.T) {
	clearJAYEnv(t)
	for _, body := range []string{"native_max_conns: 0\n", "native_max_conns: -1\n"} {
		path := filepath.Join(t.TempDir(), "jay.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfigFromSources(path, quietLogger()); err == nil {
			t.Errorf("%q was accepted; want a boot failure", strings.TrimSpace(body))
		}
	}
}

// From the environment it follows the loader's policy for bad values: logged,
// and the previous value — the default — holds. Never a cap of zero.
func TestNativeLimits_InvalidEnvKeepsDefaults(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_NATIVE_MAX_CONNS", "0")
	t.Setenv("JAY_NATIVE_TOKEN_BYTES_PER_SEC", "-5")

	log, buf := captureLogger()
	cfg, err := LoadConfigFromSources("", log)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NativeMaxConns != 1000 {
		t.Errorf("NativeMaxConns = %d, want the default 1000", cfg.NativeMaxConns)
	}
	if cfg.NativeTokenBytesPerSec != 0 {
		t.Errorf("NativeTokenBytesPerSec = %d, want the default 0", cfg.NativeTokenBytesPerSec)
	}
	for _, env := range []string{"invalid JAY_NATIVE_MAX_CONNS", "invalid JAY_NATIVE_TOKEN_BYTES_PER_SEC"} {
		if !strings.Contains(buf.String(), env) {
			t.Errorf("expected %q in the log, got: %s", env, buf.String())
		}
	}
}

func TestNativeLimits_NegativeBytesPerSecYAMLIgnored(t *testing.T) {
	clearJAYEnv(t)
	path := filepath.Join(t.TempDir(), "jay.yaml")
	if err := os.WriteFile(path, []byte("native_token_bytes_per_sec: -1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	log, buf := captureLogger()
	cfg, err := LoadConfigFromSources(path, log)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NativeTokenBytesPerSec != 0 {
		t.Errorf("NativeTokenBytesPerSec = %d, want 0", cfg.NativeTokenBytesPerSec)
	}
	if !strings.Contains(buf.String(), "invalid native_token_bytes_per_sec") {
		t.Errorf("expected an invalid-value error in the log, got: %s", buf.String())
	}
}

// listeningLine returns the "native server listening" entry of the log.
func listeningLine(t *testing.T, logged *syncBuffer) map[string]any {
	t.Helper()
	sc := bufio.NewScanner(strings.NewReader(logged.String()))
	for sc.Scan() {
		var entry map[string]any
		if json.Unmarshal(sc.Bytes(), &entry) == nil && entry["msg"] == "native server listening" {
			return entry
		}
	}
	t.Fatalf("no \"native server listening\" line: %s", logged.String())
	return nil
}

// TestNativeLimits_ReachTheServer: JAY_NATIVE_MAX_CONNS=1, through
// startDataListeners, must produce a server that refuses the second
// connection with ServerBusy — the variable in Config proves nothing on its
// own. The byte cap is read back from the server's own report of the limiter
// it built.
func TestNativeLimits_ReachTheServer(t *testing.T) {
	clearJAYEnv(t)
	t.Setenv("JAY_NATIVE_ADDR", "127.0.0.1:0")
	t.Setenv("JAY_NATIVE_MAX_CONNS", "1")
	t.Setenv("JAY_NATIVE_TOKEN_BYTES_PER_SEC", "2097152")

	cfg, err := LoadConfigFromSources("", quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	shutdownNative, logged := startDataListenersForTest(t, cfg)
	if shutdownNative == nil {
		t.Fatal("no native listener was started")
	}
	line := listeningLine(t, logged)
	if got, _ := line["token_bytes_per_sec"].(float64); got != 2097152 {
		t.Errorf("the server built a byte cap of %v, want 2097152", line["token_bytes_per_sec"])
	}
	addr, _ := line["bound"].(string)

	// The first connection takes the only slot as soon as it is accepted.
	first, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	time.Sleep(100 * time.Millisecond)

	second, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	_ = second.SetReadDeadline(time.Now().Add(3 * time.Second))
	status, err := jayproto.ReadHandshakeResponse(second)
	if err != nil {
		t.Fatalf("the second connection under JAY_NATIVE_MAX_CONNS=1 got no handshake status: %v", err)
	}
	if status != jayproto.HandshakeServerBusy {
		t.Fatalf("status = 0x%02X, want ServerBusy", status)
	}
}
