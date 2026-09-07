package proto

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// Tests for the handshake's diagnosis, which used to be a single lie: every
// failure — a cut socket, a wrong port, a full server — was answered as
// "protocol version mismatch", so the one thing a client reported was the one
// thing that was almost never true.

func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestReadHandshake_ClassifiesFailures(t *testing.T) {
	valid := func() []byte {
		var buf bytes.Buffer
		if err := WriteHandshake(&buf, "tok:sec"); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	cases := []struct {
		name     string
		input    []byte
		want     error
		wantStat byte
		respond  bool
	}{
		{
			name:     "bad magic",
			input:    []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00, 0x00, 0x03, 'a', ':', 'b'},
			want:     ErrHandshakeMagic,
			wantStat: HandshakeMalformed,
			respond:  true,
		},
		{
			name:     "unsupported version",
			input:    []byte{0x4A, 0x41, 0x59, 0x00, 0x09, 0x00, 0x00, 0x03, 'a', ':', 'b'},
			want:     ErrHandshakeVersion,
			wantStat: HandshakeVersionMismatch,
			respond:  true,
		},
		{
			name:     "empty credentials",
			input:    []byte{0x4A, 0x41, 0x59, 0x00, 0x01, 0x00, 0x00, 0x00},
			want:     ErrHandshakeCredentials,
			wantStat: HandshakeAuthFailed,
			respond:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadHandshake(bytes.NewReader(tc.input))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			status, respond := handshakeRejection(err)
			if respond != tc.respond {
				t.Fatalf("respond = %v, want %v", respond, tc.respond)
			}
			if status != tc.wantStat {
				t.Errorf("status = 0x%02X, want 0x%02X", status, tc.wantStat)
			}
		})
	}

	t.Run("torn socket gets no status", func(t *testing.T) {
		// A truncated read is a network failure, not a protocol disagreement.
		// Answering it with any status would be inventing a diagnosis for a
		// peer that is no longer there.
		_, err := ReadHandshake(bytes.NewReader(valid()[:4]))
		if err == nil {
			t.Fatal("expected an error for a truncated handshake")
		}
		if _, respond := handshakeRejection(err); respond {
			t.Error("a torn socket must not be answered with a handshake status")
		}
	})

	t.Run("truncated credentials get no status", func(t *testing.T) {
		// Declares 9 credential bytes and sends 2.
		input := []byte{0x4A, 0x41, 0x59, 0x00, 0x01, 0x00, 0x00, 0x09, 'a', ':'}
		_, err := ReadHandshake(bytes.NewReader(input))
		if err == nil {
			t.Fatal("expected an error")
		}
		if _, respond := handshakeRejection(err); respond {
			t.Error("a truncated credential read must not be classified as a protocol status")
		}
	})

	t.Run("reserved flags are ignored", func(t *testing.T) {
		// A future version may assign this byte, which requires today's
		// servers to have accepted whatever was in it.
		input := valid()
		input[5] = 0xFF
		creds, err := ReadHandshake(bytes.NewReader(input))
		if err != nil {
			t.Fatalf("a non-zero flags byte must not be rejected: %v", err)
		}
		if creds != "tok:sec" {
			t.Errorf("credentials = %q, want %q", creds, "tok:sec")
		}
	})
}

// TestServer_RejectsWithServerBusy covers the status that did not exist: at
// the connection limit the server used to close without writing anything, so
// a client saw a bare EOF and could not tell a full server from a dead one.
func TestServer_RejectsWithServerBusy(t *testing.T) {
	// maxConns of zero rejects every connection in the accept loop, before
	// anything touches the database — which is why this test needs no store.
	s := &Server{
		log:      discardLogger(),
		quit:     make(chan struct{}),
		maxConns: 0,
		conns:    make(map[net.Conn]struct{}),
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.listener = ln
	go s.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	status, err := ReadHandshakeResponse(conn)
	if err != nil {
		t.Fatalf("an over-limit connection must get a handshake response, not a bare EOF: %v", err)
	}
	if status != HandshakeServerBusy {
		t.Errorf("status = 0x%02X, want HandshakeServerBusy (0x%02X)", status, HandshakeServerBusy)
	}
}

// TestServer_BusyRejectionDoesNotBlockAccepts guards the decision to write the
// rejection inline on the accept loop: a client that never reads its response
// must not stall the acceptance of other connections.
func TestServer_BusyRejectionDoesNotBlockAccepts(t *testing.T) {
	s := &Server{
		log:      discardLogger(),
		quit:     make(chan struct{}),
		maxConns: 0,
		conns:    make(map[net.Conn]struct{}),
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.listener = ln
	go s.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })

	addr := ln.Addr().String()

	// Several connections that are opened and never read from.
	for range 5 {
		c, dialErr := net.DialTimeout("tcp", addr, 2*time.Second)
		if dialErr != nil {
			t.Fatalf("dial: %v", dialErr)
		}
		defer func() { _ = c.Close() }()
	}

	// A later connection must still be served promptly.
	done := make(chan error, 1)
	go func() {
		c, dialErr := net.DialTimeout("tcp", addr, 2*time.Second)
		if dialErr != nil {
			done <- dialErr
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, readErr := ReadHandshakeResponse(c)
		done <- readErr
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a later connection was not served: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the accept loop stalled behind unread busy rejections")
	}
}
