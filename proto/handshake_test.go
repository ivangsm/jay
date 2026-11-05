package proto

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// Tests for the handshake's diagnosis: a cut socket, a wrong port and a full
// server each get their own status, never a blanket "version mismatch".

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

// newFullServer is a server whose every connection is over the limit: a
// maxConns of zero rejects in the accept loop, before anything touches the
// database — which is why these tests need no store. SetMaxConns refuses zero,
// so the literal is the only way to build one.
func newFullServer() *Server {
	return &Server{
		log:       discardLogger(),
		quit:      make(chan struct{}),
		maxConns:  0,
		conns:     make(map[net.Conn]struct{}),
		busySlots: make(chan struct{}, maxBusyRejections),
	}
}

// TestServer_RejectsWithServerBusy: at the connection limit the server writes
// a status before closing, so a client can tell a full server from a dead one.
func TestServer_RejectsWithServerBusy(t *testing.T) {
	s := newFullServer()

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

// TestServer_BusyRejectionDoesNotBlockAccepts: a client that never reads its
// response, and never hangs up, must not stall the acceptance of other
// connections.
func TestServer_BusyRejectionDoesNotBlockAccepts(t *testing.T) {
	s := newFullServer()

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

// TestServer_BusyRejectionClosesWithoutReset is the worst case for the busy
// status: the client's handshake is already sitting unread in the server's
// receive buffer when the server answers. Closing a socket with unread data
// makes the kernel send a reset, and a TCP stack that discards received data
// on a reset loses the status. The server must instead half-close, read the
// handshake out and let the client hang up first — so the client reads the
// status and then a clean EOF, never ECONNRESET.
//
// The client reads only after a pause, so the server has long finished with
// the connection by then: a reset, if one was sent, has already arrived.
func TestServer_BusyRejectionClosesWithoutReset(t *testing.T) {
	s := newFullServer()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.listener = ln
	go s.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })

	// Below maxBusyRejections, so every connection gets a slot and the
	// saturation fallback (a bare close, on purpose) never kicks in.
	const clients = maxBusyRejections / 2
	results := make(chan error, clients)
	for range clients {
		go func() {
			results <- func() error {
				c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
				if err != nil {
					return err
				}
				defer func() { _ = c.Close() }()
				if err := WriteHandshake(c, "tok:sec"); err != nil {
					return err
				}
				time.Sleep(100 * time.Millisecond)
				if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
					return err
				}
				status, err := ReadHandshakeResponse(c)
				if err != nil {
					return fmt.Errorf("read status: %w", err)
				}
				if status != HandshakeServerBusy {
					return fmt.Errorf("status = 0x%02X, want HandshakeServerBusy", status)
				}
				var one [1]byte
				if _, err := c.Read(one[:]); !errors.Is(err, io.EOF) {
					return fmt.Errorf("after the status: got %v, want a clean EOF (a reset means the close raced the unread handshake)", err)
				}
				return nil
			}()
		}()
	}
	for range clients {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
}

// TestServer_BusyRefusalsAreBounded pins the documented degradation: with
// maxBusyRejections refusals already in flight — here, peers that neither
// read nor hang up, so each holds its slot for busyRejectTimeout — the next
// over-limit connection is closed without a status. And the bound is a bound
// in time too: once those refusals time out, statuses come back.
func TestServer_BusyRefusalsAreBounded(t *testing.T) {
	s := newFullServer()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.listener = ln
	go s.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	addr := ln.Addr().String()

	for range maxBusyRejections {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}
	// Let the accept loop hand every one of them a slot.
	deadline := time.Now().Add(2 * time.Second)
	for len(s.busySlots) < maxBusyRejections && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(s.busySlots) != maxBusyRejections {
		t.Fatalf("%d refusals in flight, want %d", len(s.busySlots), maxBusyRejections)
	}

	extra, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = extra.Close() }()
	_ = extra.SetReadDeadline(time.Now().Add(busyRejectTimeout / 2))
	if _, err := ReadHandshakeResponse(extra); !errors.Is(err, io.EOF) {
		t.Fatalf("past the refusal bound: got %v, want a bare close (EOF) before the slots free up", err)
	}

	// After busyRejectTimeout the silent peers are cut loose and the slots
	// come back.
	time.Sleep(busyRejectTimeout + 200*time.Millisecond)
	later, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = later.Close() }()
	_ = later.SetReadDeadline(time.Now().Add(2 * time.Second))
	if status, err := ReadHandshakeResponse(later); err != nil || status != HandshakeServerBusy {
		t.Fatalf("after the bound drained: status 0x%02X, err %v; want ServerBusy", status, err)
	}
}
