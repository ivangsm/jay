package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ivangsm/jay/proto"
)

// Back-pressure knobs seen from the client: the connection cap and what a
// client is told when it hits it.

func withMaxConns(n int) func(*proto.Server) {
	return func(s *proto.Server) { s.SetMaxConns(n) }
}

// TestMaxConns_RefusesOnePastTheCapAndFreesTheSlot opens N connections under a
// cap of N, proves the N+1st is refused with ErrServerBusy — the typed error,
// not an EOF — and that closing one of the N gives its slot back.
func TestMaxConns_RefusesOnePastTheCapAndFreesTheSlot(t *testing.T) {
	const capConns = 3
	env := startNativeServer(t, nil, withMaxConns(capConns))
	ctx := context.Background()

	held := make([]*Client, 0, capConns)
	for i := range capConns {
		c, err := Dial(ctx, env.addr, env.tokenID, env.secret, WithPoolSize(1))
		if err != nil {
			t.Fatalf("connection %d of %d must be accepted: %v", i+1, capConns, err)
		}
		held = append(held, c)
	}
	t.Cleanup(func() {
		for _, c := range held {
			_ = c.Close()
		}
	})

	_, err := Dial(ctx, env.addr, env.tokenID, env.secret, WithPoolSize(1))
	if !errors.Is(err, ErrServerBusy) {
		t.Fatalf("connection %d under a cap of %d: got %v, want ErrServerBusy", capConns+1, capConns, err)
	}

	// Every held client still works: the refusal did not cost anyone else.
	for i, c := range held {
		if err := c.Ping(ctx); err != nil {
			t.Fatalf("held connection %d stopped working after a refusal: %v", i+1, err)
		}
	}

	// Closing one frees its slot. The server notices the close on its next
	// read, so the slot comes back shortly after, not synchronously.
	_ = held[0].Close()
	held = held[1:]

	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := Dial(ctx, env.addr, env.tokenID, env.secret, WithPoolSize(1))
		if err == nil {
			if pingErr := c.Ping(ctx); pingErr != nil {
				t.Fatalf("the connection that took the freed slot does not work: %v", pingErr)
			}
			_ = c.Close()
			return
		}
		if !errors.Is(err, ErrServerBusy) {
			t.Fatalf("waiting for the freed slot: got %v, want ErrServerBusy or success", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("closing a connection never gave its slot back")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestMaxConns_BusyStatusSurvivesRepeatedRefusals dials the real client against
// a full server many times over real TCP. Every attempt must end in
// ErrServerBusy: a reset that ate the status would surface as a transport
// error, and a single one fails the test.
func TestMaxConns_BusyStatusSurvivesRepeatedRefusals(t *testing.T) {
	env := startNativeServer(t, nil, withMaxConns(1))
	ctx := context.Background()

	holder, err := Dial(ctx, env.addr, env.tokenID, env.secret, WithPoolSize(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Close() })

	for i := range 200 {
		_, err := Dial(ctx, env.addr, env.tokenID, env.secret, WithPoolSize(1))
		if !errors.Is(err, ErrServerBusy) {
			t.Fatalf("attempt %d: got %v, want ErrServerBusy", i+1, err)
		}
	}
}

// TestMaxConns_SilentTLSPeerDoesNotStallRefusals: over TLS, answering "busy"
// means completing a TLS handshake first, which needs the peer's ClientHello.
// A peer that connects and never sends one must not be able to hold up the
// refusal of everybody after it — which is what happened while the refusal
// ran inline on the accept loop with only a write deadline.
func TestMaxConns_SilentTLSPeerDoesNotStallRefusals(t *testing.T) {
	cert, pool := selfSignedCert(t)
	env := startNativeServer(t,
		&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		withMaxConns(1))
	clientTLS := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	ctx := context.Background()

	holder, err := Dial(ctx, env.addr, env.tokenID, env.secret, WithTLS(clientTLS), WithPoolSize(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Close() })

	// Connects, then says nothing: no ClientHello ever arrives.
	silent, err := net.Dial("tcp", env.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = silent.Close() })

	// Give the accept loop time to pick the silent peer up first.
	time.Sleep(100 * time.Millisecond)

	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	start := time.Now()
	_, err = Dial(dialCtx, env.addr, env.tokenID, env.secret, WithTLS(clientTLS), WithPoolSize(1))
	if !errors.Is(err, ErrServerBusy) {
		t.Fatalf("a TLS client behind a silent peer: got %v after %v, want ErrServerBusy", err, time.Since(start))
	}
}

// scriptedServer accepts connections one at a time and hands each to the next
// script in line, after answering its handshake with OK. It is how a test gets
// a server to do exactly one thing the real one only does under load.
func scriptedServer(t *testing.T, scripts ...func(br *bufio.Reader, c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for _, script := range scripts {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			br := bufio.NewReader(c)
			if _, err := proto.ReadHandshake(br); err != nil {
				_ = c.Close()
				return
			}
			if err := proto.WriteHandshakeResponse(c, proto.HandshakeOK); err != nil {
				_ = c.Close()
				return
			}
			script(br, c)
		}
		// Out of scripts: refuse further dials at once instead of letting
		// them sit in the backlog until the client's handshake timeout.
		_ = ln.Close()
	}()
	return ln.Addr().String()
}

// readFrame consumes one whole request frame.
func readFrame(br *bufio.Reader) error {
	_, _, metaLen, dataLen, err := proto.ReadHeader(br)
	if err != nil {
		return err
	}
	_, err = io.CopyN(io.Discard, br, int64(metaLen)+dataLen)
	return err
}

// TestPool_DropsAConnectionTheServerClosedAfterAnAnswer covers the case a
// server produces when the body happens to fit in the socket buffers: the
// client's write completes, it reads a perfectly normal error answer, and the
// server closes right after. Nothing on the wire says so. The client must
// infer it from the sizes the reference fixes, or the next upload on its
// one-connection pool goes into a dead socket.
//
// The rate-limited case is a server at the floor the reference allows for
// RateLimitDrainSize (MaxMetaSize), closing on a body one byte over it. The
// reference server drains more than that today, only for older clients; a
// client that trusted today's value would pool this dead connection the day
// the server comes down to the floor.
func TestPool_DropsAConnectionTheServerClosedAfterAnAnswer(t *testing.T) {
	cases := []struct {
		name string
		size int
		code string
	}{
		{"rate limited past the MaxMetaSize floor", proto.MaxMetaSize + 1, "RateLimitExceeded"},
		{"refused past MaxDrainSize", proto.MaxDrainSize + 1, "NoSuchBucket"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refuseThenClose := func(br *bufio.Reader, c net.Conn) {
				defer func() { _ = c.Close() }()
				// Reads the whole frame so the client's write completes,
				// then answers and closes — the worst case for the pool.
				if readFrame(br) != nil {
					return
				}
				_ = proto.WriteFrameCombined(c, proto.StatusBadRequest, 0, proto.EncodeError("refused", tc.code))
			}
			serveOK := func(br *bufio.Reader, c net.Conn) {
				defer func() { _ = c.Close() }()
				for readFrame(br) == nil {
					resp, _ := proto.EncodePutResponse("etag", "checksum")
					if proto.WriteFrameCombined(c, proto.StatusOK, 0, resp) != nil {
						return
					}
				}
			}
			addr := scriptedServer(t, refuseThenClose, serveOK)

			c, err := Dial(context.Background(), addr, "tok", "sec", WithPoolSize(1))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			ctx := context.Background()

			body := make([]byte, tc.size)
			_, err = c.PutObject(ctx, "bkt", "big", bytes.NewReader(body), int64(len(body)), nil)
			if e, ok := errors.AsType[*Error](err); !ok || e.Code != tc.code {
				t.Fatalf("got %v, want the server's %s", err, tc.code)
			}

			if _, err := c.PutObject(ctx, "bkt", "small", bytes.NewReader([]byte("ok")), 2, nil); err != nil {
				t.Fatalf("the next upload went into the connection the server closed: %v", err)
			}
		})
	}
}

// TestPool_KeepsAConnectionAfterASmallRefusal is the other side of the same
// rule: a rate-limited body up to MaxMetaSize is drained by any server, so the
// client must keep the connection. The scripted server only accepts once; a
// client that dropped the connection would find nobody to dial.
func TestPool_KeepsAConnectionAfterASmallRefusal(t *testing.T) {
	answers := 0
	refuseOnceThenServe := func(br *bufio.Reader, c net.Conn) {
		defer func() { _ = c.Close() }()
		for readFrame(br) == nil {
			answers++
			if answers == 1 {
				_ = proto.WriteFrameCombined(c, proto.StatusBadRequest, 0, proto.EncodeError("slow down", "RateLimitExceeded"))
				continue
			}
			resp, _ := proto.EncodePutResponse("etag", "checksum")
			if proto.WriteFrameCombined(c, proto.StatusOK, 0, resp) != nil {
				return
			}
		}
	}
	addr := scriptedServer(t, refuseOnceThenServe)

	c, err := Dial(context.Background(), addr, "tok", "sec", WithPoolSize(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	ctx := context.Background()

	body := make([]byte, proto.MaxMetaSize)
	_, err = c.PutObject(ctx, "bkt", "k", bytes.NewReader(body), int64(len(body)), nil)
	if e, ok := errors.AsType[*Error](err); !ok || e.Code != "RateLimitExceeded" {
		t.Fatalf("got %v, want RateLimitExceeded", err)
	}
	if _, err := c.PutObject(ctx, "bkt", "k", bytes.NewReader([]byte("ok")), 2, nil); err != nil {
		t.Fatalf("a connection the server kept was dropped (or broken): %v", err)
	}
}
