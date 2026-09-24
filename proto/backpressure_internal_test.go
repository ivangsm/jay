package proto

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/internal/ratelimit"
	"github.com/ivangsm/jay/meta"
)

// What a refused frame costs the server, measured in bytes it actually pulled
// off the socket — not in what the handler "consumed", which would miss the
// bufio layer underneath.

// countingConn counts every byte the server reads from the socket.
type countingConn struct {
	net.Conn
	read atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

// tcpPair is a real loopback TCP connection: net.Pipe has no buffers, so a
// server answering while the peer is still mid-body would deadlock on it
// instead of behaving like a socket.
func tcpPair(t *testing.T) (client net.Conn, server *countingConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sc := <-accepted
	if sc == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = client.Close(); _ = sc.Close() })
	return client, &countingConn{Conn: sc}
}

// rateLimitedHandler serves a token whose request budget is already spent, so
// its next frame is refused by the limiter.
func rateLimitedHandler(t *testing.T, conn net.Conn) *connHandler {
	t.Helper()
	lim := ratelimit.New(ratelimit.Config{Rate: 0.001, Burst: 1})
	t.Cleanup(lim.Stop)
	if !lim.Allow("tok") {
		t.Fatal("the first request must be admitted")
	}
	return &connHandler{
		auth:     auth.New(nil),
		log:      discardLogger(),
		token:    &meta.Token{TokenID: "tok", AccountID: "acc", AllowedActions: meta.AllActions, Status: "active"},
		conn:     conn,
		br:       bufio.NewReaderSize(conn, 64*1024),
		bw:       bufio.NewWriterSize(conn, 64*1024),
		limiter:  lim,
		limitKey: "tok",
	}
}

// readAnswer reads one response frame and returns its status and error code.
func readAnswer(t *testing.T, r io.Reader) (status byte, streamID uint32, code string) {
	t.Helper()
	status, streamID, metaLen, dataLen, err := ReadHeader(r)
	if err != nil {
		t.Fatalf("read answer header: %v", err)
	}
	if dataLen != 0 {
		t.Fatalf("an error answer carries no body, got data_len %d", dataLen)
	}
	m := make([]byte, metaLen)
	if _, err := io.ReadFull(r, m); err != nil {
		t.Fatalf("read answer meta: %v", err)
	}
	_, code, err = DecodeError(m)
	if err != nil {
		t.Fatalf("decode answer: %v", err)
	}
	return status, streamID, code
}

// TestRateLimited_FrameUpToTheBoundIsDrainedAndTheConnectionKept: a refused
// frame whose body is at most RateLimitDrainSize is read out and answered,
// and the stream stays aligned — proven by a second frame on the same
// connection being parsed as a frame.
//
// The bound is on the body alone, the rule the clients that predate it were
// built against: a body of exactly RateLimitDrainSize plus its metadata is
// still drained, where holding meta_len + data_len against the bound would
// have closed on it. 1.5 MiB is the size that used to be refused unread.
func TestRateLimited_FrameUpToTheBoundIsDrainedAndTheConnectionKept(t *testing.T) {
	for _, bodyLen := range []int{100 << 10, 3 << 19, RateLimitDrainSize} {
		t.Run(strconv.Itoa(bodyLen), func(t *testing.T) {
			client, server := tcpPair(t)
			h := rateLimitedHandler(t, server)

			meta, err := EncodePutObjectRequest("b", "k", "application/octet-stream", nil, false)
			if err != nil {
				t.Fatal(err)
			}
			body := bytes.Repeat([]byte("x"), bodyLen)

			go func() {
				_ = WriteFrame(client, OpPutObject, 11, meta, bytes.NewReader(body), int64(len(body)))
				_ = WriteFrame(client, OpPing, 12, nil, nil, 0)
			}()

			for _, wantStream := range []uint32{11, 12} {
				if err := h.handleOneRequest(); err != nil {
					t.Fatalf("stream %d: a refused %d-byte body must keep the connection, got %v", wantStream, bodyLen, err)
				}
				_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
				status, streamID, code := readAnswer(t, client)
				if status != StatusBadRequest || code != "RateLimitExceeded" || streamID != wantStream {
					t.Fatalf("answer = (0x%02X, stream %d, %q), want (BadRequest, stream %d, RateLimitExceeded)",
						status, streamID, code, wantStream)
				}
			}

			wantRead := int64(2*HeaderSize + len(meta) + len(body))
			if got := server.read.Load(); got != wantRead {
				t.Fatalf("server read %d bytes, want exactly the two frames (%d)", got, wantRead)
			}
		})
	}
}

// TestRateLimited_LargeFrameIsAnsweredWithoutReadingItsBody: a refused body
// past RateLimitDrainSize is not drained. The server reads at most one buffer
// fill past the header, answers, and closes on purpose — and the peer, whose
// write fails when the close lands, still finds the answer waiting. One byte
// over the bound is enough.
func TestRateLimited_LargeFrameIsAnsweredWithoutReadingItsBody(t *testing.T) {
	client, server := tcpPair(t)
	h := rateLimitedHandler(t, server)

	meta, err := EncodePutObjectRequest("b", "k", "application/octet-stream", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	const bodyLen = RateLimitDrainSize + 1
	body := bytes.Repeat([]byte("x"), bodyLen)

	writeErr := make(chan error, 1)
	go func() {
		writeErr <- WriteFrame(client, OpPutObject, 21, meta, bytes.NewReader(body), bodyLen)
	}()

	err = h.handleOneRequest()
	if !errors.Is(err, errClosedAfterAnswer) {
		t.Fatalf("a refused frame larger than RateLimitDrainSize must close on purpose, got %v", err)
	}
	_ = server.Close()

	// One bufio fill is the most the server may have pulled in: the header
	// arrives with whatever else fit in the same read.
	t.Logf("server read %d bytes of a refused %d-byte frame", server.read.Load(), HeaderSize+len(meta)+bodyLen)
	if got, most := server.read.Load(), int64(64<<10); got > most {
		t.Fatalf("server read %d bytes of a refused %d-byte frame, want at most one buffer (%d)",
			got, HeaderSize+len(meta)+bodyLen, most)
	}

	select {
	case err := <-writeErr:
		if err == nil {
			t.Fatal("the peer finished writing a body nobody read: the server did not close")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the peer's write never ended: the server neither read nor closed")
	}

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	status, streamID, code := readAnswer(t, client)
	if status != StatusBadRequest || code != "RateLimitExceeded" || streamID != 21 {
		t.Fatalf("answer = (0x%02X, stream %d, %q), want (BadRequest, stream 21, RateLimitExceeded)", status, streamID, code)
	}
}

// TestRateLimited_OversizedMetaIsNotDrained: the refusal path used to drain
// meta_len without checking it, so a refused frame declaring 4 GiB of
// metadata was read to the end. It gets the same treatment an admitted one
// does: the connection closes.
func TestRateLimited_OversizedMetaIsNotDrained(t *testing.T) {
	client, server := tcpPair(t)
	h := rateLimitedHandler(t, server)

	go func() {
		_ = WriteHeader(client, OpPutObject, 1, MaxMetaSize+1, 0)
		_, _ = client.Write(bytes.Repeat([]byte("m"), 256<<10))
	}()

	if err := h.handleOneRequest(); err == nil {
		t.Fatal("a refused frame with meta_len above MaxMetaSize must close the connection")
	}
	if got := server.read.Load(); got > 64<<10 {
		t.Fatalf("server read %d bytes of an oversized meta block, want at most one buffer", got)
	}
}

// TestWaitBytes_MovesTheDeadlineByTheWait: the body deadline measures the
// peer's throughput (1 MB/s floor). Time the server spends holding bytes back
// for the throughput cap is not the peer being slow, so every wait pushes the
// deadline back by exactly its length — otherwise a cap below the floor would
// make the server time out its own client.
func TestWaitBytes_MovesTheDeadlineByTheWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const bps = 64 << 10 // the burst floor, so one burst is one second
		h := &connHandler{
			throughput: ratelimit.NewThroughput(bps),
			waitCtx:    context.Background(),
			limitKey:   "tok",
		}

		deadline := time.Now().Add(30 * time.Second)
		var armed []time.Time
		set := func(d time.Time) error { armed = append(armed, d); return nil }

		// Within the burst: no wait, and the deadline is left alone.
		if err := h.waitBytes(bps, &deadline, set); err != nil {
			t.Fatal(err)
		}
		if len(armed) != 0 {
			t.Fatalf("a wait that took no time re-armed the deadline %d times", len(armed))
		}

		// Past it: one second of waiting, one second more of deadline.
		want := deadline.Add(time.Second)
		if err := h.waitBytes(bps, &deadline, set); err != nil {
			t.Fatal(err)
		}
		if len(armed) != 1 || !armed[0].Equal(want) || !deadline.Equal(want) {
			t.Fatalf("after a 1s wait: armed %v, deadline %v, want both at %v", armed, deadline, want)
		}
	})
}

// TestWaitBytes_ShutdownEndsTheWait: a body parked in the limiter when
// Shutdown gives up must fail, not stay parked holding its goroutine.
func TestWaitBytes_ShutdownEndsTheWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		h := &connHandler{
			throughput: ratelimit.NewThroughput(64 << 10),
			waitCtx:    ctx,
			limitKey:   "tok",
		}
		deadline := time.Now()
		set := func(time.Time) error { return nil }
		if err := h.waitBytes(64<<10, &deadline, set); err != nil {
			t.Fatal(err)
		}

		done := make(chan error, 1)
		go func() { done <- h.waitBytes(64<<10, &deadline, set) }()
		synctest.Wait()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("a wait cut short by shutdown returned %v, want context.Canceled", err)
		}
	})
}

// TestUnexpectedBodyIsDrainedNotParsed: an operation that takes no body, sent
// with one, used to leave that body in the stream, where the next ReadHeader
// parsed it as a frame header. It is drained like any refused body, and the
// frame after it is read from its real boundary.
func TestUnexpectedBodyIsDrainedNotParsed(t *testing.T) {
	client, server := tcpPair(t)
	h := &connHandler{
		log:      discardLogger(),
		token:    &meta.Token{TokenID: "tok", AccountID: "acc", AllowedActions: meta.AllActions, Status: "active"},
		conn:     server,
		br:       bufio.NewReaderSize(server, 64*1024),
		bw:       bufio.NewWriterSize(server, 64*1024),
		limiter:  ratelimit.New(ratelimit.Config{}),
		limitKey: "tok",
	}

	// A Ping carrying a 100 KiB body that looks like garbage headers, then a
	// clean Ping.
	junk := bytes.Repeat([]byte{0xEE}, 100<<10)
	go func() {
		_ = WriteFrame(client, OpPing, 1, nil, bytes.NewReader(junk), int64(len(junk)))
		_ = WriteFrame(client, OpPing, 2, nil, nil, 0)
	}()

	for _, want := range []uint32{1, 2} {
		if err := h.handleOneRequest(); err != nil {
			t.Fatalf("frame %d: %v", want, err)
		}
		_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
		status, streamID, _, _, err := ReadHeader(client)
		if err != nil {
			t.Fatal(err)
		}
		if status != StatusOK || streamID != want {
			t.Fatalf("answer = (0x%02X, stream %d), want (OK, stream %d)", status, streamID, want)
		}
	}
}
