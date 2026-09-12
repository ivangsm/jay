// Package client is the Go client for jay's native binary protocol.
//
// It is what falco talks to. Connections are pooled and long-lived: the point of
// the native protocol is to avoid paying HTTP's framing and header cost on every
// object read.
//
// Every operation takes a context.Context. Its deadline caps the per-operation
// deadline the client derives from the transfer size, and cancelling it aborts
// the operation in flight: the connection it was using is closed, because a
// frame abandoned halfway leaves the stream unaligned and the protocol has no
// cancel message (see the reference: "Cancellation and half-close").
package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/ivangsm/jay/proto"
)

// Timeouts are the client's per-operation bounds. The zero value of each field
// means the default, which mirrors the server's own sizing so both ends agree
// on the slowest acceptable transfer.
type Timeouts struct {
	// Dial bounds the TCP connect and the handshake exchange together, so a
	// hung server can never block a caller indefinitely. Default 10s.
	Dial time.Duration

	// MinOperation is the floor of every operation deadline. Default 30s.
	MinOperation time.Duration

	// BytesPerSec is the throughput a transfer is expected to sustain; the
	// deadline for an operation carrying n bytes is n/BytesPerSec plus a
	// fixed slack, never below MinOperation. Default 1 MiB/s, which is the
	// server's dataReadBytesPerSec (proto/server.go).
	BytesPerSec int64

	// Slack is added to every size-scaled deadline for the round trip.
	// Default 5s.
	Slack time.Duration
}

const (
	defaultDialTimeout    = 10 * time.Second
	defaultMinOpTimeout   = 30 * time.Second
	defaultOpBytesPerSec  = 1 << 20
	defaultOpTimeoutSlack = 5 * time.Second
	defaultPoolSize       = 4

	// maxConnIdle is how long a pooled connection may sit unused before it is
	// discarded instead of reused. Deliberately below the server's 60s idle
	// timeout (proto/server.go idleTimeout): anything close to that limit is
	// likely already dead on arrival.
	maxConnIdle = 45 * time.Second

	// presignRegion is the credential-scope region written into presigned
	// URLs. jay has no regions: the verifier reads whatever the URL says back
	// out of X-Amz-Credential, so any value works as long as the URL is
	// internally consistent. us-east-1 is what S3 clients default to.
	presignRegion = "us-east-1"
)

func (t Timeouts) withDefaults() Timeouts {
	if t.Dial <= 0 {
		t.Dial = defaultDialTimeout
	}
	if t.MinOperation <= 0 {
		t.MinOperation = defaultMinOpTimeout
	}
	if t.BytesPerSec <= 0 {
		t.BytesPerSec = defaultOpBytesPerSec
	}
	if t.Slack <= 0 {
		t.Slack = defaultOpTimeoutSlack
	}
	return t
}

// op returns the deadline duration for an operation that transfers dataLen
// payload bytes.
func (t Timeouts) op(dataLen int64) time.Duration {
	return max(time.Duration(dataLen/t.BytesPerSec)*time.Second+t.Slack, t.MinOperation)
}

// Option configures a Client at Dial time.
type Option func(*Client)

// WithPoolSize sets how many idle connections the client keeps. It bounds the
// cache, not the concurrency: a burst of callers beyond it opens extra
// connections that are closed when returned. Zero or negative keeps 4.
func WithPoolSize(n int) Option {
	return func(c *Client) {
		if n > 0 {
			c.poolSize = n
		}
	}
}

// WithTLS dials TLS instead of plain TCP. The handshake sends
// "token_id:secret" as plain bytes, so without this the credential is readable
// by anything on the network path — acceptable on a container network and
// nowhere else.
//
// The server must be configured to match (JAY_NATIVE_TLS_CERT /
// JAY_NATIVE_TLS_KEY). There is no negotiation: a TLS client against a
// plaintext listener fails its handshake, and so does the reverse. That is
// deliberate — a protocol that fell back to plaintext when TLS did not work
// would make the encryption unverifiable from the client's side.
func WithTLS(cfg *tls.Config) Option {
	return func(c *Client) { c.tlsConfig = cfg }
}

// WithLogger sets where the client reports what it does on its own: the
// pooled connection it discarded as stale, the request it replayed on a fresh
// one. Nothing is logged by default.
func WithLogger(log *slog.Logger) Option {
	return func(c *Client) {
		if log != nil {
			c.log = log
		}
	}
}

// WithTimeouts overrides the per-operation deadlines. See Timeouts for what
// each field bounds and what the defaults mirror.
func WithTimeouts(t Timeouts) Option {
	return func(c *Client) { c.timeouts = t.withDefaults() }
}

// WithS3Endpoint names the S3-compatible HTTP listener of the same jay, as a
// scheme and host ("https://s3.example.com", "http://jay:9000"). It is what
// PresignURL signs against — the SigV4 signature covers the host, so a URL
// signed for any other host can never verify — and it is required only by
// PresignURL: every other operation goes over the native connection.
func WithS3Endpoint(endpoint string) Option {
	return func(c *Client) { c.s3Endpoint = endpoint }
}

// Client is a Jay native protocol client with connection pooling.
//
// It is safe for concurrent use. One operation occupies one connection for
// its whole duration (the protocol has no multiplexing), so concurrency comes
// from the pool plus whatever extra connections a burst opens.
type Client struct {
	addr     string
	tokenID  string
	secret   string
	poolSize int
	pool     chan *conn
	mu       sync.Mutex
	closed   bool

	tlsConfig  *tls.Config
	log        *slog.Logger
	timeouts   Timeouts
	s3Endpoint string
}

type conn struct {
	nc net.Conn
	br *bufio.Reader
	bw *bufio.Writer
	// lastUsed is when the connection was last returned to the pool (or
	// created). getConn uses it to discard connections that idled long enough
	// for the server to have closed them.
	lastUsed time.Time
}

// Dial creates a client and opens its first connection, which validates the
// credentials before Dial returns: a bad token fails here, not on the first
// operation. ctx bounds that first connection on top of Timeouts.Dial.
func Dial(ctx context.Context, addr, tokenID, secret string, opts ...Option) (*Client, error) {
	c := &Client{
		addr:     addr,
		tokenID:  tokenID,
		secret:   secret,
		poolSize: defaultPoolSize,
		log:      slog.New(slog.DiscardHandler),
		timeouts: Timeouts{}.withDefaults(),
	}
	for _, opt := range opts {
		opt(c)
	}
	c.pool = make(chan *conn, c.poolSize)

	cn, err := c.newConn(ctx)
	if err != nil {
		return nil, err
	}
	c.pool <- cn
	return c, nil
}

// Close closes all pooled connections and marks the client as closed.
// Safe to call more than once.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	close(c.pool)
	for cn := range c.pool {
		_ = cn.nc.Close()
	}
	return nil
}

// getConn returns a connection and whether it came from the pool. Pooled
// connections idle for longer than maxConnIdle are closed and skipped, since
// the server has likely already dropped them under its own idle timeout.
func (c *Client) getConn(ctx context.Context) (cn *conn, pooled bool, err error) {
	if err := ctx.Err(); err != nil {
		return nil, false, ctxError(ctx)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, false, errClientClosed
	}
	c.mu.Unlock()

	for {
		select {
		case cn := <-c.pool:
			if cn == nil {
				// Pool channel was closed by Close.
				return nil, false, errClientClosed
			}
			if time.Since(cn.lastUsed) > maxConnIdle {
				c.log.Debug("jay client: discarding idle pooled connection",
					"addr", c.addr, "idle", time.Since(cn.lastUsed))
				_ = cn.nc.Close()
				continue
			}
			return cn, true, nil
		default:
			cn, err := c.newConn(ctx)
			return cn, false, err
		}
	}
}

var errClientClosed = errors.New("jay client: client is closed")

func (c *Client) putConn(cn *conn) {
	// Clear per-operation deadlines so a stale deadline cannot fire on the
	// next request that reuses this connection.
	if err := cn.nc.SetDeadline(time.Time{}); err != nil {
		_ = cn.nc.Close()
		return
	}
	cn.lastUsed = time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		_ = cn.nc.Close()
		return
	}
	select {
	case c.pool <- cn:
	default:
		_ = cn.nc.Close()
	}
}

func (c *Client) dropConn(cn *conn) {
	_ = cn.nc.Close()
}

// dial opens the transport, with TLS when configured. The TLS handshake is
// bounded by the same dial timeout as the TCP connect, so a server that accepts
// the socket and then stalls the handshake cannot hang the caller either.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	d := &net.Dialer{Timeout: c.timeouts.Dial}
	if c.tlsConfig == nil {
		return d.DialContext(ctx, "tcp", c.addr)
	}
	td := &tls.Dialer{NetDialer: d, Config: c.tlsConfig}
	return td.DialContext(ctx, "tcp", c.addr)
}

func (c *Client) newConn(ctx context.Context) (*conn, error) {
	nc, err := c.dial(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctxError(ctx)
		}
		return nil, fmt.Errorf("jay client: dial: %w", err)
	}

	br := bufio.NewReaderSize(nc, 64*1024)
	bw := bufio.NewWriterSize(nc, 64*1024)

	// Handshake, bounded by its own deadline (mirrors the server's
	// handshakeTimeout) so a wedged server cannot hang the caller.
	if err := nc.SetDeadline(deadline(ctx, c.timeouts.Dial)); err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("jay client: set handshake deadline: %w", err)
	}
	stop := watchCancel(ctx, nc)
	defer stop()

	credentials := c.tokenID + ":" + c.secret
	if err := proto.WriteHandshake(bw, credentials); err != nil {
		_ = nc.Close()
		return nil, wrapCtx(ctx, fmt.Errorf("jay client: write handshake: %w", err))
	}
	if err := bw.Flush(); err != nil {
		_ = nc.Close()
		return nil, wrapCtx(ctx, fmt.Errorf("jay client: flush handshake: %w", err))
	}

	status, err := proto.ReadHandshakeResponse(br)
	if err != nil {
		_ = nc.Close()
		return nil, wrapCtx(ctx, fmt.Errorf("jay client: read handshake response: %w", err))
	}
	if status != proto.HandshakeOK {
		_ = nc.Close()
		return nil, handshakeError(status)
	}

	if err := nc.SetDeadline(time.Time{}); err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("jay client: clear handshake deadline: %w", err)
	}

	return &conn{nc: nc, br: br, bw: bw, lastUsed: time.Now()}, nil
}

// deadline is now+d, or the context's own deadline when that comes first.
func deadline(ctx context.Context, d time.Duration) time.Time {
	t := time.Now().Add(d)
	if cd, ok := ctx.Deadline(); ok && cd.Before(t) {
		return cd
	}
	return t
}

// watchCancel makes ctx's cancellation reach a blocking read or write on nc:
// the only lever a net.Conn offers is its deadline, so cancellation moves it
// to the past, which fails the pending I/O with a timeout the caller then
// reports as ctx.Err() (see wrapCtx). The returned stop must be called when
// the operation is over; a context that can never be cancelled costs nothing.
func watchCancel(ctx context.Context, nc net.Conn) (stop func()) {
	done := ctx.Done()
	if done == nil {
		return func() {}
	}
	finished := make(chan struct{})
	go func() {
		select {
		case <-done:
			_ = nc.SetDeadline(time.Now())
		case <-finished:
		}
	}()
	return sync.OnceFunc(func() { close(finished) })
}

// ctxError is the error an operation reports when its context ended: the
// context's own, wrapped so a caller can errors.Is it against
// context.Canceled / context.DeadlineExceeded.
func ctxError(ctx context.Context) error {
	return fmt.Errorf("jay client: %w", ctx.Err())
}

// wrapCtx replaces a transport error with the context's when the context is
// what ended the operation. "i/o timeout" is what the socket says; "context
// canceled" is what happened.
func wrapCtx(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctxError(ctx)
	}
	return err
}

// sendAndReadMeta writes a bodyless request frame and reads the response
// header plus metadata. On error the connection is dropped. retryable reports
// whether the failure happened before any part of the response was consumed,
// i.e. it is safe to replay the request on a fresh connection.
func (c *Client) sendAndReadMeta(ctx context.Context, cn *conn, op byte, meta []byte) (status byte, respMeta []byte, dataLen int64, retryable bool, err error) {
	if err := cn.nc.SetDeadline(deadline(ctx, c.timeouts.op(0))); err != nil {
		c.dropConn(cn)
		return 0, nil, 0, true, fmt.Errorf("set deadline: %w", err)
	}
	stop := watchCancel(ctx, cn.nc)
	defer stop()

	if err := proto.WriteFrame(cn.bw, op, 0, meta, nil, 0); err != nil {
		c.dropConn(cn)
		return 0, nil, 0, true, fmt.Errorf("write request: %w", err)
	}
	if err := cn.bw.Flush(); err != nil {
		c.dropConn(cn)
		return 0, nil, 0, true, fmt.Errorf("flush request: %w", err)
	}

	status, _, metaLen, dataLen, err := proto.ReadHeader(cn.br)
	if err != nil {
		c.dropConn(cn)
		return 0, nil, 0, true, fmt.Errorf("read response header: %w", err)
	}

	if metaLen > proto.MaxMetaSize {
		c.dropConn(cn)
		return 0, nil, 0, false, fmt.Errorf("response metadata too large: %d", metaLen)
	}
	if metaLen > 0 {
		respMeta = make([]byte, metaLen)
		if _, err := io.ReadFull(cn.br, respMeta); err != nil {
			c.dropConn(cn)
			return 0, nil, 0, false, fmt.Errorf("read response meta: %w", err)
		}
	}
	return status, respMeta, dataLen, false, nil
}

// sendWithRetry runs sendAndReadMeta and retries exactly once on a fresh
// connection if the pooled connection failed before any response byte was
// consumed. That failure mode is almost always the server's idle timeout
// having closed the connection while it sat in the pool. There remains a
// small window where the server processed the request but the connection died
// before the response arrived; all bodyless ops here are safe to replay in
// that case (worst case a Conflict/NotFound the caller would see anyway).
//
// A cancelled context is never retried: the failure was the caller's doing.
func (c *Client) sendWithRetry(ctx context.Context, op byte, meta []byte) (cn *conn, status byte, respMeta []byte, dataLen int64, err error) {
	cn, pooled, err := c.getConn(ctx)
	if err != nil {
		return nil, 0, nil, 0, err
	}

	status, respMeta, dataLen, retryable, err := c.sendAndReadMeta(ctx, cn, op, meta)
	if err == nil {
		return cn, status, respMeta, dataLen, nil
	}
	if ctx.Err() != nil {
		return nil, 0, nil, 0, ctxError(ctx)
	}
	if !pooled || !retryable {
		return nil, 0, nil, 0, err
	}

	// The connection is already dropped by sendAndReadMeta; retry on a new one.
	c.log.Debug("jay client: replaying request on a fresh connection",
		"addr", c.addr, "op", op, "err", err)
	cn, err = c.newConn(ctx)
	if err != nil {
		return nil, 0, nil, 0, err
	}
	status, respMeta, dataLen, _, err = c.sendAndReadMeta(ctx, cn, op, meta)
	if err != nil {
		return nil, 0, nil, 0, wrapCtx(ctx, err)
	}
	return cn, status, respMeta, dataLen, nil
}

// doRequest sends a request and reads the response. For requests without data payload.
func (c *Client) doRequest(ctx context.Context, op byte, meta []byte) (status byte, respMeta []byte, err error) {
	cn, status, respMeta, dataLen, err := c.sendWithRetry(ctx, op, meta)
	if err != nil {
		return 0, nil, err
	}

	// Drain any unexpected data
	if dataLen > 0 {
		if _, err := io.CopyN(io.Discard, cn.br, dataLen); err != nil {
			c.dropConn(cn)
			return status, respMeta, nil
		}
	}

	c.putConn(cn)
	return status, respMeta, nil
}

// doRequestWithData sends a request with a data payload (PutObject/UploadPart).
//
// Unlike doRequest/doRequestWithDataResponse, this path never retries on a
// dead pooled connection: the data io.Reader may have been partially consumed
// by the failed write and cannot be rewound to replay the request. Stale
// pooled connections are instead handled preventively by the idle discard in
// getConn, which keeps this window small.
func (c *Client) doRequestWithData(ctx context.Context, op byte, meta []byte, data io.Reader, dataLen int64) (status byte, respMeta []byte, err error) {
	cn, _, err := c.getConn(ctx)
	if err != nil {
		return 0, nil, err
	}

	// Scale the deadline with the upload size, mirroring the server's data
	// read timeout so a slow-but-progressing transfer is not cut off.
	if err := cn.nc.SetDeadline(deadline(ctx, c.timeouts.op(dataLen))); err != nil {
		c.dropConn(cn)
		return 0, nil, fmt.Errorf("set deadline: %w", err)
	}
	stop := watchCancel(ctx, cn.nc)
	defer stop()

	if err := proto.WriteFrame(cn.bw, op, 0, meta, data, dataLen); err != nil {
		c.dropConn(cn)
		return 0, nil, wrapCtx(ctx, fmt.Errorf("write request: %w", err))
	}
	if err := cn.bw.Flush(); err != nil {
		c.dropConn(cn)
		return 0, nil, wrapCtx(ctx, fmt.Errorf("flush request: %w", err))
	}

	status, _, metaLen, respDataLen, err := proto.ReadHeader(cn.br)
	if err != nil {
		c.dropConn(cn)
		return 0, nil, wrapCtx(ctx, fmt.Errorf("read response header: %w", err))
	}

	if metaLen > proto.MaxMetaSize {
		c.dropConn(cn)
		return 0, nil, fmt.Errorf("response metadata too large: %d", metaLen)
	}
	if metaLen > 0 {
		respMeta = make([]byte, metaLen)
		if _, err := io.ReadFull(cn.br, respMeta); err != nil {
			c.dropConn(cn)
			return 0, nil, wrapCtx(ctx, fmt.Errorf("read response meta: %w", err))
		}
	}

	if respDataLen > 0 {
		if _, err := io.CopyN(io.Discard, cn.br, respDataLen); err != nil {
			c.dropConn(cn)
			return status, respMeta, nil
		}
	}

	c.putConn(cn)
	return status, respMeta, nil
}

// doRequestWithDataResponse sends a request and returns a response with streaming data.
// The caller must call result.Close() when done reading.
func (c *Client) doRequestWithDataResponse(ctx context.Context, op byte, meta []byte) (status byte, respMeta []byte, dataReader io.ReadCloser, dataLen int64, err error) {
	cn, status, respMeta, dataLen, err := c.sendWithRetry(ctx, op, meta)
	if err != nil {
		return 0, nil, nil, 0, err
	}

	if dataLen > 0 {
		// Extend the read deadline to cover the full body: the caller streams
		// it after this function returns, so the per-request deadline set
		// before the write would fire mid-download on large objects. putConn
		// clears this deadline when the reader is closed.
		if err := cn.nc.SetReadDeadline(deadline(ctx, c.timeouts.op(dataLen))); err != nil {
			c.dropConn(cn)
			return 0, nil, nil, 0, fmt.Errorf("set body read deadline: %w", err)
		}
		reader := &connReader{
			r:      io.LimitReader(cn.br, dataLen),
			cn:     cn,
			client: c,
			remain: dataLen,
			ctx:    ctx,
			// The body outlives this call, so cancellation has to keep
			// watching until the reader is closed.
			stop: watchCancel(ctx, cn.nc),
		}
		return status, respMeta, reader, dataLen, nil
	}

	c.putConn(cn)
	return status, respMeta, nil, 0, nil
}

// connReader wraps a limited reader over a pooled connection.
// Closing it returns the connection to the pool.
// Not safe for concurrent use — a single GetObject result must be consumed by one goroutine.
type connReader struct {
	r      io.Reader
	cn     *conn
	client *Client
	remain int64
	closed bool
	ctx    context.Context
	stop   func()
}

func (cr *connReader) Read(p []byte) (int, error) {
	// Checked first, not only when the socket blocks: bytes the kernel already
	// buffered would otherwise keep flowing after the caller gave up, and
	// "cancelling fails the next Read" is the promise GetObject makes.
	if err := cr.ctx.Err(); err != nil {
		return 0, ctxError(cr.ctx)
	}
	n, err := cr.r.Read(p)
	cr.remain -= int64(n)
	if err != nil && !errors.Is(err, io.EOF) {
		err = wrapCtx(cr.ctx, err)
	}
	return n, err
}

// Close returns the connection to the pool after draining whatever the caller
// did not read. A cancelled context, or a drain that fails, drops the
// connection instead: its stream position is no longer known.
func (cr *connReader) Close() error {
	if cr.closed {
		return nil
	}
	cr.closed = true
	cr.stop()
	if cr.ctx.Err() != nil {
		cr.client.dropConn(cr.cn)
		return nil
	}
	if cr.remain > 0 {
		if _, err := io.CopyN(io.Discard, cr.r, cr.remain); err != nil {
			cr.client.dropConn(cr.cn)
			return nil
		}
	}
	cr.client.putConn(cr.cn)
	return nil
}

// Handshake failure sentinels, so a caller can branch on what went wrong
// instead of matching on message text. The distinction that matters in
// practice is retryability: ErrServerBusy is worth backing off and retrying,
// ErrAuthFailed and ErrVersionMismatch never are.
var (
	// ErrAuthFailed means the token was rejected, or the credentials were not
	// shaped as "token_id:secret".
	ErrAuthFailed = errors.New("jay client: authentication failed")

	// ErrVersionMismatch means the server does not speak this protocol version.
	ErrVersionMismatch = errors.New("jay client: protocol version mismatch")

	// ErrServerBusy means the server is at its connection limit. Retry with
	// backoff; the server is alive and the credentials were never examined.
	ErrServerBusy = errors.New("jay client: server at connection limit")

	// ErrMalformedHandshake means the server did not recognise our handshake
	// magic — in practice, something other than Jay is on that port.
	ErrMalformedHandshake = errors.New("jay client: server rejected handshake as malformed")
)

// handshakeError translates a non-OK handshake status into an error a caller
// can match. An unknown status is reported with its number rather than folded
// into one of the known ones: a future server may add statuses, and guessing
// which one it meant is how "version mismatch" came to mean everything.
func handshakeError(status byte) error {
	switch status {
	case proto.HandshakeAuthFailed:
		return ErrAuthFailed
	case proto.HandshakeVersionMismatch:
		return ErrVersionMismatch
	case proto.HandshakeServerBusy:
		return ErrServerBusy
	case proto.HandshakeMalformed:
		return ErrMalformedHandshake
	default:
		return fmt.Errorf("jay client: handshake failed with status %d", status)
	}
}

// Error represents a Jay protocol error.
type Error struct {
	Status  byte
	Message string
	Code    string
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("jay: %s (%s)", e.Message, e.Code)
	}
	return "jay: " + e.Message
}

// IsUnknownOp reports whether err is the server saying it does not implement
// the operation — what an older jay answers to GetObjectRange or CopyObject.
// The connection survives it; the caller can fall back to the operations v1
// defines (GetObject and read the slice, or Get + Put).
func IsUnknownOp(err error) bool {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Code == "UnknownOp"
	}
	return false
}

func checkError(status byte, meta []byte) error {
	if status == proto.StatusOK {
		return nil
	}
	e := &Error{Status: status}
	if len(meta) > 0 {
		msg, code, err := proto.DecodeError(meta)
		if err == nil {
			e.Message = msg
			e.Code = code
		}
	}
	if e.Message == "" {
		e.Message = "unknown error"
	}
	return e
}
