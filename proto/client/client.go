package client

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ivangsm/jay/proto"
)

const (
	// dialTimeout bounds both the TCP connect and the handshake exchange so a
	// hung server can never block a caller indefinitely.
	dialTimeout = 10 * time.Second

	// minOpTimeout and opBytesPerSec mirror the server's minDataReadTimeout /
	// dataReadBytesPerSec sizing (proto/server.go) so both sides agree on the
	// slowest acceptable transfer: at least minOpTimeout, scaled at 1 MB/s.
	minOpTimeout   = 30 * time.Second
	opBytesPerSec  = 1 << 20 // 1 MB/s minimum expected throughput
	opTimeoutSlack = 5 * time.Second

	// maxConnIdle is how long a pooled connection may sit unused before it is
	// discarded instead of reused. Deliberately below the server's 60s idle
	// timeout (proto/server.go idleTimeout): anything close to that limit is
	// likely already dead on arrival.
	maxConnIdle = 45 * time.Second
)

// opTimeout returns the deadline duration for an operation that transfers
// dataLen payload bytes, plus a fixed slack for the round-trip.
func opTimeout(dataLen int64) time.Duration {
	t := max(time.Duration(dataLen/opBytesPerSec)*time.Second+opTimeoutSlack, minOpTimeout)
	return t
}

// Client is a Jay native protocol client with connection pooling.
type Client struct {
	addr    string
	tokenID string
	secret  string
	pool    chan *conn
	mu      sync.Mutex
	closed  bool

	// tlsConfig, when set, dials TLS instead of plain TCP.
	tlsConfig *tls.Config
}

// Options configures a Client beyond the four positional arguments of Dial.
// The zero value matches Dial's behaviour exactly.
type Options struct {
	// PoolSize is the number of pooled connections. Zero means 4.
	PoolSize int

	// TLSConfig, when non-nil, dials TLS. The handshake sends
	// "token_id:secret" as plain bytes, so without this the credential is
	// readable by anything on the network path — acceptable on a container
	// network and nowhere else.
	//
	// The server must be configured to match (JAY_NATIVE_TLS_CERT /
	// JAY_NATIVE_TLS_KEY). There is no negotiation: a TLS client against a
	// plaintext listener fails its handshake, and so does the reverse. That is
	// deliberate — a protocol that fell back to plaintext when TLS did not work
	// would make the encryption unverifiable from the client's side.
	TLSConfig *tls.Config
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

// Dial creates a new client and establishes the initial connection pool over
// plain TCP. For TLS, use DialWithOptions.
func Dial(addr, tokenID, secret string, poolSize int) (*Client, error) {
	return DialWithOptions(addr, tokenID, secret, Options{PoolSize: poolSize})
}

// DialWithOptions creates a new client with explicit options.
func DialWithOptions(addr, tokenID, secret string, opts Options) (*Client, error) {
	poolSize := opts.PoolSize
	if poolSize <= 0 {
		poolSize = 4
	}
	c := &Client{
		addr:      addr,
		tokenID:   tokenID,
		secret:    secret,
		pool:      make(chan *conn, poolSize),
		tlsConfig: opts.TLSConfig,
	}
	// Pre-connect one connection to validate credentials
	cn, err := c.newConn()
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
func (c *Client) getConn() (cn *conn, pooled bool, err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, false, errors.New("jay client: client is closed")
	}
	c.mu.Unlock()

	for {
		select {
		case cn := <-c.pool:
			if cn == nil {
				// Pool channel was closed by Close.
				return nil, false, errors.New("jay client: client is closed")
			}
			if time.Since(cn.lastUsed) > maxConnIdle {
				_ = cn.nc.Close()
				continue
			}
			return cn, true, nil
		default:
			cn, err := c.newConn()
			return cn, false, err
		}
	}
}

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
// bounded by the same dialTimeout as the TCP connect, so a server that accepts
// the socket and then stalls the handshake cannot hang the caller either.
func (c *Client) dial() (net.Conn, error) {
	d := &net.Dialer{Timeout: dialTimeout}
	if c.tlsConfig == nil {
		return d.Dial("tcp", c.addr)
	}
	return tls.DialWithDialer(d, "tcp", c.addr, c.tlsConfig)
}

func (c *Client) newConn() (*conn, error) {
	nc, err := c.dial()
	if err != nil {
		return nil, fmt.Errorf("jay client: dial: %w", err)
	}

	br := bufio.NewReaderSize(nc, 64*1024)
	bw := bufio.NewWriterSize(nc, 64*1024)

	// Handshake, bounded by its own deadline (mirrors the server's
	// handshakeTimeout) so a wedged server cannot hang the caller.
	if err := nc.SetDeadline(time.Now().Add(dialTimeout)); err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("jay client: set handshake deadline: %w", err)
	}

	credentials := c.tokenID + ":" + c.secret
	if err := proto.WriteHandshake(bw, credentials); err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("jay client: write handshake: %w", err)
	}
	if err := bw.Flush(); err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("jay client: flush handshake: %w", err)
	}

	status, err := proto.ReadHandshakeResponse(br)
	if err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("jay client: read handshake response: %w", err)
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

// sendAndReadMeta writes a bodyless request frame and reads the response
// header plus metadata. On error the connection is dropped. retryable reports
// whether the failure happened before any part of the response was consumed,
// i.e. it is safe to replay the request on a fresh connection.
func (c *Client) sendAndReadMeta(cn *conn, op byte, meta []byte) (status byte, respMeta []byte, dataLen int64, retryable bool, err error) {
	if err := cn.nc.SetDeadline(time.Now().Add(opTimeout(0))); err != nil {
		c.dropConn(cn)
		return 0, nil, 0, true, fmt.Errorf("set deadline: %w", err)
	}

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
func (c *Client) sendWithRetry(op byte, meta []byte) (cn *conn, status byte, respMeta []byte, dataLen int64, err error) {
	cn, pooled, err := c.getConn()
	if err != nil {
		return nil, 0, nil, 0, err
	}

	status, respMeta, dataLen, retryable, err := c.sendAndReadMeta(cn, op, meta)
	if err == nil {
		return cn, status, respMeta, dataLen, nil
	}
	if !pooled || !retryable {
		return nil, 0, nil, 0, err
	}

	// The connection is already dropped by sendAndReadMeta; retry on a new one.
	cn, err = c.newConn()
	if err != nil {
		return nil, 0, nil, 0, err
	}
	status, respMeta, dataLen, _, err = c.sendAndReadMeta(cn, op, meta)
	if err != nil {
		return nil, 0, nil, 0, err
	}
	return cn, status, respMeta, dataLen, nil
}

// doRequest sends a request and reads the response. For requests without data payload.
func (c *Client) doRequest(op byte, meta []byte) (status byte, respMeta []byte, err error) {
	cn, status, respMeta, dataLen, err := c.sendWithRetry(op, meta)
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
func (c *Client) doRequestWithData(op byte, meta []byte, data io.Reader, dataLen int64) (status byte, respMeta []byte, err error) {
	cn, _, err := c.getConn()
	if err != nil {
		return 0, nil, err
	}

	// Scale the deadline with the upload size, mirroring the server's data
	// read timeout so a slow-but-progressing transfer is not cut off.
	if err := cn.nc.SetDeadline(time.Now().Add(opTimeout(dataLen))); err != nil {
		c.dropConn(cn)
		return 0, nil, fmt.Errorf("set deadline: %w", err)
	}

	if err := proto.WriteFrame(cn.bw, op, 0, meta, data, dataLen); err != nil {
		c.dropConn(cn)
		return 0, nil, fmt.Errorf("write request: %w", err)
	}
	if err := cn.bw.Flush(); err != nil {
		c.dropConn(cn)
		return 0, nil, fmt.Errorf("flush request: %w", err)
	}

	status, _, metaLen, respDataLen, err := proto.ReadHeader(cn.br)
	if err != nil {
		c.dropConn(cn)
		return 0, nil, fmt.Errorf("read response header: %w", err)
	}

	if metaLen > proto.MaxMetaSize {
		c.dropConn(cn)
		return 0, nil, fmt.Errorf("response metadata too large: %d", metaLen)
	}
	if metaLen > 0 {
		respMeta = make([]byte, metaLen)
		if _, err := io.ReadFull(cn.br, respMeta); err != nil {
			c.dropConn(cn)
			return 0, nil, fmt.Errorf("read response meta: %w", err)
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
func (c *Client) doRequestWithDataResponse(op byte, meta []byte) (status byte, respMeta []byte, dataReader io.ReadCloser, dataLen int64, err error) {
	cn, status, respMeta, dataLen, err := c.sendWithRetry(op, meta)
	if err != nil {
		return 0, nil, nil, 0, err
	}

	if dataLen > 0 {
		// Extend the read deadline to cover the full body: the caller streams
		// it after this function returns, so the per-request deadline set
		// before the write would fire mid-download on large objects. putConn
		// clears this deadline when the reader is closed.
		if err := cn.nc.SetReadDeadline(time.Now().Add(opTimeout(dataLen))); err != nil {
			c.dropConn(cn)
			return 0, nil, nil, 0, fmt.Errorf("set body read deadline: %w", err)
		}
		reader := &connReader{
			r:      io.LimitReader(cn.br, dataLen),
			cn:     cn,
			client: c,
			remain: dataLen,
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
}

func (cr *connReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.remain -= int64(n)
	return n, err
}

func (cr *connReader) Close() error {
	if cr.closed {
		return nil
	}
	cr.closed = true
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
