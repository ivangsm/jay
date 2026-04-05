package client

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/ivangsm/jay/proto"
)

// Client is a Jay native protocol client with connection pooling.
type Client struct {
	addr    string
	tokenID string
	secret  string
	pool    chan *conn
	mu      sync.Mutex
	closed  bool
}

type conn struct {
	nc net.Conn
	br *bufio.Reader
	bw *bufio.Writer
}

// Dial creates a new client and establishes the initial connection pool.
func Dial(addr, tokenID, secret string, poolSize int) (*Client, error) {
	if poolSize <= 0 {
		poolSize = 4
	}
	c := &Client{
		addr:    addr,
		tokenID: tokenID,
		secret:  secret,
		pool:    make(chan *conn, poolSize),
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
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()

	close(c.pool)
	for cn := range c.pool {
		cn.nc.Close()
	}
	return nil
}

func (c *Client) getConn() (*conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("jay client: client is closed")
	}
	c.mu.Unlock()

	// Try to get a pooled connection
	select {
	case cn := <-c.pool:
		if cn != nil {
			return cn, nil
		}
	default:
	}
	// Create new connection
	return c.newConn()
}

func (c *Client) putConn(cn *conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		cn.nc.Close()
		return
	}
	select {
	case c.pool <- cn:
	default:
		cn.nc.Close()
	}
}

func (c *Client) dropConn(cn *conn) {
	cn.nc.Close()
}

func (c *Client) newConn() (*conn, error) {
	nc, err := net.Dial("tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("jay client: dial: %w", err)
	}

	br := bufio.NewReaderSize(nc, 64*1024)
	bw := bufio.NewWriterSize(nc, 64*1024)

	// Handshake
	credentials := c.tokenID + ":" + c.secret
	if err := proto.WriteHandshake(bw, credentials); err != nil {
		nc.Close()
		return nil, fmt.Errorf("jay client: write handshake: %w", err)
	}
	if err := bw.Flush(); err != nil {
		nc.Close()
		return nil, fmt.Errorf("jay client: flush handshake: %w", err)
	}

	status, err := proto.ReadHandshakeResponse(br)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jay client: read handshake response: %w", err)
	}
	if status != proto.HandshakeOK {
		nc.Close()
		switch status {
		case proto.HandshakeAuthFailed:
			return nil, fmt.Errorf("jay client: authentication failed")
		case proto.HandshakeVersionMismatch:
			return nil, fmt.Errorf("jay client: protocol version mismatch")
		default:
			return nil, fmt.Errorf("jay client: handshake failed with status %d", status)
		}
	}

	return &conn{nc: nc, br: br, bw: bw}, nil
}

// doRequest sends a request and reads the response. For requests without data payload.
func (c *Client) doRequest(op byte, meta []byte) (status byte, respMeta []byte, err error) {
	cn, err := c.getConn()
	if err != nil {
		return 0, nil, err
	}

	if err := proto.WriteFrame(cn.bw, op, 0, meta, nil, 0); err != nil {
		c.dropConn(cn)
		return 0, nil, fmt.Errorf("write request: %w", err)
	}
	if err := cn.bw.Flush(); err != nil {
		c.dropConn(cn)
		return 0, nil, fmt.Errorf("flush request: %w", err)
	}

	status, _, metaLen, dataLen, err := proto.ReadHeader(cn.br)
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

// doRequestWithData sends a request with a data payload.
func (c *Client) doRequestWithData(op byte, meta []byte, data io.Reader, dataLen int64) (status byte, respMeta []byte, err error) {
	cn, err := c.getConn()
	if err != nil {
		return 0, nil, err
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
	cn, err := c.getConn()
	if err != nil {
		return 0, nil, nil, 0, err
	}

	if err := proto.WriteFrame(cn.bw, op, 0, meta, nil, 0); err != nil {
		c.dropConn(cn)
		return 0, nil, nil, 0, fmt.Errorf("write request: %w", err)
	}
	if err := cn.bw.Flush(); err != nil {
		c.dropConn(cn)
		return 0, nil, nil, 0, fmt.Errorf("flush request: %w", err)
	}

	status, _, metaLen, dataLen, err := proto.ReadHeader(cn.br)
	if err != nil {
		c.dropConn(cn)
		return 0, nil, nil, 0, fmt.Errorf("read response header: %w", err)
	}

	if metaLen > proto.MaxMetaSize {
		c.dropConn(cn)
		return 0, nil, nil, 0, fmt.Errorf("response metadata too large: %d", metaLen)
	}
	if metaLen > 0 {
		respMeta = make([]byte, metaLen)
		if _, err := io.ReadFull(cn.br, respMeta); err != nil {
			c.dropConn(cn)
			return 0, nil, nil, 0, fmt.Errorf("read response meta: %w", err)
		}
	}

	if dataLen > 0 {
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
	return fmt.Sprintf("jay: %s", e.Message)
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
