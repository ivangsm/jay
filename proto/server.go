package proto

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

const (
	defaultMaxConns      = 1000
	handshakeTimeout     = 10 * time.Second
	idleTimeout          = 60 * time.Second
	minDataReadTimeout   = 30 * time.Second
	dataReadBytesPerSec  = 1 << 20 // 1MB/s minimum expected throughput
)

// Server is the native TCP protocol server.
type Server struct {
	db       *meta.DB
	store    *store.Store
	auth     *auth.Auth
	log      *slog.Logger
	listener net.Listener
	wg       sync.WaitGroup
	quit     chan struct{}
	maxConns int
	active   atomic.Int64
}

// NewServer creates a new native protocol server.
func NewServer(db *meta.DB, st *store.Store, au *auth.Auth, log *slog.Logger) *Server {
	return &Server{
		db:       db,
		store:    st,
		auth:     au,
		log:      log,
		quit:     make(chan struct{}),
		maxConns: defaultMaxConns,
	}
}

// ListenAndServe starts the TCP server on the given address.
// Returns a shutdown function.
func (s *Server) ListenAndServe(addr string) (func() error, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("proto: listen: %w", err)
	}
	s.listener = ln
	s.log.Info("native server listening", "addr", addr)

	go s.acceptLoop()

	return s.Shutdown, nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown() error {
	close(s.quit)
	if err := s.listener.Close(); err != nil {
		s.log.Debug("close listener", "err", err)
	}
	s.wg.Wait()
	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				s.log.Error("accept error", "err", err)
				continue
			}
		}

		if int(s.active.Load()) >= s.maxConns {
			s.log.Warn("connection limit reached, rejecting", "remote", conn.RemoteAddr())
			_ = conn.Close()
			continue
		}

		s.active.Add(1)
		s.wg.Go(func() {
			defer s.active.Add(-1)
			s.handleConn(conn)
		})
	}
}

func (s *Server) handleConn(nc net.Conn) {
	defer func() { _ = nc.Close() }()

	br := bufio.NewReaderSize(nc, 64*1024)
	bw := bufio.NewWriterSize(nc, 64*1024)

	// Set handshake deadline
	if err := nc.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		s.log.Debug("set handshake deadline", "err", err, "remote", nc.RemoteAddr())
		return
	}

	// Handshake
	credentials, err := ReadHandshake(br)
	if err != nil {
		s.log.Debug("handshake read error", "err", err, "remote", nc.RemoteAddr())
		_ = WriteHandshakeResponse(bw, HandshakeVersionMismatch)
		_ = bw.Flush()
		return
	}

	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		_ = WriteHandshakeResponse(bw, HandshakeAuthFailed)
		_ = bw.Flush()
		return
	}

	token, err := s.auth.AuthenticateCredentials(parts[0], parts[1])
	if err != nil {
		_ = WriteHandshakeResponse(bw, HandshakeAuthFailed)
		_ = bw.Flush()
		return
	}

	if err := WriteHandshakeResponse(bw, HandshakeOK); err != nil {
		return
	}
	if err := bw.Flush(); err != nil {
		return
	}

	// Clear handshake deadline
	if err := nc.SetDeadline(time.Time{}); err != nil {
		s.log.Debug("clear handshake deadline", "err", err, "remote", nc.RemoteAddr())
		return
	}

	// Connection handler
	h := &connHandler{
		db:    s.db,
		store: s.store,
		auth:  s.auth,
		log:   s.log,
		token: token,
		conn:  nc,
		br:    br,
		bw:    bw,
	}

	// Request loop
	for {
		select {
		case <-s.quit:
			return
		default:
		}

		// Set idle timeout before waiting for next request header
		if err := nc.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			s.log.Debug("set read deadline", "err", err, "remote", nc.RemoteAddr())
			return
		}

		if err := h.handleOneRequest(); err != nil {
			if err != io.EOF && !isConnClosed(err) {
				s.log.Debug("connection error", "err", err, "remote", nc.RemoteAddr())
			}
			return
		}
	}
}

// connHandler handles requests on a single authenticated connection.
type connHandler struct {
	db    *meta.DB
	store *store.Store
	auth  *auth.Auth
	log   *slog.Logger
	token *meta.Token
	conn  net.Conn
	br    *bufio.Reader
	bw    *bufio.Writer
}

func (h *connHandler) handleOneRequest() error {
	op, streamID, metaLen, dataLen, err := ReadHeader(h.br)
	if err != nil {
		return err
	}

	// Clear the idle deadline now that we have a request header
	if err := h.conn.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear idle deadline: %w", err)
	}

	// Read metadata payload
	var metaPayload []byte
	if metaLen > 0 {
		if metaLen > MaxMetaSize {
			return fmt.Errorf("metadata too large: %d", metaLen)
		}
		metaPayload = make([]byte, metaLen)
		if _, err := io.ReadFull(h.br, metaPayload); err != nil {
			return fmt.Errorf("read meta: %w", err)
		}
	}

	// Data reader (for PutObject)
	var dataReader io.Reader
	if dataLen > 0 {
		// Set a read deadline proportional to data size (minimum 30s)
		timeout := time.Duration(dataLen/dataReadBytesPerSec+1) * time.Second
		if timeout < minDataReadTimeout {
			timeout = minDataReadTimeout
		}
		if err := h.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return fmt.Errorf("set data read deadline: %w", err)
		}
		dataReader = io.LimitReader(h.br, dataLen)
	}

	req := &request{
		op:       op,
		streamID: streamID,
		meta:     metaPayload,
		data:     dataReader,
		dataLen:  dataLen,
	}

	if err := h.dispatch(req); err != nil {
		return err
	}

	// Clear data read deadline after request is handled
	if err := h.conn.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear data read deadline: %w", err)
	}

	return h.bw.Flush()
}

type request struct {
	op       byte
	streamID uint32
	meta     []byte
	data     io.Reader
	dataLen  int64
}

func (h *connHandler) writeResponse(status byte, streamID uint32, meta []byte, data io.Reader, dataLen int64) error {
	return WriteFrame(h.bw, status, streamID, meta, data, dataLen)
}

func isConnClosed(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "broken pipe")
}
