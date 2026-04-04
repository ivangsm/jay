package proto

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
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
}

// NewServer creates a new native protocol server.
func NewServer(db *meta.DB, st *store.Store, au *auth.Auth, log *slog.Logger) *Server {
	return &Server{
		db:    db,
		store: st,
		auth:  au,
		log:   log,
		quit:  make(chan struct{}),
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
	s.listener.Close()
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
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
}

func (s *Server) handleConn(nc net.Conn) {
	defer nc.Close()

	br := bufio.NewReaderSize(nc, 64*1024)
	bw := bufio.NewWriterSize(nc, 64*1024)

	// Handshake
	credentials, err := ReadHandshake(br)
	if err != nil {
		s.log.Debug("handshake read error", "err", err, "remote", nc.RemoteAddr())
		WriteHandshakeResponse(bw, HandshakeVersionMismatch)
		bw.Flush()
		return
	}

	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		WriteHandshakeResponse(bw, HandshakeAuthFailed)
		bw.Flush()
		return
	}

	token, err := s.auth.AuthenticateCredentials(parts[0], parts[1])
	if err != nil {
		WriteHandshakeResponse(bw, HandshakeAuthFailed)
		bw.Flush()
		return
	}

	if err := WriteHandshakeResponse(bw, HandshakeOK); err != nil {
		return
	}
	if err := bw.Flush(); err != nil {
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

	return h.bw.Flush()
}

type request struct {
	op       byte
	streamID uint32
	meta     json.RawMessage
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
