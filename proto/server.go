package proto

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/internal/objops"
	"github.com/ivangsm/jay/internal/ratelimit"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

const (
	defaultMaxConns     = 1000
	handshakeTimeout    = 10 * time.Second
	idleTimeout         = 60 * time.Second
	minDataReadTimeout  = 30 * time.Second
	dataReadBytesPerSec = 1 << 20 // 1 MB/s minimum expected throughput
)

// Server is the native TCP protocol server.
//
// Rate limiting uses the same token-bucket implementation as the HTTP API
// (see internal/ratelimit). The previous implementation was a sliding window
// that stored rateBurst but never consulted it — burst is now actually
// enforced and both transports share one limiter type.
type Server struct {
	db       *meta.DB
	store    *store.Store
	auth     *auth.Auth
	objops   *objops.Service
	log      *slog.Logger
	listener net.Listener
	wg       sync.WaitGroup
	quit     chan struct{}
	maxConns int
	active   atomic.Int64

	limiter *ratelimit.Limiter
}

// NewServer creates a new native protocol server.
//
// rateLimit is requests per second per connection key; rateBurst is the
// token-bucket capacity. rateLimit <= 0 disables the limiter entirely.
// Pre-existing callers pass (100, 200) from config; those defaults are
// preserved by internal/ratelimit.New when Burst <= 0.
func NewServer(db *meta.DB, st *store.Store, au *auth.Auth, log *slog.Logger, rateLimit, rateBurst int) *Server {
	return &Server{
		db:       db,
		store:    st,
		auth:     au,
		objops:   objops.New(db, st, log),
		log:      log,
		quit:     make(chan struct{}),
		maxConns: defaultMaxConns,
		limiter: ratelimit.New(ratelimit.Config{
			Rate:  float64(rateLimit),
			Burst: rateBurst,
		}),
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
	s.limiter.Stop()
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

	// Handshake deadline
	if err := nc.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		s.log.Debug("set handshake deadline", "err", err, "remote", nc.RemoteAddr())
		return
	}

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

	if err := nc.SetDeadline(time.Time{}); err != nil {
		s.log.Debug("clear handshake deadline", "err", err, "remote", nc.RemoteAddr())
		return
	}

	// Derive a source IP from RemoteAddr. The native protocol has no proxy
	// headers — whatever connects to :4012 IS the client, full stop. No
	// TrustProxyHeaders knob applies here.
	sourceIP := ""
	if host, _, splitErr := net.SplitHostPort(nc.RemoteAddr().String()); splitErr == nil {
		sourceIP = host
	}

	// Limiter key mixes token ID + remote addr so two concurrent connections
	// from the same token share the same bucket only when they come from the
	// same peer. This is the intended behaviour: one caller, one bucket.
	limitKey := token.TokenID + "@" + nc.RemoteAddr().String()

	h := &connHandler{
		db:       s.db,
		store:    s.store,
		auth:     s.auth,
		objops:   s.objops,
		log:      s.log,
		token:    token,
		conn:     nc,
		br:       br,
		bw:       bw,
		sourceIP: sourceIP,
		limiter:  s.limiter,
		limitKey: limitKey,
	}

	for {
		select {
		case <-s.quit:
			return
		default:
		}

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
//
// sourceIP is computed once at handshake and passed into every Identity built
// from this connection so bucket-policy evaluators see the real TCP peer.
type connHandler struct {
	db       *meta.DB
	store    *store.Store
	auth     *auth.Auth
	objops   *objops.Service
	log      *slog.Logger
	token    *meta.Token
	conn     net.Conn
	br       *bufio.Reader
	bw       *bufio.Writer
	sourceIP string

	limiter  *ratelimit.Limiter
	limitKey string
}

// identity builds an objops.Identity for the given action. Called once per
// operation so the Action field is always set correctly (it changes per op).
func (h *connHandler) identity(action string) objops.Identity {
	return objops.Identity{
		TokenID:   h.token.TokenID,
		AccountID: h.token.AccountID,
		SourceIP:  h.sourceIP,
		Action:    action,
	}
}

func (h *connHandler) handleOneRequest() error {
	op, streamID, metaLen, dataLen, err := ReadHeader(h.br)
	if err != nil {
		return err
	}

	// Shared token-bucket rate limit. If the limiter rejects, we must still
	// drain this frame's meta + data so the connection remains usable for
	// subsequent requests (up to MaxDrainSize — beyond that the caller is
	// either abusive or the stream is desynced; either way drop the conn).
	if !h.limiter.Allow(h.limitKey) {
		if metaLen > 0 {
			if _, err := io.CopyN(io.Discard, h.br, int64(metaLen)); err != nil {
				return err
			}
		}
		if dataLen > 0 {
			if dataLen > MaxDrainSize {
				return fmt.Errorf("rate limit + oversized frame: %d > %d", dataLen, MaxDrainSize)
			}
			if _, err := io.CopyN(io.Discard, h.br, dataLen); err != nil {
				return err
			}
		}
		errMeta := EncodeError("rate limit exceeded", "RateLimitExceeded")
		if wErr := WriteFrameCombined(h.bw, StatusBadRequest, streamID, errMeta); wErr != nil {
			return wErr
		}
		return h.bw.Flush()
	}

	// Clear the idle deadline now that we have a request header.
	if err := h.conn.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear idle deadline: %w", err)
	}

	// Read metadata payload.
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

	// Data reader (for PutObject / UploadPart).
	var dataReader io.Reader
	if dataLen > 0 {
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
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return errors.Is(opErr.Err, syscall.ECONNRESET) || errors.Is(opErr.Err, syscall.EPIPE)
	}
	return false
}
