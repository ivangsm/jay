package proto

import (
	"bufio"
	"crypto/tls"
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
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

const (
	defaultMaxConns     = 1000
	handshakeTimeout    = 10 * time.Second
	idleTimeout         = 60 * time.Second
	minDataReadTimeout  = 30 * time.Second
	dataReadBytesPerSec = 1 << 20 // 1 MB/s minimum expected throughput

	// Write-side mirror of the read throughput policy. A client that stops
	// reading its response would otherwise block the handler goroutine
	// indefinitely in io.Copy / Flush, pinning an fd and a maxConns slot.
	minDataWriteTimeout  = 30 * time.Second
	dataWriteBytesPerSec = 1 << 20 // 1 MB/s minimum expected throughput

	// shutdownGrace is how long Shutdown waits for in-flight requests to
	// finish on their own before force-closing the remaining connections.
	shutdownGrace = 5 * time.Second

	// busyRejectTimeout bounds the 8-byte "server busy" handshake reply that
	// the accept loop writes before dropping an over-limit connection.
	busyRejectTimeout = 2 * time.Second
)

// Server is the native TCP protocol server.
//
// Rate limiting uses a token-bucket algorithm with per-token buckets.
// rateLimit is requests per second; rateBurst is the bucket capacity.
// rateLimit <= 0 disables the limiter entirely.
type Server struct {
	db       *meta.DB
	store    *store.Store
	auth     *auth.Auth
	objops   *objops.Service
	log      *slog.Logger
	metrics  *maintenance.Metrics
	listener net.Listener
	wg       sync.WaitGroup
	quit     chan struct{}
	maxConns int
	active   atomic.Int64

	// tlsConfig, when set, wraps the listener. Nil means the transport is in
	// the clear — see SetTLSConfig.
	tlsConfig *tls.Config

	// conns tracks live connections so Shutdown can force-close them when
	// they don't drain within shutdownGrace (they only observe quit between
	// requests, and an idle conn can sit in ReadHeader for up to 60s).
	connMu       sync.Mutex
	conns        map[net.Conn]struct{}
	closing      bool
	shutdownOnce sync.Once

	limiter *ratelimit.Limiter
}

// NewServer creates a new native protocol server.
//
// rateLimit is requests per second per connection key; rateBurst is the
// token-bucket capacity. rateLimit <= 0 disables the limiter entirely.
// Pre-existing callers pass (100, 200) from config; those defaults are
// preserved by internal/ratelimit.New when Burst <= 0.
func NewServer(db *meta.DB, st *store.Store, au *auth.Auth, log *slog.Logger, metrics *maintenance.Metrics, rateLimit, rateBurst int) *Server {
	return &Server{
		db:       db,
		store:    st,
		auth:     au,
		objops:   objops.New(db, st, log),
		log:      log,
		metrics:  metrics,
		quit:     make(chan struct{}),
		maxConns: defaultMaxConns,
		conns:    make(map[net.Conn]struct{}),
		limiter: ratelimit.New(ratelimit.Config{
			Rate:  float64(rateLimit),
			Burst: rateBurst,
		}),
	}
}

// SetMaxObjectSize caps the size of a single PutObject/UploadPart body.
// 0 means unlimited. Must be called before ListenAndServe. The HTTP handler
// owns a separate objops.Service and is configured through its own setter.
func (s *Server) SetMaxObjectSize(n int64) {
	s.objops.SetMaxObjectSize(n)
}

// SetTLSConfig wraps the native listener in TLS. Must be called before
// ListenAndServe; a nil config leaves the transport in the clear.
//
// The handshake carries "token_id:secret" as plain bytes, so without this the
// credential is readable by anything on the path. That is tolerable on a
// container network and nowhere else.
//
// This costs the sendfile(2) fast path on GetObject: TLS has to see every byte,
// so the kernel can no longer splice a file straight to the socket. It is the
// reason TLS here is opt-in rather than the default.
func (s *Server) SetTLSConfig(cfg *tls.Config) {
	s.tlsConfig = cfg
}

// ListenAndServe starts the TCP server on the given address.
// Returns a shutdown function.
func (s *Server) ListenAndServe(addr string) (func() error, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("proto: listen: %w", err)
	}
	if s.tlsConfig != nil {
		ln = tls.NewListener(ln, s.tlsConfig)
	}
	s.listener = ln
	s.log.Info("native server listening", "addr", addr, "tls", s.tlsConfig != nil)

	go s.acceptLoop()

	return s.Shutdown, nil
}

// Shutdown gracefully stops the server. It closes the listener, gives
// in-flight connections shutdownGrace to finish on their own, then
// force-closes whatever is still alive so shutdown time is bounded (a
// connection blocked in ReadHeader only re-checks quit between requests and
// could otherwise hold shutdown for the full 60s idle deadline).
// Idempotent: subsequent calls return immediately.
func (s *Server) Shutdown() error {
	s.shutdownOnce.Do(func() {
		close(s.quit)
		if err := s.listener.Close(); err != nil {
			s.log.Debug("close listener", "err", err)
		}

		done := make(chan struct{})
		go func() {
			s.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(shutdownGrace):
			s.connMu.Lock()
			s.closing = true
			for c := range s.conns {
				_ = c.Close()
			}
			s.connMu.Unlock()
			<-done
		}

		s.limiter.Stop()
	})
	return nil
}

// trackConn registers an accepted connection for Shutdown's force-close
// sweep. Returns false when the sweep already ran — the caller must close
// the connection and bail instead of serving it.
func (s *Server) trackConn(c net.Conn) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.closing {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrackConn(c net.Conn) {
	s.connMu.Lock()
	delete(s.conns, c)
	s.connMu.Unlock()
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
			s.rejectBusy(conn)
			continue
		}

		if !s.trackConn(conn) {
			_ = conn.Close()
			continue
		}
		s.active.Add(1)
		s.wg.Go(func() {
			defer s.active.Add(-1)
			defer s.untrackConn(conn)
			s.handleConn(conn)
		})
	}
}

// rejectBusy tells a client that the server is at its connection limit and
// closes. It runs inline on the accept loop on purpose: the response is the
// 8 fixed bytes of a handshake reply on a freshly accepted socket, which fit
// in the kernel send buffer without blocking. The short deadline is the belt
// that makes "without blocking" a guarantee rather than an expectation, so a
// pathological peer cannot stall accepts.
//
// The client never sent its handshake at this point — we answer before
// reading — which is fine: the reply is self-describing and the client is
// waiting on exactly these bytes after its own write.
func (s *Server) rejectBusy(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	if err := conn.SetWriteDeadline(time.Now().Add(busyRejectTimeout)); err != nil {
		return
	}
	if err := WriteHandshakeResponse(conn, HandshakeServerBusy); err != nil {
		s.log.Debug("write busy handshake response", "err", err, "remote", conn.RemoteAddr())
	}
}

// handshakeRejection maps a ReadHandshake failure onto the status byte the
// client deserves. The io.EOF case returns false: there is nobody left to
// answer, and writing into a dead socket only produces a second error to log.
func handshakeRejection(err error) (status byte, respond bool) {
	switch {
	case errors.Is(err, ErrHandshakeVersion):
		return HandshakeVersionMismatch, true
	case errors.Is(err, ErrHandshakeMagic):
		return HandshakeMalformed, true
	case errors.Is(err, ErrHandshakeCredentials):
		return HandshakeAuthFailed, true
	default:
		// Torn socket, timeout, truncated read. Not a protocol disagreement.
		return 0, false
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
		if status, respond := handshakeRejection(err); respond {
			_ = WriteHandshakeResponse(bw, status)
			_ = bw.Flush()
		}
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

	limitKey := token.TokenID

	h := &connHandler{
		db:       s.db,
		store:    s.store,
		auth:     s.auth,
		objops:   s.objops,
		log:      s.log,
		metrics:  s.metrics,
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
			if !errors.Is(err, io.EOF) && !isConnClosed(err) {
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
	metrics  *maintenance.Metrics
	token    *meta.Token
	conn     net.Conn
	br       *bufio.Reader
	bw       *bufio.Writer
	sourceIP string

	limiter  *ratelimit.Limiter
	limitKey string
}

// authorizeBucketAccess is the cross-account gate of the native protocol: the
// counterpart of api.Handler.authorizeBucketAccess, and the same decision
// function underneath.
//
// Object put/get/head/delete reach it through objops; everything that resolves
// a bucket here without going through objops — list, multipart, and the bucket
// metadata operations — calls it directly. A token whose account does not own
// the bucket is refused unless the bucket says otherwise (public-read for
// reads, or an explicit allow statement in its policy).
func (h *connHandler) authorizeBucketAccess(bucket *meta.Bucket, action, objectKey string) error {
	return auth.AuthorizeBucketAccess(h.token, bucket, action, objectKey, h.sourceIP)
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
		if wErr := h.writeResponseCombined(StatusBadRequest, streamID, errMeta); wErr != nil {
			return wErr
		}
		if err := h.bw.Flush(); err != nil {
			return err
		}
		return h.conn.SetWriteDeadline(time.Time{})
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
		timeout := max(time.Duration(dataLen/dataReadBytesPerSec+1)*time.Second, minDataReadTimeout)
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

	if err := h.bw.Flush(); err != nil {
		return err
	}
	// Clear the write deadline armed by the response writers so it cannot
	// leak into the next request's response.
	if err := h.conn.SetWriteDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear write deadline: %w", err)
	}
	return nil
}

type request struct {
	op       byte
	streamID uint32
	meta     []byte
	data     io.Reader
	dataLen  int64
}

// armWriteDeadline sets a write deadline scaled by the response payload size:
// max(minDataWriteTimeout, payload at dataWriteBytesPerSec + 1s). Every
// response writer must call it before touching the connection; the deadline
// is cleared after the final flush in handleOneRequest.
func (h *connHandler) armWriteDeadline(payloadLen int64) error {
	timeout := max(time.Duration(payloadLen/dataWriteBytesPerSec+1)*time.Second, minDataWriteTimeout)
	return h.conn.SetWriteDeadline(time.Now().Add(timeout))
}

func (h *connHandler) writeResponse(status byte, streamID uint32, meta []byte, data io.Reader, dataLen int64) error {
	if err := h.armWriteDeadline(int64(len(meta)) + dataLen); err != nil {
		return err
	}
	return WriteFrame(h.bw, status, streamID, meta, data, dataLen)
}

func isConnClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}
	if opErr, ok := errors.AsType[*net.OpError](err); ok {
		return errors.Is(opErr.Err, syscall.ECONNRESET) || errors.Is(opErr.Err, syscall.EPIPE)
	}
	return false
}
