package proto

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
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

	// busyRejectTimeout bounds the whole refusal of an over-limit connection:
	// the TLS handshake when there is one, the 8-byte "server busy" reply, and
	// the wait for the client to close first. It is a read AND write deadline:
	// a TLS handshake reads the ClientHello before it can write anything.
	busyRejectTimeout = 2 * time.Second

	// maxBusyRejections bounds how many over-limit connections may be in the
	// middle of being refused at once. Each holds an fd and a goroutine for up
	// to busyRejectTimeout; without a bound, a flood past the connection cap
	// would cost exactly the resources the cap exists to protect. Past it,
	// the connection is closed without a status — see rejectBusy.
	maxBusyRejections = 64

	// maxHandshakeBytes is the largest handshake a client can send: the fixed
	// part plus a uint16-sized credential. rejectBusy reads at most this much
	// while it waits for the refused client to hang up.
	maxHandshakeBytes = HandshakeSize + 1<<16 - 1
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

	// throughput caps body bytes per second per token; nil means no cap. See
	// SetTokenBytesPerSec.
	throughput *ratelimit.Throughput

	// waitCtx is what a throttled body waits under. It is cancelled when
	// Shutdown gives up on in-flight requests, so a connection force-closed
	// mid-upload does not leave its goroutine parked in the limiter.
	waitCtx    context.Context
	cancelWait context.CancelFunc

	// busySlots bounds the refusals in flight; see maxBusyRejections.
	busySlots chan struct{}
}

// NewServer creates a new native protocol server.
//
// rateLimit is requests per second per token; rateBurst is the token-bucket
// capacity. rateLimit <= 0 disables the limiter entirely, and rateBurst <= 0
// takes internal/ratelimit.New's default. rateLimit is a float for the same
// reason JAY_RATE_LIMIT is: a rate below one request per second is a rate, and
// truncating 0.5 to an int turned it into "no limit" on this transport while
// the S3 API applied it.
func NewServer(db *meta.DB, st *store.Store, au *auth.Auth, log *slog.Logger, metrics *maintenance.Metrics, rateLimit float64, rateBurst int) *Server {
	waitCtx, cancelWait := context.WithCancel(context.Background())
	return &Server{
		db:        db,
		store:     st,
		auth:      au,
		objops:    objops.New(db, st, log),
		log:       log,
		metrics:   metrics,
		quit:      make(chan struct{}),
		maxConns:  defaultMaxConns,
		conns:     make(map[net.Conn]struct{}),
		busySlots: make(chan struct{}, maxBusyRejections),
		limiter: ratelimit.New(ratelimit.Config{
			Rate:  rateLimit,
			Burst: rateBurst,
		}),
		waitCtx:    waitCtx,
		cancelWait: cancelWait,
	}
}

// SetMaxObjectSize caps the size of a single PutObject/UploadPart body.
// 0 means unlimited. Must be called before ListenAndServe. The HTTP handler
// owns a separate objops.Service and is configured through its own setter.
func (s *Server) SetMaxObjectSize(n int64) {
	s.objops.SetMaxObjectSize(n)
}

// SetMaxConns caps how many connections the server holds at once, counting
// those still in their handshake. The connection past the cap is answered
// with HandshakeServerBusy and closed. Must be called before ListenAndServe.
//
// n must be positive: a cap of zero would refuse every client while the
// listener looks healthy, so a non-positive n is a programming error and
// panics, like time.NewTicker. The config layer rejects it before it gets here.
func (s *Server) SetMaxConns(n int) {
	if n <= 0 {
		panic(fmt.Sprintf("proto: SetMaxConns(%d): the connection cap must be positive", n))
	}
	s.maxConns = n
}

// SetTokenBytesPerSec caps the object bytes each token may move per second
// over this transport: request bodies read (PutObject, UploadPart) and
// response bodies written (GetObject, GetObjectRange), one budget for both
// directions, shared by all of the token's connections. 0 or less means no
// cap, which is the default. Must be called before ListenAndServe.
//
// It delays, it never refuses: an admitted request whose bytes are over
// budget is slowed, and TCP's flow control carries the slowdown back to the
// peer. The time spent waiting is added to the transfer's deadline, so the
// cap cannot make the server time out its own client. A client that sizes its
// own deadlines by an expected throughput (the Go client assumes 1 MiB/s) can
// still time out when the cap, split across its concurrent transfers, falls
// below that — see the protocol reference.
//
// The S3 API is not affected.
func (s *Server) SetTokenBytesPerSec(n int64) {
	s.throughput = ratelimit.NewThroughput(n)
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
	// "bound" is the address actually listening, which differs from addr
	// whenever addr leaves the host or the port to the kernel (":4444", ":0").
	s.log.Info("native server listening", "addr", addr, "bound", ln.Addr().String(),
		"tls", s.tlsConfig != nil,
		"max_conns", s.maxConns, "token_bytes_per_sec", s.throughput.BytesPerSec())

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
			s.cancelWait()
			s.connMu.Lock()
			s.closing = true
			for c := range s.conns {
				_ = c.Close()
			}
			s.connMu.Unlock()
			<-done
		}

		s.cancelWait()
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
// closes. The status is written before the client's handshake is read, which
// is fine: the reply is self-describing and the client is waiting on exactly
// these bytes after its own write.
//
// It does not run on the accept loop. Over TLS the reply needs a TLS handshake,
// and a TLS handshake reads the ClientHello first — a peer that connects and
// says nothing would otherwise stall every accept behind it. The refusal runs
// on its own goroutine, bounded twice: by busyRejectTimeout per connection and
// by maxBusyRejections in total. A connection that finds every slot taken is
// closed without a status; that degrades a flood to the bare EOF a client saw
// before HandshakeServerBusy existed, instead of letting the flood spend the
// fds the connection cap protects.
func (s *Server) rejectBusy(conn net.Conn) {
	select {
	case s.busySlots <- struct{}{}:
	default:
		s.log.Debug("busy refusals saturated, closing without a status", "remote", conn.RemoteAddr())
		_ = conn.Close()
		return
	}
	s.wg.Go(func() {
		defer func() { <-s.busySlots }()
		s.answerBusy(conn)
	})
}

// answerBusy writes HandshakeServerBusy and closes gracefully.
//
// "Gracefully" is the point of the second half. The client's handshake is
// usually already in our receive buffer, and closing a socket with unread data
// makes the kernel answer with a reset instead of a FIN. Linux and macOS still
// hand the client the status that arrived before the reset (measured), but not
// every TCP stack keeps data it received once a reset follows, and a client
// that reads the reset loses the only thing we came here to say. So: write the
// status, half-close, and read out whatever the client sent until it hangs up,
// which it does as soon as it has read the status. The final close then finds
// nothing unread and sends a plain FIN.
func (s *Server) answerBusy(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(busyRejectTimeout)); err != nil {
		return
	}
	if err := WriteHandshakeResponse(conn, HandshakeServerBusy); err != nil {
		s.log.Debug("write busy handshake response", "err", err, "remote", conn.RemoteAddr())
		return
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(conn, maxHandshakeBytes))
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

// logRecoveredPanic writes what a panic must always leave behind: a line in
// the same JSON stream as everything else, plus a counter that moves. Every
// native connection is a bare goroutine, so an unrecovered panic here takes the
// whole process down, not one request.
//
// stack is passed in because runtime/debug.Stack only sees the panicking frames
// while the deferred function that recovered is still running. log may be nil
// in a fixture, and a nil dereference here would be a panic nothing catches.
func logRecoveredPanic(log *slog.Logger, metrics *maintenance.Metrics, rec any, stack []byte, attrs ...any) {
	metrics.RecordPanicRecovered()
	if log == nil {
		log = slog.Default()
	}
	args := make([]any, 0, len(attrs)+4)
	args = append(args, "panic", rec, "stack", string(stack))
	args = append(args, attrs...)
	log.Error("panic recovered", args...)
}

func (s *Server) handleConn(nc net.Conn) {
	defer func() { _ = nc.Close() }()

	// Registered after the close above, so it runs BEFORE it: the connection
	// is still closed, and the panic never reaches the top frame of this
	// goroutine, where the runtime would kill the process. handleOneRequest
	// recovers first with the opcode; this one covers the handshake,
	// authentication and the deadline plumbing around the loop.
	defer func() {
		if rec := recover(); rec != nil {
			logRecoveredPanic(s.log, s.metrics, rec, debug.Stack(),
				"phase", "connection", "remote", nc.RemoteAddr())
		}
	}()

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

		throughput: s.throughput,
		waitCtx:    s.waitCtx,
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

	throughput *ratelimit.Throughput
	waitCtx    context.Context
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

func (h *connHandler) handleOneRequest() (err error) {
	op, streamID, metaLen, dataLen, err := ReadHeader(h.br)
	if err != nil {
		return err
	}

	// The frame is identified from here on, so a panic can name the opcode and
	// stream that caused it. The connection is NOT kept alive afterwards: the
	// handler may have consumed part of its own frame, so the stream is of
	// unknown alignment and the next ReadHeader would parse body bytes as a
	// header. Returning an error closes the connection.
	defer func() {
		if rec := recover(); rec != nil {
			logRecoveredPanic(h.log, h.metrics, rec, debug.Stack(),
				"phase", "request",
				"remote", h.conn.RemoteAddr(),
				"token_id", h.token.TokenID,
				"op", op,
				"stream_id", streamID)
			err = fmt.Errorf("proto: panic serving op 0x%02x: %v", op, rec)
		}
	}()

	// Shared token-bucket rate limit, decided on the header alone: nothing of
	// the frame's payload has been read yet, so a refusal can choose how much
	// of it to pay for. See rejectRateLimited.
	if !h.limiter.Allow(h.limitKey) {
		return h.rejectRateLimited(streamID, metaLen, dataLen)
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
	var body *io.LimitedReader
	var dataReader io.Reader
	if dataLen > 0 {
		timeout := max(time.Duration(dataLen/dataReadBytesPerSec+1)*time.Second, minDataReadTimeout)
		readDeadline := time.Now().Add(timeout)
		if err := h.conn.SetReadDeadline(readDeadline); err != nil {
			return fmt.Errorf("set data read deadline: %w", err)
		}
		body = &io.LimitedReader{R: h.br, N: dataLen}
		dataReader = body
		if h.throughput.Enabled() {
			dataReader = &throttledReader{r: body, h: h, deadline: readDeadline}
		}
	}

	req := &request{
		op:       op,
		streamID: streamID,
		meta:     metaPayload,
		data:     dataReader,
		body:     body,
		dataLen:  dataLen,
	}

	if err := h.dispatch(req); err != nil {
		return err
	}
	// Whatever the handler left of the body goes the way drainData says, so
	// the next header is read from a frame boundary. The handlers that
	// refuse a body drain it themselves; this also covers a body sent with
	// an operation that takes none, which would otherwise be parsed as the
	// next frame's header.
	if err := drainData(req); err != nil {
		return err
	}

	if err := h.conn.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear data read deadline: %w", err)
	}

	if err := h.bw.Flush(); err != nil {
		return err
	}
	// The handler answered without consuming the frame, and what was left of
	// the body was more than it is worth draining: the answer is on the wire,
	// and the stream behind it is not aligned on a frame any more.
	if req.closeAfter {
		return errClosedAfterAnswer
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
	// data is what a handler reads the body from: body itself, or body behind
	// the per-token throughput cap.
	data io.Reader
	// body is the frame body, bounded to dataLen. body.N is how much of it is
	// still unread, which is what drainData has to account for — not dataLen,
	// since a handler may have consumed part of it before failing.
	body    *io.LimitedReader
	dataLen int64
	// closeAfter is set by drainData when the unread rest of the body is more
	// than MaxDrainSize: the handler still writes its answer, and the
	// connection is closed after it instead of being drained.
	closeAfter bool
}

// errClosedAfterAnswer ends a connection whose current frame was answered
// without being read to the end. It is a deliberate close, not a failure: the
// peer has its answer, and the bytes it is still sending belong to a frame
// nobody will read.
var errClosedAfterAnswer = errors.New("proto: frame answered without being consumed, closing the connection")

// rejectRateLimited answers a frame the limiter refused. The header is all
// that has been read.
func (h *connHandler) rejectRateLimited(streamID uint32, metaLen uint32, dataLen int64) error {
	if metaLen > MaxMetaSize {
		// Not a frame the server would read if it were admitted either.
		return fmt.Errorf("metadata too large: %d", metaLen)
	}
	// The body alone is held against the bound, and the metadata is read on
	// top of it: the rule every client older than RateLimitDrainSize was
	// built against, so every frame the servers they knew drained is still
	// drained. Holding meta_len + data_len against it instead would close on
	// a MaxDrainSize upload that brings any metadata at all.
	//
	// Nothing is added to dataLen before the comparison: it comes off the
	// wire and can be anything up to MaxInt64, and a sum could wrap
	// negative, pass as a small frame, drain nothing and keep a connection
	// whose frame is still unread. Once kept, the sum is at most
	// MaxMetaSize + RateLimitDrainSize.
	keep := dataLen <= RateLimitDrainSize
	if keep {
		if _, err := io.CopyN(io.Discard, h.br, int64(metaLen)+dataLen); err != nil {
			return err
		}
	}
	errMeta := EncodeError("rate limit exceeded", "RateLimitExceeded")
	if err := h.writeResponseCombined(StatusBadRequest, streamID, errMeta); err != nil {
		return err
	}
	if err := h.bw.Flush(); err != nil {
		return err
	}
	if !keep {
		return errClosedAfterAnswer
	}
	return h.conn.SetWriteDeadline(time.Time{})
}

// throttledReader is a request body behind the per-token throughput cap. It
// reads first and pays after, like the scrubber: the bytes wait in our buffer
// while the budget refills, and the peer is held back by TCP's flow control.
//
// deadline is the body's read deadline. Every wait pushes it back by as long
// as the wait took, so the deadline keeps measuring the peer's throughput —
// what it exists for — and not the time the server chose to spend waiting.
type throttledReader struct {
	r        io.Reader
	h        *connHandler
	deadline time.Time
}

func (t *throttledReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		if werr := t.h.waitBytes(n, &t.deadline, t.h.conn.SetReadDeadline); werr != nil {
			return n, werr
		}
	}
	return n, err
}

// waitBytes charges n body bytes to the token's throughput budget and, when
// that took time, moves *deadline back by the same amount through set.
func (h *connHandler) waitBytes(n int, deadline *time.Time, set func(time.Time) error) error {
	start := time.Now()
	if err := h.throughput.WaitN(h.waitCtx, h.limitKey, n); err != nil {
		return fmt.Errorf("throughput wait: %w", err)
	}
	if waited := time.Since(start); waited > 0 {
		*deadline = deadline.Add(waited)
		if err := set(*deadline); err != nil {
			return fmt.Errorf("extend deadline: %w", err)
		}
	}
	return nil
}

// armWriteDeadline sets a write deadline scaled by the response payload size:
// max(minDataWriteTimeout, payload at dataWriteBytesPerSec + 1s). Every
// response writer must call it before touching the connection; the deadline
// is cleared after the final flush in handleOneRequest.
func (h *connHandler) armWriteDeadline(payloadLen int64) error {
	_, err := h.armWriteDeadlineAt(payloadLen)
	return err
}

// armWriteDeadlineAt is armWriteDeadline for a writer that needs the deadline
// back, to push it later (see waitBytes).
func (h *connHandler) armWriteDeadlineAt(payloadLen int64) (time.Time, error) {
	timeout := max(time.Duration(payloadLen/dataWriteBytesPerSec+1)*time.Second, minDataWriteTimeout)
	deadline := time.Now().Add(timeout)
	return deadline, h.conn.SetWriteDeadline(deadline)
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
