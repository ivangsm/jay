// Package accesslog holds what both of jay's HTTP listeners need to trace a
// request: the request ID minted at the edge, the peer address the log names,
// and the response recorder an access line reads its status and size from.
//
// It exists so the S3 listener and the admin listener cannot drift apart on
// any of the three. What each listener writes in its access line, and at which
// level, stays with the listener.
package accesslog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
)

// Header is the response header that carries the request ID, on both
// listeners. It is the S3 name because the S3 listener had it first and S3
// clients already surface it; one name across jay means one thing to grep for.
const Header = "x-amz-request-id"

type ctxKey struct{}

// NewRequestID returns a cryptographically random 16-hex-digit request ID.
//
// crypto/rand.Read's error is discarded because as of Go 1.24 it cannot happen:
// the function is documented as "never returns an error, and always fills b
// entirely" — if the OS cannot supply entropy, the runtime kills the process.
// The `_, _` is for the linter, not to paper over a possible failure.
func NewRequestID() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// Stamp mints a request ID, puts it on the response header and returns r with
// the ID in its context. It must run in the OUTERMOST middleware of a
// listener: a middleware only ever sees the request it was handed, so an ID
// minted further in leaves an outer logger reading request_id="".
//
// The ID is always minted here, never taken from an inbound header: a client
// that could choose its own request ID could collide with someone else's or
// forge log entries.
func Stamp(w http.ResponseWriter, r *http.Request) *http.Request {
	id := NewRequestID()
	w.Header().Set(Header, id)
	return r.WithContext(context.WithValue(r.Context(), ctxKey{}, id))
}

// RequestID returns the ID Stamp installed, or "" when the request never went
// through it.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// PeerIP returns the address of the direct TCP peer, without the port. It
// deliberately ignores forwarding headers: the admin listener keys its
// authentication backoff by this value, and the log has to name the same
// address the backoff counted. (The S3 listener has its own derivation, which
// honours X-Forwarded-For when JAY_TRUST_PROXY_HEADERS says so.)
func PeerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Recorder wraps a ResponseWriter to capture what the access line reports: the
// status that reached the client, the body bytes written, and whether the
// response has started at all.
//
// Started is what lets a panic handler tell a panic that happened before the
// response began (answerable with a 500) from one halfway through a body
// (answerable only by tearing the connection down).
type Recorder struct {
	http.ResponseWriter
	status  int
	bytes   int64
	started bool
}

// NewRecorder wraps w. Until a handler says otherwise the status is 200, which
// is what net/http sends for a handler that writes without calling WriteHeader.
func NewRecorder(w http.ResponseWriter) *Recorder {
	return &Recorder{ResponseWriter: w, status: http.StatusOK}
}

// WriteHeader records the FIRST status: net/http ignores every later call, so
// recording the last one would make the log disagree with the response.
func (rec *Recorder) WriteHeader(code int) {
	if !rec.started {
		rec.status = code
		rec.started = true
	}
	rec.ResponseWriter.WriteHeader(code)
}

// Write records that the response has begun and counts the bytes written.
func (rec *Recorder) Write(b []byte) (int, error) {
	rec.started = true
	n, err := rec.ResponseWriter.Write(b)
	rec.bytes += int64(n)
	return n, err
}

// ReadFrom keeps sendfile(2) reachable: copying an *os.File into the response
// goes through the underlying writer's ReadFrom, which on a TCP connection is
// the zero-copy path.
func (rec *Recorder) ReadFrom(r io.Reader) (int64, error) {
	rec.started = true
	var (
		n   int64
		err error
	)
	if rf, ok := rec.ResponseWriter.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(r)
	} else {
		n, err = io.Copy(rec.ResponseWriter, r)
	}
	rec.bytes += n
	return n, err
}

// Flush forwards to the underlying writer when it can flush.
func (rec *Recorder) Flush() {
	if f, ok := rec.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the connection underneath.
func (rec *Recorder) Unwrap() http.ResponseWriter {
	return rec.ResponseWriter
}

// Status is the status code the client got (200 when nothing was written).
func (rec *Recorder) Status() int { return rec.status }

// Bytes is the number of body bytes written so far.
func (rec *Recorder) Bytes() int64 { return rec.bytes }

// Started reports whether any part of the response has reached the writer.
func (rec *Recorder) Started() bool { return rec.started }

// Compile-time interface checks.
var (
	_ http.ResponseWriter = (*Recorder)(nil)
	_ http.Flusher        = (*Recorder)(nil)
	_ io.ReaderFrom       = (*Recorder)(nil)
)
