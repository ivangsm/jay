package accesslog

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The ID the client is handed and the ID the handlers read are one value, and
// it is never the one the client sent.
func TestStamp_HeaderAndContextCarryTheSameMintedID(t *testing.T) {
	const forged = "i-chose-this-id"
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(Header, forged)
	w := httptest.NewRecorder()

	stamped := Stamp(w, req)

	fromHeader := w.Header().Get(Header)
	fromContext := RequestID(stamped.Context())
	if fromHeader == "" || fromHeader != fromContext {
		t.Fatalf("header %q, context %q: want the same non-empty ID", fromHeader, fromContext)
	}
	if fromHeader == forged {
		t.Fatal("the inbound request ID was adopted instead of minting one")
	}
	if len(fromHeader) != 16 || strings.Trim(fromHeader, "0123456789abcdef") != "" {
		t.Fatalf("request ID %q is not 16 hex digits", fromHeader)
	}
	if RequestID(req.Context()) != "" {
		t.Fatal("Stamp modified the original request's context")
	}
}

func TestNewRequestID_DoesNotRepeat(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := NewRequestID()
		if seen[id] {
			t.Fatalf("request ID %s minted twice", id)
		}
		seen[id] = true
	}
}

func TestPeerIP(t *testing.T) {
	for addr, want := range map[string]string{
		"192.0.2.7:4321":  "192.0.2.7",
		"[2001:db8::1]:9": "2001:db8::1",
		"not-a-host-port": "not-a-host-port",
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = addr
		req.Header.Set("X-Forwarded-For", "203.0.113.9")
		if got := PeerIP(req); got != want {
			t.Errorf("PeerIP(%q) = %q, want %q (forwarding headers are ignored)", addr, got, want)
		}
	}
}

// The recorder reports the status the client got — the first one — and every
// byte of the body, whichever way it was written.
func TestRecorder_StatusBytesAndStarted(t *testing.T) {
	w := httptest.NewRecorder()
	rec := NewRecorder(w)
	if rec.Started() || rec.Status() != http.StatusOK || rec.Bytes() != 0 {
		t.Fatalf("fresh recorder: started %v, status %d, bytes %d", rec.Started(), rec.Status(), rec.Bytes())
	}

	rec.WriteHeader(http.StatusTeapot)
	rec.WriteHeader(http.StatusInternalServerError) // ignored by net/http, so by the log too
	if _, err := rec.Write([]byte("hello ")); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.ReadFrom(bytes.NewReader([]byte("world"))); err != nil {
		t.Fatal(err)
	}

	if !rec.Started() || rec.Status() != http.StatusTeapot {
		t.Fatalf("started %v, status %d: want true, 418", rec.Started(), rec.Status())
	}
	if rec.Bytes() != int64(len("hello world")) || w.Body.String() != "hello world" {
		t.Fatalf("bytes %d, body %q", rec.Bytes(), w.Body.String())
	}
	if rec.Unwrap() != w {
		t.Fatal("Unwrap does not return the wrapped writer")
	}
}

// A handler that writes without WriteHeader has sent a 200, and has started.
func TestRecorder_ImplicitOK(t *testing.T) {
	rec := NewRecorder(httptest.NewRecorder())
	if _, err := rec.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if !rec.Started() || rec.Status() != http.StatusOK || rec.Bytes() != 1 {
		t.Fatalf("started %v, status %d, bytes %d", rec.Started(), rec.Status(), rec.Bytes())
	}
}
