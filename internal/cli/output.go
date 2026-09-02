package cli

import (
	"fmt"
	"io"
	"sync"
)

// syncWriter serializes writes from concurrent transfers. Without it two
// workers interleave mid-line, and the race detector flags the buffer the
// tests write into — the interleaving is real on a terminal too, it just
// looks like corrupted output instead of a failure.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func newSyncWriter(w io.Writer) *syncWriter {
	return &syncWriter{w: w}
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// printf writes one line of command output. A failed write to the CLI's own
// stdout or stderr is not actionable — the message *is* the report, and there
// is nowhere left to report the failure to — so the error is dropped here,
// once and on purpose, instead of at every call site.
//
// This is only for human-facing text. Anything that must not be silently lost
// (an object body, a checksum) goes through the transfer path, which returns
// its errors.
func printf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// write emits literal text under the same rule as printf.
func write(w io.Writer, s string) {
	_, _ = io.WriteString(w, s)
}
