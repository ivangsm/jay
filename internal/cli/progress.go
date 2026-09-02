package cli

import (
	"io"
	"os"
	"sync/atomic"
	"time"
)

// progressInterval throttles redraws so a fast local transfer does not spend
// more time formatting than copying.
const progressInterval = 100 * time.Millisecond

// progressReader reports how much of a transfer has gone by. It is a plain
// io.Reader wrapper: the bytes still stream: nothing is buffered to measure them.
type progressReader struct {
	r     io.Reader
	total int64
	label string
	w     io.Writer

	read     int64
	lastDraw time.Time
}

// newProgressReader wraps r when w is a terminal. On a pipe or a CI log it
// returns r untouched, because carriage-return redraws there produce one line
// per update instead of one line total.
func newProgressReader(r io.Reader, total int64, label string, w io.Writer) io.Reader {
	if !isTerminal(w) {
		return r
	}
	return &progressReader{r: r, total: total, label: label, w: w}
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)

	if err == io.EOF || time.Since(p.lastDraw) >= progressInterval {
		p.draw()
		p.lastDraw = time.Now()
	}
	if err == io.EOF {
		write(p.w, "\n")
	}
	return n, err
}

func (p *progressReader) draw() {
	if p.total <= 0 {
		printf(p.w, "\r%s  %s", p.label, humanBytes(p.read))
		return
	}
	pct := float64(p.read) / float64(p.total) * 100
	printf(p.w, "\r%s  %s / %s (%.0f%%)   ", p.label, humanBytes(p.read), humanBytes(p.total), pct)
}

// isTerminal reports whether w is a character device. Only *os.File can be
// one; anything else (a buffer in a test, a pipe) is not.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// counter accumulates results across concurrent transfers.
type counter struct {
	ok     atomic.Int64
	failed atomic.Int64
	bytes  atomic.Int64
}
