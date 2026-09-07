package proto

// PND-0193, native half. The stakes here are higher than on the HTTP side:
// net/http recovers a panicking handler per connection, but every native
// connection is a bare goroutine, so an unrecovered panic did not lose one
// request — it killed the process.
//
// Both tests panic for real, in real code, by handing the handler a nil
// *meta.DB: the first credential check and the first bucket lookup dereference
// it. No injected hook, because a hook would prove the hook works.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/internal/ratelimit"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
)

// panicLogLine parses the captured log and returns the single "panic recovered"
// entry. A line that is not JSON fails the test on its own: the whole point of
// the fix is that the trace stays inside the machine-readable stream.
func panicLogLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var found map[string]any
	scanner := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal(raw, &entry); err != nil {
			t.Fatalf("log line is not JSON: %q (%v)", raw, err)
		}
		if entry["msg"] == "panic recovered" {
			found = entry
		}
	}
	if found == nil {
		t.Fatalf("no \"panic recovered\" line in the log:\n%s", buf.String())
	}
	return found
}

func jsonLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

func TestNativePanicDuringHandshake_LogsAndClosesInsteadOfKillingTheProcess(t *testing.T) {
	log, buf := jsonLogger()
	metrics := maintenance.NewMetrics()
	// auth.New(nil): validating the first credential pair dereferences a
	// database that is not there. Before the fix this panic reached the top of
	// the connection goroutine and took the whole test binary with it.
	s := NewServer(nil, nil, auth.New(nil), log, metrics, 0, 0)

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleConn(server)
	}()

	if err := WriteHandshake(client, "some-token:some-secret"); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := ReadHandshakeResponse(client); err == nil {
		t.Fatal("the server answered the handshake it panicked on")
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handleConn never returned")
	}

	entry := panicLogLine(t, buf)
	if entry["level"] != "ERROR" {
		t.Fatalf("panic logged at level %v, want ERROR", entry["level"])
	}
	if entry["phase"] != "connection" {
		t.Fatalf("phase = %v, want \"connection\"", entry["phase"])
	}
	if stack, _ := entry["stack"].(string); !strings.Contains(stack, "handleConn") {
		t.Fatalf("stack does not reach the connection handler:\n%v", entry["stack"])
	}
	if entry["remote"] == nil || entry["remote"] == "" {
		t.Fatalf("the line does not say which peer it was: %v", entry["remote"])
	}
	if got := metrics.PanicsRecovered.Load(); got != 1 {
		t.Fatalf("panics_recovered = %d, want 1", got)
	}
}

func TestNativePanicServingRequest_NamesTheOperationAndDropsTheConnection(t *testing.T) {
	log, buf := jsonLogger()
	metrics := maintenance.NewMetrics()

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	h := &connHandler{
		// nil db: handleHeadBucket dereferences it right after authorising.
		db:       nil,
		auth:     auth.New(nil),
		log:      log,
		metrics:  metrics,
		token:    &meta.Token{TokenID: "tok-1", AccountID: "acc-1", AllowedActions: meta.AllActions, Status: "active"},
		conn:     server,
		br:       bufio.NewReader(server),
		bw:       bufio.NewWriter(server),
		limiter:  ratelimit.New(ratelimit.Config{}),
		limitKey: "tok-1",
	}

	payload, err := EncodeBucket("some-bucket")
	if err != nil {
		t.Fatalf("encode bucket: %v", err)
	}

	const streamID = uint32(7)
	go func() {
		if err := WriteHeader(client, OpHeadBucket, streamID, uint32(len(payload)), 0); err != nil {
			return
		}
		_, _ = client.Write(payload)
	}()

	err = h.handleOneRequest()
	if err == nil {
		t.Fatal("handleOneRequest returned nil after a panic — the caller would " +
			"keep reading a stream of unknown alignment")
	}
	if !strings.Contains(err.Error(), "0x03") {
		t.Fatalf("the error does not name the opcode that panicked: %v", err)
	}

	entry := panicLogLine(t, buf)
	if entry["phase"] != "request" {
		t.Fatalf("phase = %v, want \"request\"", entry["phase"])
	}
	if op, _ := entry["op"].(float64); byte(op) != OpHeadBucket {
		t.Fatalf("op = %v, want %d (HeadBucket)", entry["op"], OpHeadBucket)
	}
	if id, _ := entry["stream_id"].(float64); uint32(id) != streamID {
		t.Fatalf("stream_id = %v, want %d", entry["stream_id"], streamID)
	}
	if entry["token_id"] != "tok-1" {
		t.Fatalf("token_id = %v, want \"tok-1\"", entry["token_id"])
	}
	if stack, _ := entry["stack"].(string); !strings.Contains(stack, "handleHeadBucket") {
		t.Fatalf("stack does not reach the handler that panicked:\n%v", entry["stack"])
	}
	if got := metrics.PanicsRecovered.Load(); got != 1 {
		t.Fatalf("panics_recovered = %d, want 1", got)
	}
}
