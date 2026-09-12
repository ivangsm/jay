package client

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ivangsm/jay/api"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/proto"
)

// --- Context: cancellation and deadlines ---

// stallingServer completes the handshake and then never answers a frame. It
// is what a wedged jay looks like from the client's side, and the only way
// out of it without a context is the size-scaled deadline, 30s at minimum.
func stallingServer(t *testing.T) *fakeServer {
	t.Helper()
	return startFakeServer(t, func(_ int32, nc net.Conn, br *bufio.Reader, _ *bufio.Writer) {
		defer func() { _ = nc.Close() }()
		// Consume the request so the client's write completes, then stall.
		_, _, metaLen, _, err := proto.ReadHeader(br)
		if err != nil {
			return
		}
		_, _ = io.CopyN(io.Discard, br, int64(metaLen))
		time.Sleep(5 * time.Second)
	})
}

func TestContext_CancelAbortsBlockedRequest(t *testing.T) {
	fs := stallingServer(t)
	c, err := Dial(context.Background(), fs.addr(), "tok", "sec", WithPoolSize(1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err = c.Ping(ctx)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("cancellation took %v: the socket deadline fired, not the context", elapsed)
	}
}

func TestContext_DeadlineCapsOperationTimeout(t *testing.T) {
	fs := stallingServer(t)
	c, err := Dial(context.Background(), fs.addr(), "tok", "sec", WithPoolSize(1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = c.HeadBucket(ctx, "any")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want context.DeadlineExceeded, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("deadline took %v to fire", elapsed)
	}
}

func TestContext_AlreadyCancelledFailsBeforeDialing(t *testing.T) {
	fs := startFakeServer(t, func(_ int32, nc net.Conn, br *bufio.Reader, bw *bufio.Writer) {
		serveRequests(nc, br, bw)
	})
	c, err := Dial(context.Background(), fs.addr(), "tok", "sec", WithPoolSize(1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	before := fs.accepts.Load()
	if err := c.Ping(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if fs.accepts.Load() != before {
		t.Fatal("a cancelled context must not open a connection")
	}
}

func TestContext_CancelledDialIsNotRetried(t *testing.T) {
	// A connection that dies before answering is normally replayed once on
	// a fresh one. Not when the caller cancelled: that would be doing work
	// nobody wants any more.
	fs := startFakeServer(t, func(_ int32, nc net.Conn, br *bufio.Reader, _ *bufio.Writer) {
		_, _, metaLen, _, err := proto.ReadHeader(br)
		if err != nil {
			return
		}
		_, _ = io.CopyN(io.Discard, br, int64(metaLen))
		time.Sleep(200 * time.Millisecond)
		_ = nc.Close()
	})
	c, err := Dial(context.Background(), fs.addr(), "tok", "sec", WithPoolSize(1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c.Ping(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want context.DeadlineExceeded, got %v", err)
	}
	// Give any misguided retry a chance to show up as a second accept.
	time.Sleep(300 * time.Millisecond)
	if n := fs.accepts.Load(); n != 1 {
		t.Fatalf("expected exactly the pre-connect, got %d connections: the cancelled request was retried", n)
	}
}

func TestContext_CancelMidBodyDropsConnection(t *testing.T) {
	env := setup(t)
	ctx := context.Background()
	if _, err := env.client.CreateBucket(ctx, "ctx"); err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("x"), 4<<20)
	if _, err := env.client.PutObject(ctx, "ctx", "big", bytes.NewReader(body), int64(len(body)), nil); err != nil {
		t.Fatal(err)
	}

	getCtx, cancel := context.WithCancel(ctx)
	res, err := env.client.GetObject(getCtx, "ctx", "big")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	if _, err := io.ReadFull(res.Body, buf); err != nil {
		t.Fatal(err)
	}
	cancel()

	// The next read must report the context, not "i/o timeout".
	var got error
	for range 64 {
		if _, got = res.Body.Read(buf); got != nil {
			break
		}
	}
	if got == nil || !errors.Is(got, context.Canceled) {
		t.Fatalf("want context.Canceled from Read, got %v", got)
	}
	_ = res.Body.Close()

	// The client is still usable: the abandoned connection was dropped, not
	// pooled with a stale deadline and half a body pending.
	if err := env.client.Ping(ctx); err != nil {
		t.Fatalf("ping after cancelled download: %v", err)
	}
}

// --- GetObjectRange ---

func TestGetObjectRange(t *testing.T) {
	env := setup(t)
	ctx := context.Background()
	if _, err := env.client.CreateBucket(ctx, "rng"); err != nil {
		t.Fatal(err)
	}
	content := []byte("0123456789")
	if _, err := env.client.PutObject(ctx, "rng", "digits", bytes.NewReader(content), 10, &PutOptions{ContentType: "text/plain"}); err != nil {
		t.Fatal(err)
	}

	read := func(t *testing.T, offset, length int64) (*GetResult, string) {
		t.Helper()
		res, err := env.client.GetObjectRange(ctx, "rng", "digits", offset, length)
		if err != nil {
			t.Fatalf("range %d/%d: %v", offset, length, err)
		}
		defer func() { _ = res.Body.Close() }()
		b, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res, string(b)
	}

	t.Run("middle", func(t *testing.T) {
		res, got := read(t, 2, 3)
		if got != "234" || res.ContentLength != 3 || res.Size != 10 {
			t.Fatalf("got %q len %d size %d", got, res.ContentLength, res.Size)
		}
		if res.ContentType != "text/plain" || res.ChecksumSHA256 == "" {
			t.Fatalf("metadata must be the whole object's: %+v", res.ObjectInfo)
		}
	})
	t.Run("to end", func(t *testing.T) {
		if _, got := read(t, 7, 0); got != "789" {
			t.Fatalf("got %q", got)
		}
		if _, got := read(t, 7, -1); got != "789" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("length past end is clamped", func(t *testing.T) {
		res, got := read(t, 8, 100)
		if got != "89" || res.ContentLength != 2 {
			t.Fatalf("got %q len %d", got, res.ContentLength)
		}
	})
	t.Run("offset past end is InvalidRange", func(t *testing.T) {
		_, err := env.client.GetObjectRange(ctx, "rng", "digits", 10, 1)
		var pe *Error
		if !errors.As(err, &pe) || pe.Code != "InvalidRange" || pe.Status != proto.StatusBadRequest {
			t.Fatalf("want InvalidRange, got %v", err)
		}
		// The connection is intact afterwards.
		if err := env.client.Ping(ctx); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing key", func(t *testing.T) {
		_, err := env.client.GetObjectRange(ctx, "rng", "nope", 0, 1)
		var pe *Error
		if !errors.As(err, &pe) || pe.Code != "NoSuchKey" {
			t.Fatalf("want NoSuchKey, got %v", err)
		}
	})
	t.Run("sequential ranges reuse the connection", func(t *testing.T) {
		var out strings.Builder
		for off := int64(0); off < 10; off += 2 {
			_, got := read(t, off, 2)
			out.WriteString(got)
		}
		if out.String() != "0123456789" {
			t.Fatalf("reassembled %q", out.String())
		}
	})
}

// --- CopyObject ---

func TestCopyObject(t *testing.T) {
	env := setup(t)
	ctx := context.Background()
	for _, b := range []string{"src", "dst"} {
		if _, err := env.client.CreateBucket(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	content := []byte("copy me")
	put, err := env.client.PutObject(ctx, "src", "a", bytes.NewReader(content), int64(len(content)),
		&PutOptions{ContentType: "text/x-test", Metadata: map[string]string{"x-amz-meta-k": "v"}})
	if err != nil {
		t.Fatal(err)
	}

	res, err := env.client.CopyObject(ctx, "src", "a", "dst", "b")
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if res.ChecksumSHA256 != put.ChecksumSHA256 || res.Size != int64(len(content)) || res.LastModified == "" {
		t.Fatalf("unexpected copy result: %+v", res)
	}

	// The effect: the destination reads back byte for byte, with the
	// source's content type and metadata.
	got, err := env.client.GetObject(ctx, "dst", "b")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = got.Body.Close() }()
	b, _ := io.ReadAll(got.Body)
	if !bytes.Equal(b, content) || got.ContentType != "text/x-test" || got.Metadata["x-amz-meta-k"] != "v" {
		t.Fatalf("destination differs: %q %s %v", b, got.ContentType, got.Metadata)
	}

	t.Run("missing source names the side", func(t *testing.T) {
		_, err := env.client.CopyObject(ctx, "src", "nope", "dst", "b")
		var pe *Error
		if !errors.As(err, &pe) || pe.Code != "NoSuchKey" || !strings.HasPrefix(pe.Message, "source:") {
			t.Fatalf("want source NoSuchKey, got %v", err)
		}
	})
	t.Run("missing destination bucket names the side", func(t *testing.T) {
		_, err := env.client.CopyObject(ctx, "src", "a", "nowhere", "b")
		var pe *Error
		if !errors.As(err, &pe) || pe.Code != "NoSuchBucket" || !strings.HasPrefix(pe.Message, "destination:") {
			t.Fatalf("want destination NoSuchBucket, got %v", err)
		}
	})
}

// --- UnknownOp from an older server ---

func TestIsUnknownOp(t *testing.T) {
	fs := startFakeServer(t, func(_ int32, nc net.Conn, br *bufio.Reader, bw *bufio.Writer) {
		defer func() { _ = nc.Close() }()
		for {
			_, streamID, metaLen, dataLen, err := proto.ReadHeader(br)
			if err != nil {
				return
			}
			_, _ = io.CopyN(io.Discard, br, int64(metaLen)+dataLen)
			if err := proto.WriteFrameCombined(bw, proto.StatusBadRequest, streamID,
				proto.EncodeError("unknown operation", "UnknownOp")); err != nil {
				return
			}
			if err := bw.Flush(); err != nil {
				return
			}
		}
	})
	c, err := Dial(context.Background(), fs.addr(), "tok", "sec", WithPoolSize(1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	_, err = c.CopyObject(context.Background(), "a", "b", "c", "d")
	if !IsUnknownOp(err) {
		t.Fatalf("want an UnknownOp error, got %v", err)
	}
	if IsUnknownOp(errors.New("other")) || IsUnknownOp(nil) {
		t.Fatal("IsUnknownOp must be false for anything else")
	}
}

// --- PresignURL ---

func TestPresignURL_WorksAgainstTheS3Listener(t *testing.T) {
	env := setup(t)
	ctx := context.Background()

	// The same jay, through its HTTP surface.
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	h := api.NewHandler(env.db, env.st, auth.New(env.db), log, nil, "test-secret-for-signing-that-is-long-enough", nil)
	s3 := httptest.NewServer(h)
	defer s3.Close()

	if _, err := env.client.CreateBucket(ctx, "signed"); err != nil {
		t.Fatal(err)
	}
	content := []byte("presigned body")
	if _, err := env.client.PutObject(ctx, "signed", "dir/file.txt", bytes.NewReader(content), int64(len(content)), nil); err != nil {
		t.Fatal(err)
	}

	t.Run("requires the endpoint", func(t *testing.T) {
		if _, err := env.client.PresignURL("GET", "signed", "dir/file.txt", time.Minute); err == nil {
			t.Fatal("a client without WithS3Endpoint must refuse to sign: the signature covers the host")
		}
	})

	c, err := Dial(ctx, env.addr, env.tokenID, env.secret, WithPoolSize(1), WithS3Endpoint(s3.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	t.Run("GET downloads", func(t *testing.T) {
		u, err := c.PresignURL("GET", "signed", "dir/file.txt", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.Get(u) //nolint:gosec // test URL from the local server
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || !bytes.Equal(b, content) {
			t.Fatalf("status %d body %q", resp.StatusCode, b)
		}
	})

	t.Run("PUT uploads and the native side sees it", func(t *testing.T) {
		u, err := c.PresignURL("PUT", "signed", "uploaded.txt", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPut, u, strings.NewReader("via presign"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		info, err := c.HeadObject(ctx, "signed", "uploaded.txt")
		if err != nil || info.Size != int64(len("via presign")) {
			t.Fatalf("object not there after presigned PUT: %v %+v", err, info)
		}
	})

	t.Run("wrong method is refused", func(t *testing.T) {
		u, err := c.PresignURL("GET", "signed", "dir/file.txt", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a GET signature used for DELETE must be refused, got %d", resp.StatusCode)
		}
		if _, err := c.HeadObject(ctx, "signed", "dir/file.txt"); err != nil {
			t.Fatalf("object must survive the refused delete: %v", err)
		}
	})

	t.Run("expiry is bounded", func(t *testing.T) {
		if _, err := c.PresignURL("GET", "signed", "k", 8*24*time.Hour); err == nil {
			t.Fatal("8 days must exceed the 7-day maximum")
		}
		if _, err := c.PresignURL("GET", "signed", "k", 0); err == nil {
			t.Fatal("zero expiry must be refused")
		}
	})
}
