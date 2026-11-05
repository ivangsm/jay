package proto_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net"
	"testing"
	"time"

	"github.com/ivangsm/jay/proto"
	"github.com/ivangsm/jay/proto/client"
)

// The back-pressure knobs end to end, through the real client over real TCP:
// what a refused upload tells the caller, what it does to the connection pool,
// and what the per-token throughput cap does to a transfer.

func dialPool1(t *testing.T, env *testEnv) *client.Client {
	t.Helper()
	c, err := client.Dial(context.Background(), env.addr, env.tokenID, env.secret, client.WithPoolSize(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func clientErrorCode(err error) string {
	if e, ok := errors.AsType[*client.Error](err); ok {
		return e.Code
	}
	return ""
}

// TestRateLimit_FractionalRateIsEnforced: JAY_RATE_LIMIT=0.5 used to reach the
// native server as int(0.5) == 0, which disables the limiter, while the S3 API
// applied it. A rate below one request per second is still a rate.
func TestRateLimit_FractionalRateIsEnforced(t *testing.T) {
	env := setupWith(t, 0.5, 1, nil)
	c := dialPool1(t, env)
	ctx := context.Background()

	if err := c.Ping(ctx); err != nil {
		t.Fatalf("the burst admits the first request: %v", err)
	}
	if err := c.Ping(ctx); clientErrorCode(err) != "RateLimitExceeded" {
		t.Fatalf("second request inside the same second at 0.5 req/s: got %v, want RateLimitExceeded", err)
	}
}

// TestRateLimit_RefusedUploadTellsTheCallerAndLeavesAWorkingPool refuses
// uploads on both sides of RateLimitDrainSize. The caller must get
// RateLimitExceeded — not "broken pipe" — and the next upload on the same
// one-connection pool must work: a pool that kept a connection the server
// closed would fail it.
//
// Up to the bound (1.5 MiB, and exactly RateLimitDrainSize, metadata on top)
// the server drains the body and keeps the connection; past it (12 MiB) it
// answers without reading, closes, and the client's write fails, so the
// answer has to be read from behind the broken pipe. What the server read in
// each case is asserted in backpressure_internal_test.go; this is what the
// caller sees.
func TestRateLimit_RefusedUploadTellsTheCallerAndLeavesAWorkingPool(t *testing.T) {
	for _, size := range []int{3 << 19, proto.RateLimitDrainSize, 12 << 20} {
		t.Run(byteCount(size), func(t *testing.T) {
			// 1 req/s, burst 1: once spent, the budget stays spent for a
			// full second — slack enough for a slow (-race) run to get the
			// upload in before it refills.
			env := setupWith(t, 1, 1, nil)
			c := dialPool1(t, env)
			ctx := context.Background()

			if _, err := c.CreateBucket(ctx, "bkt"); err != nil {
				t.Fatal(err)
			}
			body := bytes.Repeat([]byte("z"), size)
			spendBudget(t, c)

			_, err := c.PutObject(ctx, "bkt", "big", bytes.NewReader(body), int64(size), nil)
			if clientErrorCode(err) != "RateLimitExceeded" {
				t.Fatalf("refused %d-byte upload: got %v, want RateLimitExceeded", size, err)
			}
			if _, obj, _ := env.db.GetBucketAndObject("bkt", "big"); obj != nil {
				t.Fatal("a refused upload left an object behind")
			}

			time.Sleep(1100 * time.Millisecond) // one request's worth of refill
			if _, err := c.PutObject(ctx, "bkt", "small", bytes.NewReader([]byte("ok")), 2, nil); err != nil {
				t.Fatalf("the upload after a refusal failed — a dead connection was pooled: %v", err)
			}
		})
	}
}

// TestRateLimit_HugeDeclaredFrameClosesTheConnection: a rate-limited frame is
// kept (drained) only if data_len fits RateLimitDrainSize, and data_len comes
// off the wire. An earlier form of the check added meta_len to it, and
// meta_len=1 with data_len=MaxInt64 wrapped that sum negative: the frame
// counted as small, nothing was drained, and the connection stayed open with
// the whole frame unread — the bytes the peer declared as this frame's body
// would then be parsed as the next frame.
func TestRateLimit_HugeDeclaredFrameClosesTheConnection(t *testing.T) {
	env := setupWith(t, 1, 1, nil)

	nc, err := net.Dial("tcp", env.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nc.Close() }()
	br := bufio.NewReader(nc)
	if err := proto.WriteHandshake(nc, env.tokenID+":"+env.secret); err != nil {
		t.Fatal(err)
	}
	if st, err := proto.ReadHandshakeResponse(br); err != nil || st != proto.HandshakeOK {
		t.Fatalf("handshake: status %d, err %v", st, err)
	}
	_ = nc.SetDeadline(time.Now().Add(5 * time.Second))

	// Spend the burst, then declare a frame the server must refuse unread.
	if err := proto.WriteFrame(nc, proto.OpPing, 1, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, metaLen, _, err := proto.ReadHeader(br); err != nil {
		t.Fatal(err)
	} else if _, err := io.CopyN(io.Discard, br, int64(metaLen)); err != nil {
		t.Fatal(err)
	}
	if err := proto.WriteHeader(nc, proto.OpPutObject, 2, 1, math.MaxInt64); err != nil {
		t.Fatal(err)
	}

	status, _, metaLen, _, err := proto.ReadHeader(br)
	if err != nil {
		t.Fatalf("the refused frame got no answer: %v", err)
	}
	answer := make([]byte, metaLen)
	if _, err := io.ReadFull(br, answer); err != nil {
		t.Fatal(err)
	}
	if status != proto.StatusBadRequest || !bytes.Contains(answer, []byte("RateLimitExceeded")) {
		t.Fatalf("answer: status %d, meta %q; want RateLimitExceeded", status, answer)
	}

	// The server must close now. A kept connection blocks this read until the
	// deadline instead of returning EOF.
	_, err = br.ReadByte()
	if err == nil {
		t.Fatal("the server sent more bytes after the refusal")
	}
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		t.Fatal("the server kept the connection with a MaxInt64-byte frame unread")
	}
}

// spendBudget pings until the limiter refuses, so the request that follows is
// refused too, whatever the refill has done since the last one.
func spendBudget(t *testing.T, c *client.Client) {
	t.Helper()
	for range 10 {
		if clientErrorCode(c.Ping(context.Background())) == "RateLimitExceeded" {
			return
		}
	}
	t.Fatal("the rate limiter never refused a ping")
}

// TestRefusedLargeUpload_GetsItsAnswer: a body larger than MaxDrainSize that a
// handler refuses (here: the bucket does not exist) used to close the
// connection before answering, so the caller saw a transport error instead of
// NoSuchBucket. The answer now goes out first.
func TestRefusedLargeUpload_GetsItsAnswer(t *testing.T) {
	env := setup(t)
	c := dialPool1(t, env)
	ctx := context.Background()

	size := proto.MaxDrainSize + 2<<20
	body := bytes.Repeat([]byte("z"), size)
	_, err := c.PutObject(ctx, "no-such-bucket", "k", bytes.NewReader(body), int64(size), nil)
	if clientErrorCode(err) != "NoSuchBucket" {
		t.Fatalf("refused %d-byte upload: got %v, want NoSuchBucket", size, err)
	}

	if _, err := c.CreateBucket(ctx, "bkt"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutObject(ctx, "bkt", "small", bytes.NewReader([]byte("ok")), 2, nil); err != nil {
		t.Fatalf("the upload after a refusal failed — a dead connection was pooled: %v", err)
	}
}

// TestThroughputCap_SlowsTransfersAndKeepsThemWhole caps the token at
// 1 MiB/s with its one-second (1 MiB) burst, then moves 2 MiB up and the same
// 2 MiB back down. A token bucket lets through at most burst + rate × T bytes
// in any window of T, so 4 MiB cannot take less than 3 s however the time
// splits between the two directions — which is what is asserted, rather than a
// per-direction figure a slow run would blur. Both transfers must still arrive
// byte for byte.
func TestThroughputCap_SlowsTransfersAndKeepsThemWhole(t *testing.T) {
	const bps = 1 << 20
	env := setupWith(t, 0, 0, func(s *proto.Server) { s.SetTokenBytesPerSec(bps) })
	c := dialPool1(t, env)
	ctx := context.Background()

	if _, err := c.CreateBucket(ctx, "bkt"); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 2*bps)
	for i := range body {
		body[i] = byte(i * 7)
	}
	sum := sha256.Sum256(body)

	start := time.Now()
	put, err := c.PutObject(ctx, "bkt", "k", bytes.NewReader(body), int64(len(body)), nil)
	if err != nil {
		t.Fatal(err)
	}
	upload := time.Since(start)
	if put.ChecksumSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("the capped upload was stored with a different checksum")
	}

	got, err := c.GetObject(ctx, "bkt", "k")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(got.Body)
	_ = got.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	total := time.Since(start)
	if !bytes.Equal(data, body) {
		t.Fatal("the capped download does not match what was uploaded")
	}

	t.Logf("capped at 1 MiB/s: 2 MiB up in %v, 4 MiB round trip in %v", upload, total)
	if total < 2900*time.Millisecond {
		t.Fatalf("4 MiB through a 1 MiB/s cap with a 1 MiB burst took %v, want at least 3s", total)
	}
}

func byteCount(n int) string {
	if n >= 1<<20 && n%(1<<20) == 0 {
		return itoa(n>>20) + "MiB"
	}
	return itoa(n>>10) + "KiB"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
