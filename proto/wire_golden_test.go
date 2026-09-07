package proto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Golden tests for the v1 wire format.
//
// Every other test in this package runs Encode* and Decode* against each
// other, which means a symmetric change to both sides passes green while
// breaking every peer that did not ship in the same binary. These tests fix
// the BYTES, so they fail on exactly that change.
//
// Two rules keep them useful:
//
//  1. The expected bytes are written by hand, from
//     site/src/content/docs/reference/native-protocol.md. Never regenerate
//     them from the encoder — that reproduces the bug this file exists to
//     catch. There is deliberately no -update flag.
//  2. Length prefixes and counts are always spelled out in hex. Only string
//     payloads are written as text, because []byte("etag") is the literal
//     content, not the encoding of it.

// wire builds an expected byte string from fragments. Each fragment is either
// raw bytes (a length prefix, a count, an integer) or a string payload.
func wire(parts ...any) []byte {
	var out []byte
	for _, p := range parts {
		switch v := p.(type) {
		case []byte:
			out = append(out, v...)
		case string:
			out = append(out, v...)
		case byte:
			out = append(out, v)
		default:
			panic("wire: unsupported fragment type")
		}
	}
	return out
}

// b is shorthand for a literal byte sequence.
func b(bs ...byte) []byte { return bs }

// assertWire compares got against the hand-written want and, on mismatch,
// explains what the failure actually means. A developer who lands here has
// changed the protocol, and the useful output is the decision they now have to
// make — not a diff of two hex blobs.
func assertWire(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if bytes.Equal(got, want) {
		return
	}

	var msg strings.Builder
	msg.WriteString("\n=== WIRE FORMAT CHANGED: " + name + " ===\n\n")
	msg.WriteString("want (" + itoa(len(want)) + " bytes): " + hex.EncodeToString(want) + "\n")
	msg.WriteString("got  (" + itoa(len(got)) + " bytes): " + hex.EncodeToString(got) + "\n")
	if off := firstDiff(got, want); off >= 0 {
		msg.WriteString("first difference at byte " + itoa(off) + "\n")
	}
	msg.WriteString(`
This is not a test you fix by copying the new bytes in.

The v1 encoding is positional: no tags, no field names, no per-record length.
A peer built against the old layout cannot detect the change — it reads one
field too many or too few and gets garbage or errShortBuffer depending on
which direction the skew runs. Nothing on the wire says a version differs,
because the version byte travels only in the handshake.

So pick one, deliberately:

  * The change is an ACCIDENT — revert it.
  * You need a NEW OPERATION — add an opcode instead. That IS compatible: an
    older server answers BadRequest/UnknownOp and keeps the connection open.
    This is the supported path for Range, Copy and Presign.
  * You need a new field on an EXISTING message — it is only safe as a
    trailing field read with Decoder.HasMore, and only makes old-encoder →
    new-decoder work. It does nothing for new-encoder → old-decoder: the old
    peer stops early and silently drops the field. Use it only when the
    default equals the previous behaviour (see skip_etag).
  * The break is genuinely necessary — bump Version to 0x02, so the handshake
    refuses old peers instead of corrupting them, and update the reference doc
    at site/src/content/docs/reference/native-protocol.md.

Then, and only then, update the bytes below to match the documented layout.`)

	t.Fatal(msg.String())
}

func firstDiff(a, bb []byte) int {
	n := min(len(a), len(bb))
	for i := range n {
		if a[i] != bb[i] {
			return i
		}
	}
	if len(a) != len(bb) {
		return n
	}
	return -1
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// --- Handshake ---------------------------------------------------------

func TestGolden_Handshake(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHandshake(&buf, "tok:sec"); err != nil {
		t.Fatalf("WriteHandshake: %v", err)
	}

	want := wire(
		b(0x4A, 0x41, 0x59, 0x00), // magic "JAY\0"
		b(0x01),                   // version
		b(0x00),                   // flags (reserved, always zero)
		b(0x00, 0x07),             // auth_len = 7
		"tok:sec",
	)
	assertWire(t, "client handshake", buf.Bytes(), want)

	if got := buf.Len(); got != HandshakeSize+7 {
		t.Errorf("handshake length = %d, want %d", got, HandshakeSize+7)
	}
}

func TestGolden_HandshakeResponse(t *testing.T) {
	// Every status the server can send. A new status is a wire addition and
	// must be listed here on purpose, not discovered by a peer in production.
	cases := []struct {
		name   string
		status byte
		want   []byte
	}{
		{"ok", HandshakeOK, wire(b(0x4A, 0x41, 0x59, 0x00), b(0x01), b(0x00), b(0x00, 0x00))},
		{"auth failed", HandshakeAuthFailed, wire(b(0x4A, 0x41, 0x59, 0x00), b(0x01), b(0x01), b(0x00, 0x00))},
		{"version mismatch", HandshakeVersionMismatch, wire(b(0x4A, 0x41, 0x59, 0x00), b(0x01), b(0x02), b(0x00, 0x00))},
		{"server busy", HandshakeServerBusy, wire(b(0x4A, 0x41, 0x59, 0x00), b(0x01), b(0x03), b(0x00, 0x00))},
		{"malformed", HandshakeMalformed, wire(b(0x4A, 0x41, 0x59, 0x00), b(0x01), b(0x04), b(0x00, 0x00))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteHandshakeResponse(&buf, tc.status); err != nil {
				t.Fatalf("WriteHandshakeResponse: %v", err)
			}
			assertWire(t, "handshake response ("+tc.name+")", buf.Bytes(), tc.want)
		})
	}
}

// --- Frame header ------------------------------------------------------

func TestGolden_FrameHeader(t *testing.T) {
	var buf bytes.Buffer
	// GetObject, stream 0, 5 bytes of meta, 1 byte of body.
	if err := WriteHeader(&buf, OpGetObject, 0, 5, 1); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}

	want := wire(
		b(0x11),                   // op = GetObject
		b(0x00, 0x00, 0x00, 0x00), // stream_id (reserved in v1)
		b(0x00, 0x00, 0x00, 0x05), // meta_len
		b(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01), // data_len
	)
	assertWire(t, "frame header", buf.Bytes(), want)

	if buf.Len() != HeaderSize {
		t.Errorf("header length = %d, want %d", buf.Len(), HeaderSize)
	}
}

func TestGolden_FrameHeaderEchoesStreamID(t *testing.T) {
	// stream_id is reserved but must survive a round trip unchanged: the
	// server echoes what it received. A future multiplexing version depends
	// on today's implementations not clobbering it.
	var buf bytes.Buffer
	if err := WriteHeader(&buf, StatusOK, 0xDEADBEEF, 0, 0); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}

	want := wire(
		b(0x00),                   // status = OK
		b(0xDE, 0xAD, 0xBE, 0xEF), // stream_id, big-endian
		b(0x00, 0x00, 0x00, 0x00), // meta_len
		b(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00), // data_len
	)
	assertWire(t, "frame header with stream id", buf.Bytes(), want)
}

func TestGolden_WriteFrameCombined(t *testing.T) {
	// The combined writer is an optimisation that must produce byte-identical
	// output to header-then-meta. Its own layout is therefore fixed too.
	var buf bytes.Buffer
	if err := WriteFrameCombined(&buf, StatusNotFound, 0, []byte{0xAA, 0xBB}); err != nil {
		t.Fatalf("WriteFrameCombined: %v", err)
	}

	want := wire(
		b(0x01),                   // status = NotFound
		b(0x00, 0x00, 0x00, 0x00), // stream_id
		b(0x00, 0x00, 0x00, 0x02), // meta_len = 2
		b(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00), // data_len = 0
		b(0xAA, 0xBB), // meta
	)
	assertWire(t, "combined frame", buf.Bytes(), want)

	// And it must agree with the two-step writer, or the optimisation is a
	// second implementation of the format that can drift.
	var split bytes.Buffer
	if err := WriteFrame(&split, StatusNotFound, 0, []byte{0xAA, 0xBB}, nil, 0); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), split.Bytes()) {
		t.Errorf("WriteFrameCombined and WriteFrame disagree:\ncombined %x\nsplit    %x",
			buf.Bytes(), split.Bytes())
	}
}

// --- Primitive encoding ------------------------------------------------

func TestGolden_Primitives(t *testing.T) {
	t.Run("string is uint16-prefixed", func(t *testing.T) {
		e := NewEncoder(nil)
		e.String("hi")
		if err := e.Err(); err != nil {
			t.Fatalf("encode: %v", err)
		}
		assertWire(t, "string", e.Bytes(), wire(b(0x00, 0x02), "hi"))
	})

	t.Run("empty string is a bare zero length", func(t *testing.T) {
		e := NewEncoder(nil)
		e.String("")
		assertWire(t, "empty string", e.Bytes(), b(0x00, 0x00))
	})

	t.Run("int64 is 8 bytes big-endian", func(t *testing.T) {
		e := NewEncoder(nil)
		e.Int64(1)
		assertWire(t, "int64", e.Bytes(), b(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01))
	})

	t.Run("negative int64 is two's complement", func(t *testing.T) {
		e := NewEncoder(nil)
		e.Int64(-1)
		assertWire(t, "negative int64", e.Bytes(), b(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF))
	})

	t.Run("int32 is 4 bytes big-endian", func(t *testing.T) {
		e := NewEncoder(nil)
		e.Int32(258)
		assertWire(t, "int32", e.Bytes(), b(0x00, 0x00, 0x01, 0x02))
	})

	t.Run("bool is one byte", func(t *testing.T) {
		e := NewEncoder(nil)
		e.Bool(true)
		e.Bool(false)
		assertWire(t, "bool", e.Bytes(), b(0x01, 0x00))
	})

	t.Run("string list is count-prefixed", func(t *testing.T) {
		e := NewEncoder(nil)
		e.Strings([]string{"a", "bc"})
		assertWire(t, "string list", e.Bytes(), wire(
			b(0x00, 0x02), // count
			b(0x00, 0x01), "a",
			b(0x00, 0x02), "bc",
		))
	})

	t.Run("int list is count-prefixed with 4-byte elements", func(t *testing.T) {
		e := NewEncoder(nil)
		e.Ints([]int{1, 2})
		assertWire(t, "int list", e.Bytes(), wire(
			b(0x00, 0x02),
			b(0x00, 0x00, 0x00, 0x01),
			b(0x00, 0x00, 0x00, 0x02),
		))
	})

	t.Run("single-entry map", func(t *testing.T) {
		// One entry only: Go map iteration order is unspecified, so a golden
		// test over two entries would be flaky rather than strict.
		e := NewEncoder(nil)
		e.StringMap(map[string]string{"k": "v"})
		assertWire(t, "string map", e.Bytes(), wire(
			b(0x00, 0x01), // count
			b(0x00, 0x01), "k",
			b(0x00, 0x01), "v",
		))
	})

	t.Run("empty map is a bare zero count", func(t *testing.T) {
		e := NewEncoder(nil)
		e.StringMap(nil)
		assertWire(t, "empty map", e.Bytes(), b(0x00, 0x00))
	})
}

// --- Message layouts ---------------------------------------------------

func TestGolden_BucketKey(t *testing.T) {
	got, err := EncodeBucketKey("bkt", "key")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "BucketKey", got, wire(
		b(0x00, 0x03), "bkt",
		b(0x00, 0x03), "key",
	))
}

func TestGolden_Bucket(t *testing.T) {
	got, err := EncodeBucket("bkt")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "Bucket", got, wire(b(0x00, 0x03), "bkt"))
}

func TestGolden_PutObjectRequest(t *testing.T) {
	got, err := EncodePutObjectRequest("bkt", "key", "text/plain", nil, false)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "PutObjectRequest", got, wire(
		b(0x00, 0x03), "bkt",
		b(0x00, 0x03), "key",
		b(0x00, 0x0A), "text/plain",
		b(0x00, 0x00), // metadata: empty map
		b(0x00),       // skip_etag = false
	))
}

func TestGolden_PutObjectRequestSkipETagIsTrailing(t *testing.T) {
	// skip_etag is the one trailing optional field in v1. The guarantee is
	// that a request WITHOUT it decodes to false — that is what makes an old
	// client talking to a new server safe. Fix the truncated form in bytes.
	full, err := EncodePutObjectRequest("b", "k", "", nil, true)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "PutObjectRequest with skip_etag", full, wire(
		b(0x00, 0x01), "b",
		b(0x00, 0x01), "k",
		b(0x00, 0x00), // content_type: empty
		b(0x00, 0x00), // metadata: empty map
		b(0x01),       // skip_etag = true
	))

	// A pre-skip_etag encoder produced exactly this: the same bytes minus the
	// trailing flag.
	legacy := wire(
		b(0x00, 0x01), "b",
		b(0x00, 0x01), "k",
		b(0x00, 0x00),
		b(0x00, 0x00),
	)
	_, _, _, _, skipETag, err := DecodePutObjectRequest(legacy)
	if err != nil {
		t.Fatalf("decoding a pre-skip_etag request must succeed, got %v", err)
	}
	if skipETag {
		t.Error("a request with no skip_etag byte must decode to false")
	}
}

func TestGolden_PutResponse(t *testing.T) {
	got, err := EncodePutResponse("et", "cs")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "PutResponse", got, wire(
		b(0x00, 0x02), "et",
		b(0x00, 0x02), "cs",
	))
}

func TestGolden_ObjectInfo(t *testing.T) {
	got, err := EncodeObjectInfo("text/plain", 11, "et", "cs", "2026-01-01T00:00:00Z", nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "ObjectInfo", got, wire(
		b(0x00, 0x0A), "text/plain",
		b(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B), // size = 11
		b(0x00, 0x02), "et",
		b(0x00, 0x02), "cs",
		b(0x00, 0x14), "2026-01-01T00:00:00Z", // 20 bytes
		b(0x00, 0x00), // metadata: empty map
	))
}

func TestGolden_Error(t *testing.T) {
	got := EncodeError("nope", "NoSuchKey")
	assertWire(t, "Error", got, wire(
		b(0x00, 0x04), "nope",
		b(0x00, 0x09), "NoSuchKey",
	))
}

func TestGolden_BucketInfo(t *testing.T) {
	got, err := EncodeBucketInfo("id", "nm", "2026-01-01T00:00:00Z", "private")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "BucketInfo", got, wire(
		b(0x00, 0x02), "id",
		b(0x00, 0x02), "nm",
		b(0x00, 0x14), "2026-01-01T00:00:00Z",
		b(0x00, 0x07), "private",
	))
}

func TestGolden_ListObjectsRequest(t *testing.T) {
	got, err := EncodeListObjectsRequest("bkt", "p/", "/", "aft", 100)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "ListObjectsRequest", got, wire(
		b(0x00, 0x03), "bkt",
		b(0x00, 0x02), "p/",
		b(0x00, 0x01), "/",
		b(0x00, 0x03), "aft",
		b(0x00, 0x00, 0x00, 0x64), // max_keys = 100
	))
}

func TestGolden_ListObjectsResponse(t *testing.T) {
	got, err := EncodeListObjectsResponse(
		[]ListObjectEntry{{
			Key:            "k",
			Size:           7,
			ETag:           "et",
			ChecksumSHA256: "cs",
			LastModified:   "2026-01-01T00:00:00Z",
			ContentType:    "text/plain",
		}},
		[]string{"p/"},
		true,
		"next",
	)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "ListObjectsResponse", got, wire(
		b(0x00, 0x01), // object count
		b(0x00, 0x01), "k",
		b(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07), // size
		b(0x00, 0x02), "et",
		b(0x00, 0x02), "cs",
		b(0x00, 0x14), "2026-01-01T00:00:00Z",
		b(0x00, 0x0A), "text/plain",
		b(0x00, 0x01), // common prefix count
		b(0x00, 0x02), "p/",
		b(0x01), // is_truncated
		b(0x00, 0x04), "next",
	))
}

func TestGolden_ListObjectsResponseEmpty(t *testing.T) {
	// The empty listing is the most common response on the wire and its
	// encoding is not obvious: zero counts still occupy their two bytes.
	got, err := EncodeListObjectsResponse(nil, nil, false, "")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "empty ListObjectsResponse", got, wire(
		b(0x00, 0x00), // no objects
		b(0x00, 0x00), // no common prefixes
		b(0x00),       // is_truncated = false
		b(0x00, 0x00), // next_start_after = ""
	))
}

func TestGolden_CreateMultipartRequest(t *testing.T) {
	got, err := EncodeCreateMultipartRequest("bkt", "key", "text/plain")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "CreateMultipartRequest", got, wire(
		b(0x00, 0x03), "bkt",
		b(0x00, 0x03), "key",
		b(0x00, 0x0A), "text/plain",
	))
}

func TestGolden_UploadPartRequest(t *testing.T) {
	got, err := EncodeUploadPartRequest("bkt", "key", "up", 3)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "UploadPartRequest", got, wire(
		b(0x00, 0x03), "bkt",
		b(0x00, 0x03), "key",
		b(0x00, 0x02), "up",
		b(0x00, 0x00, 0x00, 0x03), // part_number
	))
}

func TestGolden_CompleteMultipartRequest(t *testing.T) {
	got, err := EncodeCompleteMultipartRequest("bkt", "key", "up", []int{1, 2})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "CompleteMultipartRequest", got, wire(
		b(0x00, 0x03), "bkt",
		b(0x00, 0x03), "key",
		b(0x00, 0x02), "up",
		b(0x00, 0x02),             // part count
		b(0x00, 0x00, 0x00, 0x01), // part 1
		b(0x00, 0x00, 0x00, 0x02), // part 2
	))
}

func TestGolden_BucketKeyUpload(t *testing.T) {
	got, err := EncodeBucketKeyUpload("bkt", "key", "up")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "BucketKeyUpload", got, wire(
		b(0x00, 0x03), "bkt",
		b(0x00, 0x03), "key",
		b(0x00, 0x02), "up",
	))
}

func TestGolden_CompleteMultipartResponse(t *testing.T) {
	got, err := EncodeCompleteMultipartResponse("et", "cs", 258)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "CompleteMultipartResponse", got, wire(
		b(0x00, 0x02), "et",
		b(0x00, 0x02), "cs",
		b(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02), // size = 258
	))
}

func TestGolden_ListPartsResponse(t *testing.T) {
	got, err := EncodeListPartsResponse([]PartInfoEntry{{
		PartNumber:     1,
		Size:           5,
		ETag:           "et",
		ChecksumSHA256: "cs",
	}})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "ListPartsResponse", got, wire(
		b(0x00, 0x01),             // part count
		b(0x00, 0x00, 0x00, 0x01), // part_number
		b(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05), // size
		b(0x00, 0x02), "et",
		b(0x00, 0x02), "cs",
	))
}

func TestGolden_BucketList(t *testing.T) {
	got, err := EncodeBucketList([]string{"b1", "b2"}, []string{"t1", "t2"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	assertWire(t, "BucketList", got, wire(
		b(0x00, 0x02), // count
		b(0x00, 0x02), "b1",
		b(0x00, 0x02), "t1",
		b(0x00, 0x02), "b2",
		b(0x00, 0x02), "t2",
	))
}

// --- Constants ---------------------------------------------------------

// TestGolden_ProtocolConstants pins the numeric values themselves. Renaming a
// constant is free; renumbering one silently repoints every peer.
func TestGolden_ProtocolConstants(t *testing.T) {
	cases := []struct {
		name string
		got  byte
		want byte
	}{
		{"Version", Version, 0x01},

		{"OpCreateBucket", OpCreateBucket, 0x01},
		{"OpDeleteBucket", OpDeleteBucket, 0x02},
		{"OpHeadBucket", OpHeadBucket, 0x03},
		{"OpListBuckets", OpListBuckets, 0x04},
		{"OpPutObject", OpPutObject, 0x10},
		{"OpGetObject", OpGetObject, 0x11},
		{"OpHeadObject", OpHeadObject, 0x12},
		{"OpDeleteObject", OpDeleteObject, 0x13},
		{"OpListObjects", OpListObjects, 0x14},
		{"OpCreateMultipartUpload", OpCreateMultipartUpload, 0x20},
		{"OpUploadPart", OpUploadPart, 0x21},
		{"OpCompleteMultipart", OpCompleteMultipart, 0x22},
		{"OpAbortMultipart", OpAbortMultipart, 0x23},
		{"OpListParts", OpListParts, 0x24},
		{"OpPing", OpPing, 0xFF},

		{"StatusOK", StatusOK, 0x00},
		{"StatusNotFound", StatusNotFound, 0x01},
		{"StatusConflict", StatusConflict, 0x02},
		{"StatusBadRequest", StatusBadRequest, 0x03},
		{"StatusForbidden", StatusForbidden, 0x04},
		{"StatusInternal", StatusInternal, 0x05},

		{"HandshakeOK", HandshakeOK, 0x00},
		{"HandshakeAuthFailed", HandshakeAuthFailed, 0x01},
		{"HandshakeVersionMismatch", HandshakeVersionMismatch, 0x02},
		{"HandshakeServerBusy", HandshakeServerBusy, 0x03},
		{"HandshakeMalformed", HandshakeMalformed, 0x04},
	}

	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = 0x%02X, want 0x%02X — renumbering a protocol constant "+
				"silently repoints every peer; add a new value instead", tc.name, tc.got, tc.want)
		}
	}

	if Magic != 0x4A415900 {
		t.Errorf("Magic = 0x%08X, want 0x4A415900", Magic)
	}
	if HeaderSize != 17 {
		t.Errorf("HeaderSize = %d, want 17", HeaderSize)
	}
	if HandshakeSize != 8 {
		t.Errorf("HandshakeSize = %d, want 8", HandshakeSize)
	}
	if HandshakeResponseSize != 8 {
		t.Errorf("HandshakeResponseSize = %d, want 8", HandshakeResponseSize)
	}
	if MaxMetaSize != 1<<20 {
		t.Errorf("MaxMetaSize = %d, want %d", MaxMetaSize, 1<<20)
	}
}
