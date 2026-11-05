package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// ── AWS's published vectors ─────────────────────────────────────────────────
//
// Transcribed from the SigV4 streaming examples in the S3 API reference
// ("Signature calculations for the Authorization header: transferring payload
// in multiple chunks", and its trailing-header counterpart). The same numbers
// are pinned by minio-go's signer tests (pkg/signer/request-signature-
// streaming_test.go), which is a second, independent transcription.
//
// The example: PUT /examplebucket/chunkObject.txt on s3.amazonaws.com,
// 20130524T000000Z, us-east-1, 66560 bytes of 'a' sent as a 65536-byte chunk,
// a 1024-byte chunk and the final empty one.
const (
	awsStreamSecret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	awsStreamAmzDate   = "20130524T000000Z"
	awsStreamDateStamp = "20130524"
	awsStreamRegion    = "us-east-1"
	awsStreamScope     = "20130524/us-east-1/s3/aws4_request"

	awsStreamSeedSignature   = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"
	awsStreamChunk1Signature = "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648"
	awsStreamChunk2Signature = "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497"
	awsStreamFinalSignature  = "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9"

	// The trailing-header example: the trailer that follows a final chunk whose
	// signature is awsTrailerPrevSignature.
	awsTrailerPrevSignature = "e05ab64fe1dfdbf0b5870abbaabdb063c371d4e96f2767e6934d90529c5ae850"
	awsTrailerCanonical     = "x-amz-checksum-crc32c:wdBDMA==\n"
	awsTrailerSignature     = "41e14ac611e27a8bb3d66c3bad6856f209297767d5dd4fc87d8fa9e422e03faf"
)

func awsStreamSigner(prev string) *chunkSigner {
	return &chunkSigner{
		key:     deriveSigningKey(awsStreamSecret, awsStreamDateStamp, awsStreamRegion, sigV4Service),
		amzDate: awsStreamAmzDate,
		scope:   awsStreamScope,
		prev:    prev,
	}
}

// The seed signature is an ordinary SigV4 header signature whose payload hash
// is the STREAMING-* literal. Pinning it proves the canonical request jay
// builds for a streaming upload is the one AWS signs.
func TestStreamingSeedSignature_MatchesAWSPublishedVector(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "/examplebucket/chunkObject.txt", nil)
	r.Host = "s3.amazonaws.com"
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("Content-Length", "66824")
	r.Header.Set("x-amz-content-sha256", StreamingSignedPayload)
	r.Header.Set("x-amz-date", awsStreamAmzDate)
	r.Header.Set("x-amz-decoded-content-length", "66560")
	r.Header.Set("x-amz-storage-class", "REDUCED_REDUNDANCY")

	signed := "content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class"
	canonical := buildCanonicalRequest(r, signed)
	stringToSign := buildStringToSign(awsStreamDateStamp, awsStreamAmzDate, awsStreamRegion, canonical)
	key := deriveSigningKey(awsStreamSecret, awsStreamDateStamp, awsStreamRegion, sigV4Service)
	if got := hex.EncodeToString(hmacSHA256(key, []byte(stringToSign))); got != awsStreamSeedSignature {
		t.Fatalf("seed signature\n got %s\nwant %s\ncanonical request:\n%s", got, awsStreamSeedSignature, canonical)
	}
}

func TestChunkSignatures_MatchAWSPublishedVector(t *testing.T) {
	s := awsStreamSigner(awsStreamSeedSignature)

	for _, step := range []struct {
		name string
		data []byte
		want string
	}{
		{"chunk 1 (65536 bytes)", bytes.Repeat([]byte("a"), 65536), awsStreamChunk1Signature},
		{"chunk 2 (1024 bytes)", bytes.Repeat([]byte("a"), 1024), awsStreamChunk2Signature},
		{"final chunk", nil, awsStreamFinalSignature},
	} {
		sum := sha256.Sum256(step.data)
		got := s.chunkSignature(sum[:])
		if got != step.want {
			t.Fatalf("%s\n got %s\nwant %s", step.name, got, step.want)
		}
		s.prev = got
	}
}

func TestTrailerSignature_MatchesAWSPublishedVector(t *testing.T) {
	s := awsStreamSigner(awsTrailerPrevSignature)
	sum := sha256.Sum256([]byte(awsTrailerCanonical))
	if got := s.trailerSignature(sum[:]); got != awsTrailerSignature {
		t.Fatalf("trailer signature\n got %s\nwant %s", got, awsTrailerSignature)
	}
}

// The AWS example body, framed with the published signatures as literal text —
// nothing here is computed by the code under test — decodes to its 66560
// bytes, and only then reports EOF.
func TestChunkedReader_DecodesAWSPublishedExample(t *testing.T) {
	data := bytes.Repeat([]byte("a"), 66560)
	var body bytes.Buffer
	body.WriteString("10000;chunk-signature=" + awsStreamChunk1Signature + "\r\n")
	body.Write(data[:65536])
	body.WriteString("\r\n400;chunk-signature=" + awsStreamChunk2Signature + "\r\n")
	body.Write(data[65536:])
	body.WriteString("\r\n0;chunk-signature=" + awsStreamFinalSignature + "\r\n\r\n")
	if body.Len() != 66824 {
		t.Fatalf("framed example is %d bytes, AWS's Content-Length is 66824", body.Len())
	}

	cr := newChunkedReader(io.NopCloser(&body),
		StreamingPayload{Mode: StreamingSignedPayload, Signed: true, DecodedLength: 66560},
		awsStreamSigner(awsStreamSeedSignature))
	got, err := io.ReadAll(cr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("decoded %d bytes, want the 66560 of the example", len(got))
	}
}

// ── A test encoder ──────────────────────────────────────────────────────────

// trailerStyle is how a client lays out the trailer section. Both occur in the
// wild and both must decode.
type trailerStyle int

const (
	// awsStyle: every trailer "name:value\r\n", then the signature line, then
	// CRLF. The AWS SDKs.
	awsStyle trailerStyle = iota
	// minioStyle: every trailer "name:value\n", then CRLF, then the signature
	// line and CRLF CRLF. minio-go.
	minioStyle
)

// frame encodes data as an aws-chunked body: chunks of chunkSize bytes (the
// last one shorter), signed when s is non-nil, the final empty chunk, and the
// trailer when trailerMode is set. s is copied, so the caller's chain is not
// advanced.
func frame(data []byte, chunkSize int, s *chunkSigner, trailerMode bool, trailers []string, style trailerStyle) []byte {
	var signer *chunkSigner
	if s != nil {
		cp := *s
		signer = &cp
	}
	var b bytes.Buffer
	writeChunk := func(chunk []byte) {
		b.WriteString(strconv.FormatInt(int64(len(chunk)), 16))
		if signer != nil {
			sum := sha256.Sum256(chunk)
			sig := signer.chunkSignature(sum[:])
			signer.prev = sig
			b.WriteString(";chunk-signature=" + sig)
		}
		b.WriteString("\r\n")
		if len(chunk) > 0 {
			b.Write(chunk)
			b.WriteString("\r\n")
		}
	}
	for off := 0; off < len(data); off += chunkSize {
		writeChunk(data[off:min(off+chunkSize, len(data))])
	}
	writeChunk(nil)

	if !trailerMode {
		b.WriteString("\r\n")
		return b.Bytes()
	}
	var canonical strings.Builder
	for _, line := range trailers {
		canonical.WriteString(line + "\n")
		if style == minioStyle {
			b.WriteString(line + "\n")
		} else {
			b.WriteString(line + "\r\n")
		}
	}
	if signer != nil {
		sum := sha256.Sum256([]byte(canonical.String()))
		sig := signer.trailerSignature(sum[:])
		if style == minioStyle {
			b.WriteString("\r\n")
		}
		b.WriteString(trailerSignatureName + ":" + sig + "\r\n")
	}
	if style == minioStyle && signer == nil {
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

// testSigner is a chain for a made-up request.
func testSigner() *chunkSigner {
	return &chunkSigner{
		key:     deriveSigningKey("test-secret", "20260923", "us-east-1", sigV4Service),
		amzDate: "20260923T120000Z",
		scope:   "20260923/us-east-1/s3/aws4_request",
		prev:    strings.Repeat("0", signatureHexLen),
	}
}

func signedPayload(n int) StreamingPayload {
	return StreamingPayload{Mode: StreamingSignedPayload, Signed: true, DecodedLength: int64(n)}
}

func testData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return b
}

// decodeAll reads a ChunkedReader to the end and returns what it produced and
// the error that ended it (nil for a clean EOF).
func decodeAll(cr *ChunkedReader) ([]byte, error) {
	return io.ReadAll(cr)
}

func wantKind(t *testing.T, err, kind error) {
	t.Helper()
	if err == nil {
		t.Fatalf("want %v, got a clean end of body", kind)
	}
	if !errors.Is(err, kind) {
		t.Fatalf("want %v, got %v", kind, err)
	}
}

// ── Decoding ────────────────────────────────────────────────────────────────

func TestChunkedReader_SignedRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		name      string
		size      int
		chunkSize int
	}{
		{"empty object", 0, 64 << 10},
		{"one chunk", 15, 64 << 10},
		{"exactly one full chunk", 64 << 10, 64 << 10},
		{"many chunks", 200_000, 64 << 10},
		{"one-byte chunks", 300, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := testData(tc.size)
			body := frame(data, tc.chunkSize, testSigner(), false, nil, awsStyle)
			cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)), signedPayload(tc.size), testSigner())
			got, err := decodeAll(cr)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("decoded %d bytes, want %d identical ones", len(got), len(data))
			}
		})
	}
}

// Small reads must not change anything: a reader that hands out one byte at a
// time crosses every chunk boundary mid-Read.
func TestChunkedReader_OneByteReads(t *testing.T) {
	data := testData(1000)
	body := frame(data, 97, testSigner(), false, nil, awsStyle)
	cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)), signedPayload(len(data)), testSigner())

	var got []byte
	buf := make([]byte, 1)
	for {
		n, err := cr.Read(buf)
		got = append(got, buf[:n]...)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if !bytes.Equal(got, data) {
		t.Fatal("one-byte reads decoded different bytes")
	}
}

// A signature that fails in chunk N — first, middle or the final empty one —
// ends the body with ErrChunkSignatureMismatch. The reader never reports EOF,
// which is what keeps the write path from committing.
func TestChunkedReader_TamperedSignatureNeverReachesEOF(t *testing.T) {
	data := testData(3 * 1000)
	for _, tc := range []struct {
		name  string
		chunk int // 1-based; 4 is the final empty chunk
	}{
		{"first chunk", 1},
		{"middle chunk", 2},
		{"last data chunk", 3},
		{"final empty chunk", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := frame(data, 1000, testSigner(), false, nil, awsStyle)
			body = flipSignature(t, body, tc.chunk)
			cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)), signedPayload(len(data)), testSigner())
			_, err := decodeAll(cr)
			wantKind(t, err, ErrChunkSignatureMismatch)

			// Sticky: nothing after the failure can resurrect the stream.
			if n, again := cr.Read(make([]byte, 10)); n != 0 || !errors.Is(again, ErrChunkSignatureMismatch) {
				t.Fatalf("after a failure Read returned (%d, %v)", n, again)
			}
		})
	}
}

// flipSignature changes one hex digit of the nth chunk-signature in body.
func flipSignature(t *testing.T, body []byte, n int) []byte {
	t.Helper()
	out := bytes.Clone(body)
	marker := []byte(";chunk-signature=")
	off := 0
	for i := range n {
		idx := bytes.Index(out[off:], marker)
		if idx < 0 {
			t.Fatalf("body has fewer than %d chunk signatures", n)
		}
		off += idx + len(marker)
		if i == n-1 {
			if out[off] == '0' {
				out[off] = '1'
			} else {
				out[off] = '0'
			}
		}
	}
	return out
}

// The same chain over data that was altered in flight: the signature is intact,
// the chunk it describes is not.
func TestChunkedReader_TamperedDataRejected(t *testing.T) {
	data := testData(2500)
	body := frame(data, 1000, testSigner(), false, nil, awsStyle)
	i := bytes.Index(body, data[1200:1210])
	body[i] ^= 0x01
	cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)), signedPayload(len(data)), testSigner())
	_, err := decodeAll(cr)
	wantKind(t, err, ErrChunkSignatureMismatch)
}

// A signature from ANOTHER chain (a different seed, i.e. a different request)
// verifies nothing, even when every chunk is internally consistent. This is
// the replay case: chunks cut from one upload and pasted into another.
func TestChunkedReader_ChunksFromAnotherRequestRejected(t *testing.T) {
	data := testData(100)
	other := testSigner()
	other.prev = strings.Repeat("f", signatureHexLen)
	body := frame(data, 64, other, false, nil, awsStyle)
	cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)), signedPayload(len(data)), testSigner())
	_, err := decodeAll(cr)
	wantKind(t, err, ErrChunkSignatureMismatch)
}

func TestChunkedReader_DecodedLengthMismatch(t *testing.T) {
	data := testData(100)
	body := frame(data, 64, testSigner(), false, nil, awsStyle)

	t.Run("declared more than sent", func(t *testing.T) {
		cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)), signedPayload(101), testSigner())
		_, err := decodeAll(cr)
		wantKind(t, err, ErrDecodedLengthMismatch)
	})
	t.Run("declared less than sent", func(t *testing.T) {
		cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)), signedPayload(99), testSigner())
		got, err := decodeAll(cr)
		wantKind(t, err, ErrDecodedLengthMismatch)
		// Refused at the chunk header, before its data is read.
		if len(got) > 64 {
			t.Fatalf("decoded %d bytes past the chunk that overran the declared length", len(got))
		}
	})
}

// A chunk size is validated against what remains of the declared length
// before a byte is read, and never drives an allocation. A 1 TiB chunk
// header over a 10-byte body costs nothing.
func TestChunkedReader_HugeChunkSizeAllocatesNothing(t *testing.T) {
	body := []byte("10000000000;chunk-signature=" + strings.Repeat("a", signatureHexLen) + "\r\n0123456789")
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)),
		StreamingPayload{Mode: StreamingSignedPayload, Signed: true, DecodedLength: 1 << 40}, testSigner())
	_, err := decodeAll(cr)
	runtime.ReadMemStats(&after)
	wantKind(t, err, ErrChunkedBodyMalformed)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Fatalf("decoding a 1 TiB chunk header allocated %d bytes", grew)
	}
}

func TestChunkedReader_MalformedFraming(t *testing.T) {
	sig := strings.Repeat("a", signatureHexLen)
	for _, tc := range []struct {
		name     string
		body     string
		unsigned bool
		declared int64
	}{
		{name: "empty body", body: ""},
		{name: "hex garbage", body: "zz;chunk-signature=" + sig + "\r\n"},
		{name: "0x prefix", body: "0x5;chunk-signature=" + sig + "\r\n"},
		{name: "negative size", body: "-5;chunk-signature=" + sig + "\r\n"},
		{name: "space in size", body: " 5;chunk-signature=" + sig + "\r\n"},
		{name: "no size", body: ";chunk-signature=" + sig + "\r\n"},
		{name: "17 hex digits", body: "00000000000000005;chunk-signature=" + sig + "\r\n"},
		{name: "header line too long", body: strings.Repeat("1", 10<<10) + "\r\n"},
		{name: "LF without CR", body: "5;chunk-signature=" + sig + "\n"},
		{name: "missing signature", body: "5\r\nhello\r\n"},
		{name: "unknown extension", body: "5;foo=bar\r\nhello\r\n"},
		{name: "short signature", body: "5;chunk-signature=abc\r\nhello\r\n"},
		{name: "non-hex signature", body: "5;chunk-signature=" + strings.Repeat("z", signatureHexLen) + "\r\nhello\r\n"},
		{name: "signature with an extra extension", body: "5;chunk-signature=" + sig + ";x=y\r\nhello\r\n"},
		{name: "data not followed by CRLF", body: "5;chunk-signature=" + sig + "\r\nhelloX\r\n"},
		{name: "body ends inside a chunk", body: "5;chunk-signature=" + sig + "\r\nhel"},
		{name: "body ends before the final chunk", body: "5;chunk-signature=" + sig + "\r\nhello\r\n"},
		{name: "extension in the unsigned mode", body: "5;chunk-signature=" + sig + "\r\nhello\r\n", unsigned: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			declared := tc.declared
			if declared == 0 {
				declared = 5
			}
			p := StreamingPayload{Mode: StreamingSignedPayload, Signed: true, DecodedLength: declared}
			s := testSigner()
			if tc.unsigned {
				p = StreamingPayload{Mode: StreamingUnsignedPayloadTrailer, Trailer: true, DecodedLength: declared}
				s = nil
			}
			cr := newChunkedReader(io.NopCloser(strings.NewReader(tc.body)), p, s)
			_, err := decodeAll(cr)
			// A malformed body can also trip a signature check first (its
			// placeholder signature is wrong by construction); either way it
			// must not end cleanly.
			if err == nil {
				t.Fatal("a malformed body decoded to a clean end")
			}
			if !errors.Is(err, ErrChunkedBodyMalformed) && !errors.Is(err, ErrChunkSignatureMismatch) {
				t.Fatalf("want a malformed-body error, got %v", err)
			}
		})
	}
}

// After the final chunk of the non-trailer mode comes exactly CRLF and the end
// of the body: anything else is refused, not ignored.
func TestChunkedReader_GarbageAfterFinalChunk(t *testing.T) {
	data := testData(10)
	body := frame(data, 64, testSigner(), false, nil, awsStyle)
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"trailing bytes", append(bytes.Clone(body), "extra"...)},
		{"missing final CRLF", body[:len(body)-2]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cr := newChunkedReader(io.NopCloser(bytes.NewReader(tc.body)), signedPayload(len(data)), testSigner())
			_, err := decodeAll(cr)
			wantKind(t, err, ErrChunkedBodyMalformed)
		})
	}
}

// ── Trailers ────────────────────────────────────────────────────────────────

type trailerCapture struct {
	names  []string
	values []string
}

func (c *trailerCapture) handler(name, value string) error {
	c.names = append(c.names, name)
	c.values = append(c.values, value)
	return nil
}

func trailerPayload(n int, signed bool, declared ...string) StreamingPayload {
	p := StreamingPayload{Mode: StreamingUnsignedPayloadTrailer, Trailer: true, DecodedLength: int64(n), Trailers: declared}
	if signed {
		p.Mode, p.Signed = StreamingSignedPayloadTrailer, true
	}
	return p
}

func TestChunkedReader_TrailersDelivered(t *testing.T) {
	data := testData(70_000)
	const line = "x-amz-checksum-crc32c:wdBDMA=="
	for _, tc := range []struct {
		name   string
		signed bool
		style  trailerStyle
	}{
		{"unsigned, AWS SDK layout", false, awsStyle},
		{"unsigned, minio-go layout", false, minioStyle},
		{"signed, AWS SDK layout", true, awsStyle},
		{"signed, minio-go layout", true, minioStyle},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s *chunkSigner
			if tc.signed {
				s = testSigner()
			}
			body := frame(data, 64<<10, s, true, []string{line}, tc.style)
			cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)),
				trailerPayload(len(data), tc.signed, "x-amz-checksum-crc32c"), s)
			var got trailerCapture
			cr.SetTrailerHandler(got.handler)
			out, err := decodeAll(cr)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(out, data) {
				t.Fatal("decoded data differs")
			}
			if len(got.names) != 1 || got.names[0] != "x-amz-checksum-crc32c" || got.values[0] != "wdBDMA==" {
				t.Fatalf("trailers delivered: %v = %v", got.names, got.values)
			}
		})
	}
}

// An unsigned trailer mode with nothing declared is the unsigned payload with
// framing: legal, and it carries no trailer to deliver.
func TestChunkedReader_UnsignedTrailerModeWithoutTrailers(t *testing.T) {
	data := testData(10)
	body := frame(data, 64, nil, true, nil, awsStyle)
	cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)), trailerPayload(len(data), false), nil)
	out, err := decodeAll(cr)
	if err != nil || !bytes.Equal(out, data) {
		t.Fatalf("decode: %v (%d bytes)", err, len(out))
	}
}

func TestChunkedReader_SignedTrailerTampering(t *testing.T) {
	data := testData(100)
	const line = "x-amz-checksum-crc32:AAAAAA=="
	body := frame(data, 64, testSigner(), true, []string{line}, awsStyle)

	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
		kind   error
	}{
		{"trailer value altered", func(b []byte) []byte {
			return bytes.Replace(b, []byte("AAAAAA=="), []byte("BBBBBB=="), 1)
		}, ErrChunkSignatureMismatch},
		{"trailer signature altered", func(b []byte) []byte {
			i := bytes.Index(b, []byte(trailerSignatureName+":")) + len(trailerSignatureName) + 1
			out := bytes.Clone(b)
			out[i] ^= 0x01
			return out
		}, ErrChunkSignatureMismatch},
		{"trailer signature removed", func(b []byte) []byte {
			i := bytes.Index(b, []byte(trailerSignatureName+":"))
			return append(bytes.Clone(b[:i]), "\r\n"...)
		}, ErrChunkedBodyMalformed},
		{"a line after the signature", func(b []byte) []byte {
			return append(bytes.Clone(b[:len(b)-2]), "x-amz-checksum-crc32:AAAAAA==\r\n\r\n"...)
		}, ErrChunkedBodyMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cr := newChunkedReader(io.NopCloser(bytes.NewReader(tc.mutate(body))),
				trailerPayload(len(data), true, "x-amz-checksum-crc32"), testSigner())
			var got trailerCapture
			cr.SetTrailerHandler(got.handler)
			_, err := decodeAll(cr)
			wantKind(t, err, tc.kind)
			if len(got.names) != 0 {
				t.Fatalf("a trailer that did not verify was delivered: %v", got.names)
			}
		})
	}
}

// The trailer is held to exactly what x-amz-trailer declared.
func TestChunkedReader_TrailerMustMatchDeclaration(t *testing.T) {
	data := testData(10)
	for _, tc := range []struct {
		name     string
		declared []string
		sent     []string
	}{
		{"declared, never sent", []string{"x-amz-checksum-crc32"}, nil},
		{"sent, never declared", nil, []string{"x-amz-checksum-crc32:AAAAAA=="}},
		{"sent twice", []string{"x-amz-checksum-crc32"}, []string{"x-amz-checksum-crc32:AAAAAA==", "x-amz-checksum-crc32:AAAAAA=="}},
		{"a different one sent", []string{"x-amz-checksum-crc32"}, []string{"x-amz-checksum-sha1:AAAAAAAAAAAAAAAAAAAAAAAAAAA="}},
		{"no colon", []string{"x-amz-checksum-crc32"}, []string{"x-amz-checksum-crc32"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := frame(data, 64, nil, true, tc.sent, awsStyle)
			cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)), trailerPayload(len(data), false, tc.declared...), nil)
			var got trailerCapture
			cr.SetTrailerHandler(got.handler)
			_, err := decodeAll(cr)
			wantKind(t, err, ErrChunkedBodyMalformed)
		})
	}
}

// A trailer with nobody to verify it is refused, never accepted unchecked.
func TestChunkedReader_TrailerWithoutHandlerRefused(t *testing.T) {
	data := testData(10)
	body := frame(data, 64, nil, true, []string{"x-amz-checksum-crc32:AAAAAA=="}, awsStyle)
	cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)), trailerPayload(len(data), false, "x-amz-checksum-crc32"), nil)
	_, err := decodeAll(cr)
	wantKind(t, err, ErrChunkedBodyUnsupported)
}

// Whatever the handler refuses ends the body with the handler's error, and
// still no EOF.
func TestChunkedReader_TrailerHandlerErrorPropagates(t *testing.T) {
	data := testData(10)
	body := frame(data, 64, nil, true, []string{"x-amz-checksum-crc32:AAAAAA=="}, awsStyle)
	cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)), trailerPayload(len(data), false, "x-amz-checksum-crc32"), nil)
	sentinel := errors.New("digest does not match")
	cr.SetTrailerHandler(func(string, string) error { return sentinel })
	_, err := decodeAll(cr)
	if !errors.Is(err, sentinel) {
		t.Fatalf("want the handler's error, got %v", err)
	}
}

func TestChunkedReader_TrailerSectionBounded(t *testing.T) {
	data := testData(10)
	body := frame(data, 64, nil, true, []string{"x-amz-checksum-crc32:" + strings.Repeat("A", 8<<10)}, awsStyle)
	cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)), trailerPayload(len(data), false, "x-amz-checksum-crc32"), nil)
	var got trailerCapture
	cr.SetTrailerHandler(got.handler)
	_, err := decodeAll(cr)
	wantKind(t, err, ErrChunkedBodyMalformed)
}

// ── Announcement ────────────────────────────────────────────────────────────

func TestParseStreamingPayload(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers map[string][]string
		want    StreamingPayload
		kind    error
	}{
		{
			name:    "signed",
			headers: map[string][]string{"x-amz-content-sha256": {StreamingSignedPayload}, "x-amz-decoded-content-length": {"15"}},
			want:    StreamingPayload{Mode: StreamingSignedPayload, Signed: true, DecodedLength: 15},
		},
		{
			name: "signed with trailer",
			headers: map[string][]string{
				"x-amz-content-sha256": {StreamingSignedPayloadTrailer}, "x-amz-decoded-content-length": {"0"},
				"x-amz-trailer": {"X-Amz-Checksum-CRC32C"},
			},
			want: StreamingPayload{Mode: StreamingSignedPayloadTrailer, Signed: true, Trailer: true, Trailers: []string{"x-amz-checksum-crc32c"}},
		},
		{
			name: "unsigned with trailer",
			headers: map[string][]string{
				"x-amz-content-sha256": {StreamingUnsignedPayloadTrailer}, "x-amz-decoded-content-length": {"7"},
				"x-amz-trailer": {"x-amz-checksum-crc64nvme"},
			},
			want: StreamingPayload{Mode: StreamingUnsignedPayloadTrailer, Trailer: true, DecodedLength: 7, Trailers: []string{"x-amz-checksum-crc64nvme"}},
		},
		{
			name:    "SigV4a ECDSA",
			headers: map[string][]string{"x-amz-content-sha256": {"STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD"}, "x-amz-decoded-content-length": {"1"}},
			kind:    ErrChunkedBodyUnsupported,
		},
		{
			name:    "SigV4a ECDSA with trailer",
			headers: map[string][]string{"x-amz-content-sha256": {"STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER"}, "x-amz-decoded-content-length": {"1"}},
			kind:    ErrChunkedBodyUnsupported,
		},
		{
			name:    "unknown streaming mode",
			headers: map[string][]string{"x-amz-content-sha256": {"STREAMING-SOMETHING-ELSE"}, "x-amz-decoded-content-length": {"1"}},
			kind:    ErrChunkedBodyUnsupported,
		},
		{
			name:    "framing without a streaming mode",
			headers: map[string][]string{"x-amz-content-sha256": {"UNSIGNED-PAYLOAD"}, "Content-Encoding": {"aws-chunked"}, "x-amz-decoded-content-length": {"1"}},
			kind:    ErrChunkedBodyMalformed,
		},
		{
			name:    "decoded length missing",
			headers: map[string][]string{"x-amz-content-sha256": {StreamingSignedPayload}},
			kind:    ErrChunkedBodyMalformed,
		},
		{
			name:    "decoded length signed",
			headers: map[string][]string{"x-amz-content-sha256": {StreamingSignedPayload}, "x-amz-decoded-content-length": {"+5"}},
			kind:    ErrChunkedBodyMalformed,
		},
		{
			name:    "decoded length negative",
			headers: map[string][]string{"x-amz-content-sha256": {StreamingSignedPayload}, "x-amz-decoded-content-length": {"-5"}},
			kind:    ErrChunkedBodyMalformed,
		},
		{
			name:    "decoded length padded",
			headers: map[string][]string{"x-amz-content-sha256": {StreamingSignedPayload}, "x-amz-decoded-content-length": {" 5"}},
			kind:    ErrChunkedBodyMalformed,
		},
		{
			name:    "decoded length overflows",
			headers: map[string][]string{"x-amz-content-sha256": {StreamingSignedPayload}, "x-amz-decoded-content-length": {"99999999999999999999"}},
			kind:    ErrChunkedBodyMalformed,
		},
		{
			name:    "decoded length twice",
			headers: map[string][]string{"x-amz-content-sha256": {StreamingSignedPayload}, "x-amz-decoded-content-length": {"5", "6"}},
			kind:    ErrChunkedBodyMalformed,
		},
		{
			name: "trailer declared for a mode without one",
			headers: map[string][]string{
				"x-amz-content-sha256": {StreamingSignedPayload}, "x-amz-decoded-content-length": {"5"},
				"x-amz-trailer": {"x-amz-checksum-crc32"},
			},
			kind: ErrChunkedBodyMalformed,
		},
		{
			name: "trailer declared twice",
			headers: map[string][]string{
				"x-amz-content-sha256": {StreamingUnsignedPayloadTrailer}, "x-amz-decoded-content-length": {"5"},
				"x-amz-trailer": {"x-amz-checksum-crc32, x-amz-checksum-crc32"},
			},
			kind: ErrChunkedBodyMalformed,
		},
		{
			name: "trailer signature declared as a trailer",
			headers: map[string][]string{
				"x-amz-content-sha256": {StreamingSignedPayloadTrailer}, "x-amz-decoded-content-length": {"5"},
				"x-amz-trailer": {"x-amz-trailer-signature"},
			},
			kind: ErrChunkedBodyMalformed,
		},
		{
			name: "invalid trailer name",
			headers: map[string][]string{
				"x-amz-content-sha256": {StreamingUnsignedPayloadTrailer}, "x-amz-decoded-content-length": {"5"},
				"x-amz-trailer": {"x-amz-checksum crc32"},
			},
			kind: ErrChunkedBodyMalformed,
		},
		{
			name: "too many trailers",
			headers: map[string][]string{
				"x-amz-content-sha256": {StreamingUnsignedPayloadTrailer}, "x-amz-decoded-content-length": {"5"},
				"x-amz-trailer": {"a,b,c,d,e"},
			},
			kind: ErrChunkedBodyMalformed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/b/k", nil)
			for k, vs := range tc.headers {
				for _, v := range vs {
					r.Header.Add(k, v)
				}
			}
			got, err := ParseStreamingPayload(r)
			if tc.kind != nil {
				wantKind(t, err, tc.kind)
				var cerr *ChunkedBodyError
				if !errors.As(err, &cerr) || cerr.Detail == "" {
					t.Fatalf("error carries no detail: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseStreamingPayload: %v", err)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestStripAWSChunkedCoding(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want []string
	}{
		{[]string{"aws-chunked"}, nil},
		{[]string{"aws-chunked,gzip"}, []string{"gzip"}},
		{[]string{"gzip, aws-chunked"}, []string{"gzip"}},
		{[]string{"AWS-CHUNKED"}, nil},
		{[]string{"gzip", "aws-chunked"}, []string{"gzip"}},
		{[]string{"aws-chunked,gzip,br"}, []string{"gzip,br"}},
	} {
		h := http.Header{}
		for _, v := range tc.in {
			h.Add("Content-Encoding", v)
		}
		stripAWSChunkedCoding(h)
		if got := h.Values("Content-Encoding"); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%q → %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestChunkedBodyIndicator(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		want    string
	}{
		{
			name:    "plain signed payload is not framed",
			headers: map[string][]string{"x-amz-content-sha256": {sha256Hex("hello")}},
			want:    "",
		},
		{
			name:    "unsigned payload is not framed",
			headers: map[string][]string{"x-amz-content-sha256": {"UNSIGNED-PAYLOAD"}},
			want:    "",
		},
		{
			name:    "no headers at all",
			headers: nil,
			want:    "",
		},
		{
			// What minio-go (mc, warp) sends on every plain-HTTP upload.
			name:    "streaming signed payload",
			headers: map[string][]string{"x-amz-content-sha256": {"STREAMING-AWS4-HMAC-SHA256-PAYLOAD"}},
			want:    "x-amz-content-sha256",
		},
		{
			name:    "streaming with trailer",
			headers: map[string][]string{"x-amz-content-sha256": {"STREAMING-UNSIGNED-PAYLOAD-TRAILER"}},
			want:    "x-amz-content-sha256",
		},
		{
			name:    "declared literal is matched case-insensitively",
			headers: map[string][]string{"x-amz-content-sha256": {"streaming-aws4-hmac-sha256-payload"}},
			want:    "x-amz-content-sha256",
		},
		{
			// Framing sent without announcing the STREAMING-* literal: the
			// declared hash alone would miss it.
			name: "decoded content length without the literal",
			headers: map[string][]string{
				"x-amz-content-sha256":         {"UNSIGNED-PAYLOAD"},
				"x-amz-decoded-content-length": {"15"},
			},
			want: "x-amz-decoded-content-length",
		},
		{
			name:    "a trailer declaration without the literal",
			headers: map[string][]string{"x-amz-trailer": {"x-amz-checksum-crc32"}},
			want:    "x-amz-trailer",
		},
		{
			name:    "content-encoding alone",
			headers: map[string][]string{"Content-Encoding": {"aws-chunked"}},
			want:    "content-encoding",
		},
		{
			name:    "content-encoding combined with another coding",
			headers: map[string][]string{"Content-Encoding": {"aws-chunked,gzip"}},
			want:    "content-encoding",
		},
		{
			// Header.Get only sees the first value; the token can be in any.
			name:    "content-encoding in a second header value",
			headers: map[string][]string{"Content-Encoding": {"gzip", "aws-chunked"}},
			want:    "content-encoding",
		},
		{
			name:    "an ordinary content-encoding is not framing",
			headers: map[string][]string{"Content-Encoding": {"gzip"}},
			want:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("body"))
			for k, vs := range tc.headers {
				for _, v := range vs {
					r.Header.Add(k, v)
				}
			}
			if got := ChunkedBodyIndicator(r); got != tc.want {
				t.Errorf("ChunkedBodyIndicator = %q, want %q", got, tc.want)
			}
		})
	}
}

// ── Fuzzing ─────────────────────────────────────────────────────────────────

// FuzzChunkedReader drives the decoder with arbitrary bodies, in the unsigned
// trailer mode (where random input can actually get past the framing) and in
// the signed mode (where it exercises the header parser and the chain).
//
// The invariant is the one every decoder in this repo is held to: never
// panic, always terminate, never hand back more than was declared, and never
// end cleanly on a stream that did not add up.
//
// Run the corpus (part of `make test`):
//
//	go test ./auth/ -run FuzzChunkedReader
//
// Actually fuzz:
//
//	go test ./auth/ -fuzz FuzzChunkedReader -fuzztime 60s
func FuzzChunkedReader(f *testing.F) {
	data := testData(300)
	f.Add(frame(data, 64, nil, true, []string{"x-amz-checksum-crc32:AAAAAA=="}, awsStyle), int64(300), false)
	f.Add(frame(data, 64, nil, true, []string{"x-amz-checksum-crc32:AAAAAA=="}, minioStyle), int64(300), false)
	f.Add(frame(data, 7, testSigner(), false, nil, awsStyle), int64(300), true)
	f.Add(frame(nil, 64, testSigner(), false, nil, awsStyle), int64(0), true)
	f.Add([]byte("0\r\n\r\n"), int64(0), false)
	f.Add([]byte("ffffffffffffffff\r\n"), int64(1<<62), false)
	f.Add([]byte(strings.Repeat("1", 300)), int64(5), false)
	f.Add([]byte("5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n"), int64(5), false)

	f.Fuzz(func(t *testing.T, body []byte, declared int64, signed bool) {
		if declared < 0 {
			declared = -declared
			if declared < 0 {
				declared = 0
			}
		}
		p := StreamingPayload{Mode: StreamingUnsignedPayloadTrailer, Trailer: true,
			DecodedLength: declared, Trailers: []string{"x-amz-checksum-crc32"}}
		var s *chunkSigner
		if signed {
			p = signedPayload(0)
			p.DecodedLength = declared
			s = testSigner()
		}
		cr := newChunkedReader(io.NopCloser(bytes.NewReader(body)), p, s)
		delivered := 0
		cr.SetTrailerHandler(func(string, string) error { delivered++; return nil })

		out, err := io.ReadAll(cr)
		if int64(len(out)) > declared {
			t.Fatalf("decoded %d bytes, more than the %d declared", len(out), declared)
		}
		if err == nil {
			if int64(len(out)) != declared {
				t.Fatalf("clean end after %d bytes, %d declared", len(out), declared)
			}
			if !signed && delivered != 1 {
				t.Fatalf("clean end without delivering the declared trailer (delivered %d)", delivered)
			}
		}
	})
}
