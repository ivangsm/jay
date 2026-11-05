package auth

// aws-chunked: the body framing of SigV4's streaming modes.
//
// A client that does not want to hash a whole payload before sending it (minio-go
// over plain HTTP, the AWS SDKs when they add a trailing checksum) declares one
// of the STREAMING-* literals in x-amz-content-sha256 and sends the body as
//
//	<hex-size>;chunk-signature=<sig>\r\n<data>\r\n      signed modes
//	<hex-size>\r\n<data>\r\n                            unsigned mode
//	...
//	0;chunk-signature=<sig>\r\n                         final chunk, always empty
//	[<name>:<value>\r\n ... x-amz-trailer-signature:<sig>\r\n]   trailer modes
//	\r\n
//
// Content-Length counts the framing; the payload's own length travels in
// x-amz-decoded-content-length.
//
// Each chunk signature is an HMAC over the previous signature and the chunk's
// SHA-256, seeded by the request signature, so the chain authenticates every
// byte AND the order and the end of the stream: a chunk cannot be dropped,
// reordered or appended without breaking the next signature, and the final
// empty chunk is signed too.
//
// ChunkedReader undoes the framing in the request's own goroutine, as the
// handler reads, and never buffers more than one header line: data bytes are
// passed through as they arrive and the chunk they belong to is verified when
// its last byte has been read. It does NOT report io.EOF until the final chunk,
// the declared length and the trailer have all been verified, and the write
// path commits nothing before EOF (store.WriteObjectVerified renames only after
// the body is exhausted), so a signature that fails anywhere — first chunk or
// last — leaves nothing behind.
//
// That property is only as good as the consumer's discipline: a handler that
// ACTS on bytes before EOF (parses an XML document and deletes what it names,
// say) would act on bytes whose chunk has not been verified yet. That is why
// the HTTP layer admits framing only on PutObject and UploadPart (see
// api.withChunkedBodyGate), the two operations that commit only at EOF.

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// The x-amz-content-sha256 literals of the streaming modes.
const (
	// streamingPayloadPrefix covers every STREAMING-* literal AWS defines, the
	// ones jay decodes and the ones it refuses alike.
	streamingPayloadPrefix = "STREAMING-"

	// StreamingSignedPayload frames the body in signed chunks, no trailer. It is
	// what minio-go (mc, warp) sends on every plain-HTTP upload.
	StreamingSignedPayload = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	// StreamingSignedPayloadTrailer is the same with a signed trailer after the
	// final chunk, carrying a checksum of the payload.
	StreamingSignedPayloadTrailer = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	// StreamingUnsignedPayloadTrailer frames the body in unsigned chunks with a
	// trailing checksum. The request itself is still signed; the payload is as
	// trustworthy as UNSIGNED-PAYLOAD plus whatever checksum the trailer carries.
	StreamingUnsignedPayloadTrailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"

	// streamingECDSAPrefix is SigV4a's streaming family (ECDSA P-256 over the
	// same chunk layout). jay implements no SigV4a at all.
	streamingECDSAPrefix = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD"
)

// The headers and literals of the framing itself.
const (
	decodedContentLengthHeader = "x-amz-decoded-content-length"
	trailerDeclarationHeader   = "x-amz-trailer"
	trailerSignatureName       = "x-amz-trailer-signature"
	awsChunkedCoding           = "aws-chunked"
	chunkSignatureExtension    = "chunk-signature="

	// chunkStringToSignAlgorithm and trailerStringToSignAlgorithm open the
	// string to sign of a chunk and of the trailer, in place of the request's
	// AWS4-HMAC-SHA256.
	chunkStringToSignAlgorithm   = "AWS4-HMAC-SHA256-PAYLOAD"
	trailerStringToSignAlgorithm = "AWS4-HMAC-SHA256-TRAILER"

	// emptySHA256Hex is SHA-256 of nothing. Every chunk string to sign carries
	// it in the position a header hash would take; chunks have no headers.
	emptySHA256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// signatureHexLen is the length of a hex-encoded HMAC-SHA256.
	signatureHexLen = 2 * sha256.Size
)

// Bounds on what the network may make the decoder hold. None of them depends on
// a size the client declared: a chunk's data is streamed, never allocated.
const (
	// maxChunkHeaderLine bounds one chunk header, CRLF included. The longest
	// legitimate one is 16 hex digits + ";chunk-signature=" + 64 hex + CRLF =
	// 99 bytes.
	maxChunkHeaderLine = 128
	// maxChunkSizeDigits is the most hex digits a chunk size may have: 16 is
	// already 2^64-1, far beyond any x-amz-decoded-content-length.
	maxChunkSizeDigits = 16
	// maxTrailerSection bounds everything after the final chunk. A checksum
	// trailer plus its signature is under 200 bytes.
	maxTrailerSection = 4 << 10
	// maxDeclaredTrailers bounds x-amz-trailer. S3 allows one checksum per
	// request; a few more names are tolerated here and refused, by name, by the
	// operation that has to verify them.
	maxDeclaredTrailers = 4
)

// ErrChunkedBodyUnsupported reports an aws-chunked request jay will not decode:
// a variant it does not implement (SigV4a's ECDSA streaming), a credential that
// cannot carry it (a bearer token or a presigned URL has no seed signature to
// chain from), an operation that does not accept it, or a trailer the operation
// cannot verify. The HTTP layer answers 501 for it.
var ErrChunkedBodyUnsupported = errors.New("aws-chunked request body is not supported")

// Errors the decoder reports about the body itself. They come back wrapped in a
// *ChunkedBodyError, so a caller can both test the kind with errors.Is and read
// what exactly was wrong.
var (
	// ErrChunkedBodyMalformed: the framing, or the headers announcing it, do not
	// follow the aws-chunked grammar.
	ErrChunkedBodyMalformed = errors.New("aws-chunked request body is malformed")
	// ErrChunkSignatureMismatch: a chunk or trailer signature does not verify.
	ErrChunkSignatureMismatch = errors.New("aws-chunked signature does not match")
	// ErrDecodedLengthMismatch: the chunks do not add up to
	// x-amz-decoded-content-length.
	ErrDecodedLengthMismatch = errors.New("aws-chunked body does not match x-amz-decoded-content-length")
)

// ChunkedBodyError carries the kind (one of the sentinels above) and a short
// description of the offending part, safe to echo back to the client.
type ChunkedBodyError struct {
	Kind   error
	Detail string
}

// Error implements error.
func (e *ChunkedBodyError) Error() string { return e.Kind.Error() + ": " + e.Detail }

// Unwrap exposes the kind for errors.Is.
func (e *ChunkedBodyError) Unwrap() error { return e.Kind }

func chunkedErr(kind error, format string, args ...any) error {
	return &ChunkedBodyError{Kind: kind, Detail: fmt.Sprintf(format, args...)}
}

// ChunkedBodyIndicator reports which request header shows the body carries
// aws-chunked framing, or "" when none does. The header name is returned rather
// than a bool so a refusal can name what it saw.
//
// Four independent signals are checked, because the declared payload hash is
// not the only one: x-amz-content-sha256 STREAMING-* (what the signature
// covers), x-amz-decoded-content-length and x-amz-trailer (both exist only in
// this mode, even from a client that never declares the literal) and
// Content-Encoding: aws-chunked (matched per token and across every value,
// since it combines with other codings). None of the four has any other meaning
// in S3.
func ChunkedBodyIndicator(r *http.Request) string {
	if strings.HasPrefix(
		strings.ToUpper(strings.TrimSpace(r.Header.Get("x-amz-content-sha256"))),
		streamingPayloadPrefix,
	) {
		return "x-amz-content-sha256"
	}
	if len(r.Header.Values(decodedContentLengthHeader)) > 0 {
		return decodedContentLengthHeader
	}
	if len(r.Header.Values(trailerDeclarationHeader)) > 0 {
		return trailerDeclarationHeader
	}
	for _, value := range r.Header.Values("Content-Encoding") {
		for coding := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(coding), awsChunkedCoding) {
				return "content-encoding"
			}
		}
	}
	return ""
}

// UsesSigV4Header reports whether r is authenticated by a SigV4 Authorization
// header — the only credential form whose signature can seed a chunk chain.
func UsesSigV4Header(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), sigV4Algorithm+" ")
}

// StreamingPayload is an aws-chunked request as its headers announce it.
type StreamingPayload struct {
	// Mode is the x-amz-content-sha256 literal, upper-cased.
	Mode string
	// Signed reports that every chunk carries a chunk-signature.
	Signed bool
	// Trailer reports that a trailer section follows the final chunk.
	Trailer bool
	// DecodedLength is x-amz-decoded-content-length: the payload's real size.
	DecodedLength int64
	// Trailers are the names x-amz-trailer declares, lower-cased, in order.
	Trailers []string
}

// ParseStreamingPayload reads the headers of a request ChunkedBodyIndicator
// flagged and says how its body is framed. It reads no byte of the body.
//
// It returns a *ChunkedBodyError wrapping ErrChunkedBodyMalformed when the
// announcement is inconsistent — framing without a STREAMING-* literal, a
// missing or non-numeric x-amz-decoded-content-length, a trailer declared for
// a mode that has none — and one wrapping ErrChunkedBodyUnsupported for a
// STREAMING-* variant jay does not implement.
func ParseStreamingPayload(r *http.Request) (StreamingPayload, error) {
	declared := strings.ToUpper(strings.TrimSpace(r.Header.Get("x-amz-content-sha256")))

	var p StreamingPayload
	switch {
	case declared == StreamingSignedPayload:
		p = StreamingPayload{Mode: declared, Signed: true}
	case declared == StreamingSignedPayloadTrailer:
		p = StreamingPayload{Mode: declared, Signed: true, Trailer: true}
	case declared == StreamingUnsignedPayloadTrailer:
		p = StreamingPayload{Mode: declared, Trailer: true}
	case strings.HasPrefix(declared, streamingECDSAPrefix):
		return StreamingPayload{}, chunkedErr(ErrChunkedBodyUnsupported,
			"%s is a SigV4a (ECDSA P-256) streaming signature; jay implements SigV4 only", declared)
	case strings.HasPrefix(declared, streamingPayloadPrefix):
		return StreamingPayload{}, chunkedErr(ErrChunkedBodyUnsupported,
			"unknown streaming payload mode %s", declared)
	default:
		// Framing announced by another header, with a payload hash that is a
		// real digest or UNSIGNED-PAYLOAD. No streaming mode means there is
		// nothing to decode with, and storing the framing is the defect this
		// decoder exists to prevent.
		return StreamingPayload{}, chunkedErr(ErrChunkedBodyMalformed,
			"the request announces an aws-chunked body (%s) but x-amz-content-sha256 declares no STREAMING-* mode",
			ChunkedBodyIndicator(r))
	}

	n, err := parseDecodedLength(r.Header.Values(decodedContentLengthHeader))
	if err != nil {
		return StreamingPayload{}, err
	}
	p.DecodedLength = n

	trailers, err := parseTrailerDeclaration(r.Header.Values(trailerDeclarationHeader))
	if err != nil {
		return StreamingPayload{}, err
	}
	if len(trailers) > 0 && !p.Trailer {
		return StreamingPayload{}, chunkedErr(ErrChunkedBodyMalformed,
			"x-amz-trailer is declared but %s carries no trailer", p.Mode)
	}
	p.Trailers = trailers
	return p, nil
}

// parseDecodedLength parses x-amz-decoded-content-length strictly: exactly one
// value, decimal digits only. A sign, a space or a second value is refused
// rather than interpreted, because the value bounds everything the decoder
// accepts afterwards.
func parseDecodedLength(values []string) (int64, error) {
	if len(values) == 0 {
		return 0, chunkedErr(ErrChunkedBodyMalformed,
			"x-amz-decoded-content-length is required for an aws-chunked body")
	}
	if len(values) > 1 {
		return 0, chunkedErr(ErrChunkedBodyMalformed, "x-amz-decoded-content-length appears more than once")
	}
	v := values[0]
	if v == "" || len(v) > 19 {
		return 0, chunkedErr(ErrChunkedBodyMalformed, "x-amz-decoded-content-length %q is not a byte count", v)
	}
	for i := range len(v) {
		if v[i] < '0' || v[i] > '9' {
			return 0, chunkedErr(ErrChunkedBodyMalformed, "x-amz-decoded-content-length %q is not a byte count", v)
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, chunkedErr(ErrChunkedBodyMalformed, "x-amz-decoded-content-length %q is not a byte count", v)
	}
	return n, nil
}

// parseTrailerDeclaration splits x-amz-trailer into lower-cased names. Every
// value is honoured (a client may repeat the header or comma-join it), a name
// may appear only once, and the list is capped.
func parseTrailerDeclaration(values []string) ([]string, error) {
	var names []string
	for _, value := range values {
		for raw := range strings.SplitSeq(value, ",") {
			name := strings.ToLower(strings.TrimSpace(raw))
			if name == "" {
				continue
			}
			if !isTrailerName(name) || name == trailerSignatureName {
				return nil, chunkedErr(ErrChunkedBodyMalformed, "x-amz-trailer names an invalid header %q", name)
			}
			for _, seen := range names {
				if seen == name {
					return nil, chunkedErr(ErrChunkedBodyMalformed, "x-amz-trailer declares %s twice", name)
				}
			}
			names = append(names, name)
			if len(names) > maxDeclaredTrailers {
				return nil, chunkedErr(ErrChunkedBodyMalformed,
					"x-amz-trailer declares more than %d headers", maxDeclaredTrailers)
			}
		}
	}
	return names, nil
}

// isTrailerName accepts the lower-case header names S3 uses for trailers.
func isTrailerName(name string) bool {
	for i := range len(name) {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// chunkSigner holds what verifying the chain needs: the request's signing key,
// its date and credential scope, and the last signature seen — the request
// signature itself before the first chunk.
type chunkSigner struct {
	key     []byte
	amzDate string
	scope   string
	prev    string
}

// chunkSignature computes the signature of one chunk given its data's SHA-256.
//
//	AWS4-HMAC-SHA256-PAYLOAD\n<amz-date>\n<scope>\n<previous-signature>\n<sha256("")>\n<sha256(data)>
func (s *chunkSigner) chunkSignature(dataSHA256 []byte) string {
	stringToSign := chunkStringToSignAlgorithm + "\n" +
		s.amzDate + "\n" +
		s.scope + "\n" +
		s.prev + "\n" +
		emptySHA256Hex + "\n" +
		hex.EncodeToString(dataSHA256)
	return hex.EncodeToString(hmacSHA256(s.key, []byte(stringToSign)))
}

// trailerSignature computes the signature of the trailer given the SHA-256 of
// its canonical form (every trailing header as "name:value\n", in the order
// sent).
//
//	AWS4-HMAC-SHA256-TRAILER\n<amz-date>\n<scope>\n<previous-signature>\n<sha256(trailer)>
func (s *chunkSigner) trailerSignature(canonicalSHA256 []byte) string {
	stringToSign := trailerStringToSignAlgorithm + "\n" +
		s.amzDate + "\n" +
		s.scope + "\n" +
		s.prev + "\n" +
		hex.EncodeToString(canonicalSHA256)
	return hex.EncodeToString(hmacSHA256(s.key, []byte(stringToSign)))
}

// verify compares a provided signature against the expected one in constant
// time and, on success, advances the chain.
func (s *chunkSigner) verify(expected string, provided []byte) bool {
	if subtle.ConstantTimeCompare([]byte(expected), provided) != 1 {
		return false
	}
	s.prev = expected
	return true
}

// chunkState is where the decoder stands in the stream.
type chunkState int

const (
	stateChunkHeader chunkState = iota // next bytes are a chunk header line
	stateChunkData                     // inside a chunk's data
	stateDone                          // everything verified; io.EOF from here on
)

// ChunkedReader decodes an aws-chunked body. It is what the handler reads
// once AuthenticateSigV4 has accepted a streaming request: r.Body is replaced
// by one, so the bytes a handler sees are the payload, never the framing.
type ChunkedReader struct {
	src     *bufio.Reader
	body    io.ReadCloser
	payload StreamingPayload
	signer  *chunkSigner // nil in the unsigned mode

	state     chunkState
	remaining int64 // data bytes left in the current chunk
	decoded   int64 // data bytes delivered so far
	chunkNo   int   // 1-based number of the current chunk, for error messages
	chunkSig  []byte
	chunkHash hash.Hash

	line [maxChunkHeaderLine]byte

	onTrailer func(name, value string) error
	err       error // sticky: once failed, every later Read reports the same error
}

// newChunkedReader wraps body. signer is nil for the unsigned mode.
func newChunkedReader(body io.ReadCloser, p StreamingPayload, signer *chunkSigner) *ChunkedReader {
	cr := &ChunkedReader{
		src:     bufio.NewReaderSize(body, 64<<10),
		body:    body,
		payload: p,
		signer:  signer,
	}
	if signer != nil {
		cr.chunkHash = sha256.New()
	}
	return cr
}

// installChunkedReader swaps r.Body for a decoder and makes the rest of the
// request describe the payload rather than the framing: ContentLength becomes
// the decoded length and aws-chunked leaves Content-Encoding, so the coding
// that remains (if any) is the one the object actually has.
func installChunkedReader(r *http.Request, p StreamingPayload, signer *chunkSigner) {
	body := r.Body
	if body == nil {
		body = http.NoBody
	}
	r.Body = newChunkedReader(body, p, signer)
	r.ContentLength = p.DecodedLength
	stripAWSChunkedCoding(r.Header)
}

// stripAWSChunkedCoding removes the aws-chunked token from Content-Encoding and
// deletes the header when nothing else is left — the way S3 stores
// `aws-chunked,gzip` as `gzip`.
func stripAWSChunkedCoding(h http.Header) {
	values := h.Values("Content-Encoding")
	if len(values) == 0 {
		return
	}
	var kept []string
	for _, value := range values {
		for coding := range strings.SplitSeq(value, ",") {
			coding = strings.TrimSpace(coding)
			if coding == "" || strings.EqualFold(coding, awsChunkedCoding) {
				continue
			}
			kept = append(kept, coding)
		}
	}
	if len(kept) == 0 {
		h.Del("Content-Encoding")
		return
	}
	h.Set("Content-Encoding", strings.Join(kept, ","))
}

// ChunkedBodyOf returns the decoder installed on r, if its body is framed.
func ChunkedBodyOf(r *http.Request) (*ChunkedReader, bool) {
	cr, ok := r.Body.(*ChunkedReader)
	return cr, ok
}

// Trailers returns the names x-amz-trailer declared, lower-cased.
func (c *ChunkedReader) Trailers() []string {
	return append([]string(nil), c.payload.Trailers...)
}

// SetTrailerHandler registers the function that receives every trailing
// header, after the trailer signature (if any) has verified and BEFORE the
// reader reports io.EOF. An error it returns becomes the reader's error.
//
// A trailer that arrives with no handler registered is refused with
// ErrChunkedBodyUnsupported: a trailing checksum nobody checks would be a
// verification that never happened.
func (c *ChunkedReader) SetTrailerHandler(fn func(name, value string) error) {
	c.onTrailer = fn
}

// Close closes the underlying body.
func (c *ChunkedReader) Close() error { return c.body.Close() }

// Read implements io.Reader over the decoded payload.
func (c *ChunkedReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	for {
		switch c.state {
		case stateDone:
			return 0, io.EOF

		case stateChunkHeader:
			if err := c.readChunkHeader(); err != nil {
				return 0, c.fail(err)
			}

		case stateChunkData:
			if c.remaining == 0 {
				if err := c.finishChunk(); err != nil {
					return 0, c.fail(err)
				}
				continue
			}
			if len(p) == 0 {
				return 0, nil
			}
			want := int64(len(p))
			if want > c.remaining {
				want = c.remaining
			}
			n, err := c.src.Read(p[:want])
			if n > 0 {
				if c.chunkHash != nil {
					c.chunkHash.Write(p[:n])
				}
				c.remaining -= int64(n)
				c.decoded += int64(n)
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = chunkedErr(ErrChunkedBodyMalformed,
						"the body ended inside chunk %d, %d bytes short", c.chunkNo, c.remaining)
				}
				return n, c.fail(err)
			}
			return n, nil
		}
	}
}

// fail latches err so every later Read returns it.
func (c *ChunkedReader) fail(err error) error {
	c.err = err
	return err
}

// readChunkHeader parses `<hex-size>[;chunk-signature=<sig>]\r\n` and either
// enters the chunk's data or, for the empty final chunk, finishes the stream.
func (c *ChunkedReader) readChunkHeader() error {
	c.chunkNo++
	line, err := c.readLine()
	if err != nil {
		return err
	}

	sizeField, ext, hasExt := strings.Cut(string(line), ";")
	size, err := parseChunkSize(sizeField)
	if err != nil {
		return chunkedErr(ErrChunkedBodyMalformed, "chunk %d: %v", c.chunkNo, err)
	}

	switch {
	case c.signer != nil:
		sig, ok := strings.CutPrefix(ext, chunkSignatureExtension)
		if !hasExt || !ok || !isHexSignature(sig) {
			return chunkedErr(ErrChunkedBodyMalformed,
				"chunk %d: expected ;chunk-signature=<64 hex digits>, got %q", c.chunkNo, truncate(ext))
		}
		c.chunkSig = append(c.chunkSig[:0], sig...)
	case hasExt:
		return chunkedErr(ErrChunkedBodyMalformed,
			"chunk %d: %s carries no chunk extensions, got %q", c.chunkNo, c.payload.Mode, truncate(ext))
	}

	// Validated against what is left BEFORE a byte of data is read, so a
	// declared size never drives an allocation or a read past the payload.
	if left := c.payload.DecodedLength - c.decoded; size > uint64(left) {
		return chunkedErr(ErrDecodedLengthMismatch,
			"chunk %d declares %d bytes but only %d remain of x-amz-decoded-content-length %d",
			c.chunkNo, size, left, c.payload.DecodedLength)
	}

	if size == 0 {
		return c.finishStream()
	}
	c.remaining = int64(size)
	c.state = stateChunkData
	return nil
}

// finishChunk consumes the CRLF after a chunk's data and verifies its signature.
func (c *ChunkedReader) finishChunk() error {
	if err := c.expectCRLF(); err != nil {
		return err
	}
	if c.signer != nil {
		if err := c.verifyChunk(); err != nil {
			return err
		}
	}
	c.state = stateChunkHeader
	return nil
}

// verifyChunk checks the current chunk's signature against its data and resets
// the data hash for the next one.
func (c *ChunkedReader) verifyChunk() error {
	expected := c.signer.chunkSignature(c.chunkHash.Sum(nil))
	c.chunkHash.Reset()
	if !c.signer.verify(expected, c.chunkSig) {
		return chunkedErr(ErrChunkSignatureMismatch, "chunk %d", c.chunkNo)
	}
	return nil
}

// finishStream handles the empty final chunk: its signature, the declared
// length, the trailer section, and only then the end of the stream.
func (c *ChunkedReader) finishStream() error {
	if c.signer != nil {
		if err := c.verifyChunk(); err != nil {
			return err
		}
	}
	if c.decoded != c.payload.DecodedLength {
		return chunkedErr(ErrDecodedLengthMismatch,
			"the chunks carry %d bytes, x-amz-decoded-content-length declares %d",
			c.decoded, c.payload.DecodedLength)
	}

	rest, err := c.readTrailerSection()
	if err != nil {
		return err
	}
	if !c.payload.Trailer {
		if string(rest) != "\r\n" {
			return chunkedErr(ErrChunkedBodyMalformed,
				"expected CRLF and the end of the body after the final chunk, got %q", truncate(string(rest)))
		}
		c.state = stateDone
		return nil
	}

	trailers, err := c.parseTrailers(rest)
	if err != nil {
		return err
	}
	if err := c.deliverTrailers(trailers); err != nil {
		return err
	}
	c.state = stateDone
	return nil
}

// trailerField is one trailing header as it arrived.
type trailerField struct {
	name  string // lower-cased
	value string // surrounding whitespace trimmed
	raw   string // the line exactly as sent, without its terminator
}

// readTrailerSection reads everything after the final chunk header, which must
// end the body within maxTrailerSection bytes.
func (c *ChunkedReader) readTrailerSection() ([]byte, error) {
	rest, err := io.ReadAll(io.LimitReader(c.src, maxTrailerSection+1))
	if err != nil {
		return nil, err
	}
	if len(rest) > maxTrailerSection {
		return nil, chunkedErr(ErrChunkedBodyMalformed,
			"more than %d bytes follow the final chunk", maxTrailerSection)
	}
	return rest, nil
}

// parseTrailers parses and, in the signed mode, verifies the trailer section.
//
// The grammar is `(<name>:<value> LF)* [x-amz-trailer-signature:<sig> LF] CRLF`,
// where each LF may be preceded by a CR. Blank lines between fields are
// tolerated: minio-go writes each trailer as "name:value\n" and then a CRLF,
// the AWS SDKs write "name:value\r\n". Neither blank line carries content, so
// tolerating it changes nothing the signature covers.
func (c *ChunkedReader) parseTrailers(rest []byte) ([]trailerField, error) {
	section, ok := strings.CutSuffix(string(rest), "\r\n")
	if !ok || (section != "" && !strings.HasSuffix(section, "\n")) {
		return nil, chunkedErr(ErrChunkedBodyMalformed,
			"the trailer section does not end with an empty line: %q", truncate(string(rest)))
	}

	var (
		fields    []trailerField
		signature string
		signed    bool
	)
	for raw := range strings.SplitSeq(strings.TrimSuffix(section, "\n"), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if line == "" {
			continue
		}
		if signed {
			return nil, chunkedErr(ErrChunkedBodyMalformed,
				"%s must be the last line of the trailer", trailerSignatureName)
		}
		name, value, found := strings.Cut(line, ":")
		name = strings.ToLower(name)
		if !found || name == "" || !isTrailerName(name) {
			return nil, chunkedErr(ErrChunkedBodyMalformed, "malformed trailer line %q", truncate(line))
		}
		if name == trailerSignatureName {
			signature = strings.TrimSpace(value)
			signed = true
			continue
		}
		fields = append(fields, trailerField{name: name, value: strings.TrimSpace(value), raw: line})
	}

	if err := c.checkDeclared(fields); err != nil {
		return nil, err
	}

	switch {
	case c.signer == nil && signed:
		return nil, chunkedErr(ErrChunkedBodyMalformed,
			"%s carries no %s", c.payload.Mode, trailerSignatureName)
	case c.signer != nil && !signed:
		return nil, chunkedErr(ErrChunkedBodyMalformed,
			"%s requires %s", c.payload.Mode, trailerSignatureName)
	case c.signer != nil:
		if !isHexSignature(signature) {
			return nil, chunkedErr(ErrChunkedBodyMalformed,
				"%s is not 64 hex digits", trailerSignatureName)
		}
		var canonical strings.Builder
		for _, f := range fields {
			canonical.WriteString(f.raw)
			canonical.WriteByte('\n')
		}
		sum := sha256.Sum256([]byte(canonical.String()))
		if !c.signer.verify(c.signer.trailerSignature(sum[:]), []byte(signature)) {
			return nil, chunkedErr(ErrChunkSignatureMismatch, "trailer")
		}
	}
	return fields, nil
}

// checkDeclared holds the trailer to exactly what x-amz-trailer announced: no
// field that was not declared, none twice, none missing.
func (c *ChunkedReader) checkDeclared(fields []trailerField) error {
	seen := make(map[string]bool, len(fields))
	for _, f := range fields {
		declared := false
		for _, name := range c.payload.Trailers {
			if name == f.name {
				declared = true
				break
			}
		}
		if !declared {
			return chunkedErr(ErrChunkedBodyMalformed, "trailer %s was not declared in x-amz-trailer", f.name)
		}
		if seen[f.name] {
			return chunkedErr(ErrChunkedBodyMalformed, "trailer %s arrived twice", f.name)
		}
		seen[f.name] = true
	}
	for _, name := range c.payload.Trailers {
		if !seen[name] {
			return chunkedErr(ErrChunkedBodyMalformed, "trailer %s was declared in x-amz-trailer and never arrived", name)
		}
	}
	return nil
}

// deliverTrailers hands each verified trailer to the operation, which is the
// only party that knows what it means. Without a handler there is nobody to
// verify it, and the body is refused rather than accepted unchecked.
func (c *ChunkedReader) deliverTrailers(fields []trailerField) error {
	for _, f := range fields {
		if c.onTrailer == nil {
			return chunkedErr(ErrChunkedBodyUnsupported,
				"trailing %s cannot be verified by this operation", f.name)
		}
		if err := c.onTrailer(f.name, f.value); err != nil {
			return err
		}
	}
	return nil
}

// readLine reads one CRLF-terminated chunk header line into the fixed buffer
// and returns it without the terminator. It never reads more than
// maxChunkHeaderLine bytes, whatever the client sends.
func (c *ChunkedReader) readLine() ([]byte, error) {
	n := 0
	for {
		b, err := c.src.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, chunkedErr(ErrChunkedBodyMalformed,
					"the body ended before the final chunk (in the header of chunk %d)", c.chunkNo)
			}
			return nil, err
		}
		if b == '\n' {
			if n == 0 || c.line[n-1] != '\r' {
				return nil, chunkedErr(ErrChunkedBodyMalformed,
					"chunk %d: header line is not terminated by CRLF", c.chunkNo)
			}
			return c.line[:n-1], nil
		}
		if n == len(c.line) {
			return nil, chunkedErr(ErrChunkedBodyMalformed,
				"chunk %d: header line is longer than %d bytes", c.chunkNo, maxChunkHeaderLine)
		}
		c.line[n] = b
		n++
	}
}

// expectCRLF consumes the CRLF that must follow a chunk's data.
func (c *ChunkedReader) expectCRLF() error {
	for _, want := range []byte{'\r', '\n'} {
		b, err := c.src.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return chunkedErr(ErrChunkedBodyMalformed,
					"the body ended after the data of chunk %d", c.chunkNo)
			}
			return err
		}
		if b != want {
			return chunkedErr(ErrChunkedBodyMalformed,
				"chunk %d: data is not followed by CRLF (its size does not match its data)", c.chunkNo)
		}
	}
	return nil
}

// parseChunkSize parses the hex size of a chunk: 1 to 16 hex digits, nothing
// else — no sign, no whitespace, no 0x.
func parseChunkSize(field string) (uint64, error) {
	if field == "" || len(field) > maxChunkSizeDigits {
		return 0, fmt.Errorf("chunk size %q is not 1 to %d hex digits", truncate(field), maxChunkSizeDigits)
	}
	var n uint64
	for i := range len(field) {
		d, ok := hexDigit(field[i])
		if !ok {
			return 0, fmt.Errorf("chunk size %q is not hexadecimal", truncate(field))
		}
		n = n<<4 | uint64(d)
	}
	return n, nil
}

// hexDigit decodes one hex digit of either case.
func hexDigit(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	}
	return 0, false
}

// isHexSignature reports whether s has the shape of a SigV4 signature. The
// comparison that follows is what decides whether it is the RIGHT one.
func isHexSignature(s string) bool {
	if len(s) != signatureHexLen {
		return false
	}
	for i := range len(s) {
		if _, ok := hexDigit(s[i]); !ok {
			return false
		}
	}
	return true
}

// truncate keeps client-supplied text in an error message short.
func truncate(s string) string {
	const limit = 64
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
