package api

// End-to-end tests for aws-chunked uploads (SigV4 streaming), signed and
// framed by an encoder that is NOT jay's.
//
// The encoder below is written from the SigV4 streaming specification — the
// seed signature is an ordinary header signature whose payload hash is the
// STREAMING-* literal, each chunk is signed over the previous signature and
// its own SHA-256, and the trailer over the SHA-256 of "name:value\n" — and
// lives in package api, which cannot reach auth's chunk signer even by
// accident. jay's signer is pinned to AWS's published numbers separately, in
// auth/chunked_test.go.
//
// Every test asserts the EFFECT: the bytes stored, an object present or
// absent, the data directory unchanged. The status code alone would have
// passed with the original defect, which answered 200 and stored the framing.

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"hash/crc32"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/ivangsm/jay/meta"
)

// walkDataDir returns every regular file under the store's data directory,
// relative to it, sorted. Used to prove a rejected upload wrote nothing: not
// the object, not a temp file, not an orphan a later recovery pass would have
// to quarantine.
func walkDataDir(t *testing.T, h *Handler) []string {
	t.Helper()
	root := h.store.DataDir()
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		// bbolt's own file changes on every metadata read; it is not what a
		// rejected upload could leave behind.
		if strings.HasPrefix(rel, "meta"+string(filepath.Separator)) || strings.HasSuffix(rel, ".db") {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walk data dir: %v", err)
	}
	sort.Strings(out)
	return out
}

// chunkedTestBucket creates a bucket owned by the token's account.
func chunkedTestBucket(t *testing.T, db *meta.DB, tok *meta.Token, name string) {
	t.Helper()
	b := &meta.Bucket{
		ID: uuid.New().String(), Name: name,
		OwnerAccountID: tok.AccountID, Visibility: "private", Status: "active",
	}
	if err := db.CreateBucket(b); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
}

// awsChunkedBody is the framed body exactly as minio-go puts it on the wire
// for a 15-byte file, with placeholder signatures. Only for refusals: it is
// never meant to verify.
var awsChunkedBody = "f;chunk-signature=" + strings.Repeat("a", 64) + "\r\n" +
	"hola desde jay\n" + "\r\n" +
	"0;chunk-signature=" + strings.Repeat("b", 64) + "\r\n\r\n"

// ── An independent SigV4 streaming encoder ──────────────────────────────────

const (
	streamSigned          = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	streamSignedTrailer   = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	streamUnsignedTrailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
	emptyPayloadSHA256    = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	testStreamHost        = "example.com" // httptest.NewRequest's default Host
)

// streamSpec describes one framed upload.
type streamSpec struct {
	mode      string
	data      []byte
	chunkSize int // 64 KiB when zero, like minio-go and the AWS SDKs

	// trailerName/trailerValue: one trailing header, e.g. a checksum. An empty
	// trailerValue is replaced by the correct CRC32 of data.
	trailerName  string
	trailerValue string
	// minioLayout writes the trailer "name:value\n" + CRLF, as minio-go does,
	// instead of the AWS SDKs' "name:value\r\n".
	minioLayout bool

	// declaredLength replaces len(data) in x-amz-decoded-content-length when
	// overrideLength is set.
	declaredLength int
	overrideLength bool
	// extraHeaders are set (and signed) on the request.
	extraHeaders map[string]string
	// tamper rewrites the framed body after it has been signed.
	tamper func([]byte) []byte
}

// streamSigning is what the encoder carries from the headers into the chunks.
type streamSigning struct {
	key     []byte
	amzDate string
	scope   string
	prev    string
}

func (s *streamSigning) sign(algorithm string, lines ...string) string {
	stringToSign := algorithm + "\n" + s.amzDate + "\n" + s.scope + "\n" + s.prev + "\n" + strings.Join(lines, "\n")
	sig := hex.EncodeToString(awsHMAC(s.key, []byte(stringToSign)))
	s.prev = sig
	return sig
}

// crc32Base64 is the x-amz-checksum-crc32 value S3 defines: big-endian CRC32
// (IEEE), base64.
func crc32Base64(data []byte) string {
	sum := crc32.ChecksumIEEE(data)
	return base64.StdEncoding.EncodeToString([]byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)})
}

// streamingRequest builds a PUT to target (a path with an optional query)
// signed with a SigV4 Authorization header in spec.mode, with the body framed
// and, in the signed modes, every chunk signed.
func streamingRequest(t *testing.T, target string, tok *meta.Token, secret string, spec streamSpec) *http.Request {
	t.Helper()
	if spec.chunkSize == 0 {
		spec.chunkSize = 64 << 10
	}
	declared := len(spec.data)
	if spec.overrideLength {
		declared = spec.declaredLength
	}
	signed := spec.mode != streamUnsignedTrailer
	trailerMode := spec.mode != streamSigned

	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	now := time.Now().UTC()
	amzDate, dateStamp := now.Format("20060102T150405Z"), now.Format("20060102")
	scope := dateStamp + "/us-east-1/s3/aws4_request"

	headers := map[string]string{
		"host":                         testStreamHost,
		"x-amz-content-sha256":         spec.mode,
		"x-amz-date":                   amzDate,
		"x-amz-decoded-content-length": strconv.Itoa(declared),
		"content-encoding":             "aws-chunked",
	}
	if spec.trailerName != "" {
		headers["x-amz-trailer"] = spec.trailerName
	}
	for k, v := range spec.extraHeaders {
		headers[strings.ToLower(k)] = v
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + strings.TrimSpace(headers[k]) + "\n")
	}

	var query []string
	for k, vs := range u.Query() {
		for _, v := range vs {
			query = append(query, awsURIEncode(k, true)+"="+awsURIEncode(v, true))
		}
	}
	sort.Strings(query)

	canonicalRequest := strings.Join([]string{
		http.MethodPut,
		awsURIEncode(u.Path, false),
		strings.Join(query, "&"),
		canonHeaders.String(),
		strings.Join(names, ";"),
		spec.mode,
	}, "\n")
	key := awsHMAC([]byte("AWS4"+secret), []byte(dateStamp))
	key = awsHMAC(key, []byte("us-east-1"))
	key = awsHMAC(key, []byte("s3"))
	key = awsHMAC(key, []byte("aws4_request"))
	seed := hex.EncodeToString(awsHMAC(key, []byte(strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, awsSHA256Hex(canonicalRequest),
	}, "\n"))))

	s := &streamSigning{key: key, amzDate: amzDate, scope: scope, prev: seed}
	var body bytes.Buffer
	writeChunk := func(chunk []byte) {
		body.WriteString(strconv.FormatInt(int64(len(chunk)), 16))
		if signed {
			sum := sha256.Sum256(chunk)
			body.WriteString(";chunk-signature=" + s.sign("AWS4-HMAC-SHA256-PAYLOAD", emptyPayloadSHA256, hex.EncodeToString(sum[:])))
		}
		body.WriteString("\r\n")
		if len(chunk) > 0 {
			body.Write(chunk)
			body.WriteString("\r\n")
		}
	}
	for off := 0; off < len(spec.data); off += spec.chunkSize {
		writeChunk(spec.data[off:min(off+spec.chunkSize, len(spec.data))])
	}
	writeChunk(nil)

	if trailerMode {
		if spec.trailerName != "" {
			value := spec.trailerValue
			if value == "" {
				value = crc32Base64(spec.data)
			}
			line := spec.trailerName + ":" + value
			if spec.minioLayout {
				body.WriteString(line + "\n")
			} else {
				body.WriteString(line + "\r\n")
			}
			if signed {
				sum := sha256.Sum256([]byte(line + "\n"))
				if spec.minioLayout {
					body.WriteString("\r\n")
				}
				body.WriteString("x-amz-trailer-signature:" + s.sign("AWS4-HMAC-SHA256-TRAILER", hex.EncodeToString(sum[:])) + "\r\n")
			} else if spec.minioLayout {
				body.WriteString("\r\n")
			}
		} else if signed {
			sum := sha256.Sum256(nil)
			body.WriteString("x-amz-trailer-signature:" + s.sign("AWS4-HMAC-SHA256-TRAILER", hex.EncodeToString(sum[:])) + "\r\n")
		}
	}
	body.WriteString("\r\n")

	framed := body.Bytes()
	if spec.tamper != nil {
		framed = spec.tamper(framed)
	}
	req := httptest.NewRequest(http.MethodPut, target, bytes.NewReader(framed))
	for k, v := range headers {
		if k != "host" {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+tok.TokenID+"/"+scope+
		", SignedHeaders="+strings.Join(names, ";")+", Signature="+seed)
	return req
}

// declaring overrides the declared decoded length of a spec.
func declaring(spec streamSpec, n int) streamSpec {
	spec.declaredLength = n
	spec.overrideLength = true
	return spec
}

// flipChunkSignature returns a tamper function that changes one hex digit of
// the nth chunk-signature.
func flipChunkSignature(n int) func([]byte) []byte {
	return func(b []byte) []byte {
		out := bytes.Clone(b)
		marker := []byte(";chunk-signature=")
		off := 0
		for range n {
			idx := bytes.Index(out[off:], marker)
			if idx < 0 {
				return out
			}
			off += idx + len(marker)
		}
		if out[off] == '0' {
			out[off] = '1'
		} else {
			out[off] = '0'
		}
		return out
	}
}

// patternData returns n bytes that are not all the same, so a misplaced chunk
// boundary changes the result.
func patternData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

// storedBytes reads the object back through the handler as a client would.
func storedBytes(t *testing.T, h *Handler, tok *meta.Token, secret, bucket, key string) ([]byte, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Body.Bytes(), w.Code
}

func decodeS3Error(t *testing.T, w *httptest.ResponseRecorder) S3Error {
	t.Helper()
	var errResp S3Error
	if err := xml.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("response is not an S3 error document: %v (%s)", err, w.Body.String())
	}
	return errResp
}

// ── Accepted: the payload is stored, never the framing ─────────────────────

func TestChunkedUpload_PutObjectStoresThePayload(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec streamSpec
	}{
		{"signed, one chunk", streamSpec{mode: streamSigned, data: []byte("hola desde jay\n")}},
		{"signed, many chunks", streamSpec{mode: streamSigned, data: patternData(200_000)}},
		{"signed, small chunks", streamSpec{mode: streamSigned, data: patternData(5000), chunkSize: 333}},
		{"signed, empty object", streamSpec{mode: streamSigned, data: nil}},
		{"signed trailer, AWS SDK layout", streamSpec{mode: streamSignedTrailer, data: patternData(70_000), trailerName: "x-amz-checksum-crc32"}},
		{"signed trailer, minio-go layout", streamSpec{mode: streamSignedTrailer, data: patternData(70_000), trailerName: "x-amz-checksum-crc32", minioLayout: true}},
		{"unsigned trailer, AWS SDK layout", streamSpec{mode: streamUnsignedTrailer, data: patternData(70_000), trailerName: "x-amz-checksum-crc32"}},
		{"unsigned trailer, minio-go layout", streamSpec{mode: streamUnsignedTrailer, data: patternData(70_000), trailerName: "x-amz-checksum-crc32", minioLayout: true}},
		{"unsigned trailer mode with no trailer", streamSpec{mode: streamUnsignedTrailer, data: patternData(1000)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db, tok, secret := fullSetupTestHandler(t)
			chunkedTestBucket(t, db, tok, "chunk-bkt")

			req := streamingRequest(t, "/chunk-bkt/obj.bin", tok, secret, tc.spec)
			framedLen := req.ContentLength
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
			}

			got, code := storedBytes(t, h, tok, secret, "chunk-bkt", "obj.bin")
			if code != http.StatusOK {
				t.Fatalf("GET after upload: %d", code)
			}
			if !bytes.Equal(got, tc.spec.data) {
				t.Fatalf("stored %d bytes, want the %d-byte payload (framing was %d bytes)",
					len(got), len(tc.spec.data), framedLen)
			}

			_, obj, err := db.GetBucketAndObject("chunk-bkt", "obj.bin")
			if err != nil {
				t.Fatalf("metadata: %v", err)
			}
			if obj.SizeBytes != int64(len(tc.spec.data)) {
				t.Errorf("metadata size %d, want the decoded %d", obj.SizeBytes, len(tc.spec.data))
			}
			wantMD5 := md5.Sum(tc.spec.data)
			if obj.ETag != hex.EncodeToString(wantMD5[:]) {
				t.Errorf("ETag %s is not the MD5 of the payload", obj.ETag)
			}
			wantSHA := sha256.Sum256(tc.spec.data)
			if obj.ChecksumSHA256 != hex.EncodeToString(wantSHA[:]) {
				t.Errorf("checksum %s is not the SHA-256 of the payload", obj.ChecksumSHA256)
			}
			if tc.spec.trailerName != "" {
				if got := w.Header().Get(tc.spec.trailerName); got != crc32Base64(tc.spec.data) {
					t.Errorf("%s echoed %q, want %q", tc.spec.trailerName, got, crc32Base64(tc.spec.data))
				}
			}
		})
	}
}

// minio-go frames multipart parts exactly like whole objects. Two framed parts
// assemble into the concatenation of their payloads.
func TestChunkedUpload_UploadPartStoresThePayload(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	chunkedTestBucket(t, db, tok, "chunk-bkt")
	uploadID := createUploadForTest(t, h, tok, secret, "chunk-bkt", "mp.bin")

	part1, part2 := patternData(100_000), bytes.Repeat([]byte("z"), 5000)
	etags := make([]string, 0, 2)
	for i, spec := range []streamSpec{
		{mode: streamSigned, data: part1},
		{mode: streamSignedTrailer, data: part2, trailerName: "x-amz-checksum-crc32"},
	} {
		req := streamingRequest(t, "/chunk-bkt/mp.bin?partNumber="+strconv.Itoa(i+1)+"&uploadId="+uploadID, tok, secret, spec)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("part %d: want 200, got %d: %s", i+1, w.Code, w.Body.String())
		}
		etags = append(etags, w.Header().Get("ETag"))
	}

	completeUploadForTest(t, h, tok, secret, "chunk-bkt", "mp.bin", uploadID, etags)
	got, _ := storedBytes(t, h, tok, secret, "chunk-bkt", "mp.bin")
	if want := append(bytes.Clone(part1), part2...); !bytes.Equal(got, want) {
		t.Fatalf("assembled %d bytes, want the %d of the two payloads", len(got), len(want))
	}
}

func createUploadForTest(t *testing.T, h *Handler, tok *meta.Token, secret, bucket, key string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/"+bucket+"/"+key+"?uploads", nil)
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var res InitiateMultipartUploadResult
	if err := xml.Unmarshal(w.Body.Bytes(), &res); err != nil || res.UploadID == "" {
		t.Fatalf("create multipart upload: %d %s", w.Code, w.Body.String())
	}
	return res.UploadID
}

func completeUploadForTest(t *testing.T, h *Handler, tok *meta.Token, secret, bucket, key, uploadID string, etags []string) {
	t.Helper()
	var doc strings.Builder
	doc.WriteString("<CompleteMultipartUpload>")
	for i, e := range etags {
		doc.WriteString("<Part><PartNumber>" + strconv.Itoa(i+1) + "</PartNumber><ETag>" + e + "</ETag></Part>")
	}
	doc.WriteString("</CompleteMultipartUpload>")
	req := httptest.NewRequest(http.MethodPost, "/"+bucket+"/"+key+"?uploadId="+uploadID, strings.NewReader(doc.String()))
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("complete multipart: %d %s", w.Code, w.Body.String())
	}
}

// ── Refused mid-stream: nothing is committed ────────────────────────────────

// The failure case that matters: a body that goes wrong AFTER jay has started
// writing it. Whatever the reason, the answer is an error, the previous object
// under the same key is untouched, and the data directory holds exactly what
// it held before — no new object, no temp file.
func TestChunkedUpload_RejectedMidStreamCommitsNothing(t *testing.T) {
	data := patternData(3 * 64 << 10)
	for _, tc := range []struct {
		name   string
		spec   streamSpec
		status int
		code   string
	}{
		{"first chunk signature altered", streamSpec{mode: streamSigned, data: data, tamper: flipChunkSignature(1)},
			http.StatusForbidden, s3ErrSignatureDoesNotMatch},
		{"second chunk signature altered", streamSpec{mode: streamSigned, data: data, tamper: flipChunkSignature(2)},
			http.StatusForbidden, s3ErrSignatureDoesNotMatch},
		{"final chunk signature altered", streamSpec{mode: streamSigned, data: data, tamper: flipChunkSignature(4)},
			http.StatusForbidden, s3ErrSignatureDoesNotMatch},
		{"a data byte altered", streamSpec{mode: streamSigned, data: data, tamper: func(b []byte) []byte {
			out := bytes.Clone(b)
			out[len(out)/2] ^= 0x01
			return out
		}}, http.StatusForbidden, s3ErrSignatureDoesNotMatch},
		{"declares more than it sends", declaring(streamSpec{mode: streamSigned, data: data}, len(data)+1),
			http.StatusBadRequest, s3ErrIncompleteBody},
		{"declares less than it sends", declaring(streamSpec{mode: streamSigned, data: data}, len(data)-1),
			http.StatusBadRequest, s3ErrIncompleteBody},
		{"truncated body", streamSpec{mode: streamSigned, data: data, tamper: func(b []byte) []byte {
			return b[:len(b)-100]
		}}, http.StatusBadRequest, s3ErrInvalidRequest},
		{"trailing checksum is wrong (unsigned trailer)", streamSpec{mode: streamUnsignedTrailer, data: data,
			trailerName: "x-amz-checksum-crc32", trailerValue: "AAAAAA=="}, http.StatusBadRequest, s3ErrBadDigest},
		{"trailing checksum is wrong (signed trailer)", streamSpec{mode: streamSignedTrailer, data: data,
			trailerName: "x-amz-checksum-crc32", trailerValue: "AAAAAA=="}, http.StatusBadRequest, s3ErrBadDigest},
		{"trailing checksum is not base64", streamSpec{mode: streamUnsignedTrailer, data: data,
			trailerName: "x-amz-checksum-crc32", trailerValue: "!!!!"}, http.StatusBadRequest, s3ErrInvalidRequest},
		{"trailing checksum altered after signing", streamSpec{mode: streamSignedTrailer, data: data,
			trailerName: "x-amz-checksum-crc32", tamper: func(b []byte) []byte {
				good := []byte("x-amz-checksum-crc32:" + crc32Base64(data))
				return bytes.Replace(b, good, []byte("x-amz-checksum-crc32:AAAAAA=="), 1)
			}}, http.StatusForbidden, s3ErrSignatureDoesNotMatch},
		{"declared trailer never sent", streamSpec{mode: streamUnsignedTrailer, data: data,
			trailerName: "x-amz-checksum-crc32", tamper: func(b []byte) []byte {
				i := bytes.Index(b, []byte("x-amz-checksum-crc32:"))
				return append(bytes.Clone(b[:i]), "\r\n"...)
			}}, http.StatusBadRequest, s3ErrInvalidRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db, tok, secret := fullSetupTestHandler(t)
			chunkedTestBucket(t, db, tok, "chunk-bkt")
			putObjectForTest(t, h, tok, secret, "chunk-bkt", "obj.bin", "the previous version")
			before := walkDataDir(t, h)

			w := httptest.NewRecorder()
			h.ServeHTTP(w, streamingRequest(t, "/chunk-bkt/obj.bin", tok, secret, tc.spec))

			if w.Code != tc.status {
				t.Fatalf("want %d, got %d: %s", tc.status, w.Code, w.Body.String())
			}
			if got := decodeS3Error(t, w).Code; got != tc.code {
				t.Errorf("Code = %q, want %q", got, tc.code)
			}
			got, _ := storedBytes(t, h, tok, secret, "chunk-bkt", "obj.bin")
			if string(got) != "the previous version" {
				t.Fatalf("the previous object was replaced: now %d bytes", len(got))
			}
			if after := walkDataDir(t, h); strings.Join(after, "\n") != strings.Join(before, "\n") {
				t.Fatalf("data dir changed after a rejected upload:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

// Without a previous version, a refused upload leaves no object at all.
func TestChunkedUpload_RejectedLeavesNoObject(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	chunkedTestBucket(t, db, tok, "chunk-bkt")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, streamingRequest(t, "/chunk-bkt/new.bin", tok, secret,
		streamSpec{mode: streamSigned, data: patternData(1000), tamper: flipChunkSignature(1)}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
	if _, _, err := db.GetBucketAndObject("chunk-bkt", "new.bin"); err == nil {
		t.Fatal("object metadata was committed for a rejected upload")
	}
	if files := walkDataDir(t, h); len(files) != 0 {
		t.Fatalf("a rejected upload left files behind: %v", files)
	}
}

// A refused part does not take the place of the part it retries, and is not
// registered.
func TestChunkedUpload_RejectedPartIsNotRegistered(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	chunkedTestBucket(t, db, tok, "chunk-bkt")
	uploadID := createUploadForTest(t, h, tok, secret, "chunk-bkt", "mp.bin")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, streamingRequest(t, "/chunk-bkt/mp.bin?partNumber=1&uploadId="+uploadID, tok, secret,
		streamSpec{mode: streamSigned, data: patternData(70_000), tamper: flipChunkSignature(2)}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
	upload, err := db.GetMultipartUpload(uploadID)
	if err != nil {
		t.Fatalf("get upload: %v", err)
	}
	if len(upload.Parts) != 0 {
		t.Fatalf("a rejected part was registered: %+v", upload.Parts)
	}
}

// The size ceiling applies to the decoded payload, framed or not.
func TestChunkedUpload_MaxObjectSizeAppliesToThePayload(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	chunkedTestBucket(t, db, tok, "chunk-bkt")
	h.SetMaxObjectSize(1000)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, streamingRequest(t, "/chunk-bkt/big.bin", tok, secret, streamSpec{mode: streamSigned, data: patternData(1001)}))
	if w.Code != http.StatusBadRequest || decodeS3Error(t, w).Code != s3ErrEntityTooLarge {
		t.Fatalf("want 400 EntityTooLarge, got %d: %s", w.Code, w.Body.String())
	}
	if _, _, err := db.GetBucketAndObject("chunk-bkt", "big.bin"); err == nil {
		t.Fatal("an over-sized framed upload was committed")
	}

	// And the framing does not count against it: exactly at the ceiling, with
	// ~100 bytes of framing on top, is accepted.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, streamingRequest(t, "/chunk-bkt/edge.bin", tok, secret, streamSpec{mode: streamSigned, data: patternData(1000)}))
	if w.Code != http.StatusOK {
		t.Fatalf("an upload exactly at the ceiling: want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ── Refused before reading: what jay does not decode ────────────────────────

// Trailers jay cannot verify are refused before a byte of the body is read,
// never accepted and ignored.
func TestChunkedUpload_UnverifiableTrailerRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec streamSpec
	}{
		{"not a checksum", streamSpec{mode: streamUnsignedTrailer, data: []byte("x"), trailerName: "x-amz-meta-foo", trailerValue: "bar"}},
		{"an algorithm S3 does not define", streamSpec{mode: streamUnsignedTrailer, data: []byte("x"), trailerName: "x-amz-checksum-md5", trailerValue: "AAAAAAAAAAAAAAAAAAAAAA=="}},
		{"a digest in a header AND in the trailer", streamSpec{mode: streamUnsignedTrailer, data: []byte("x"), trailerName: "x-amz-checksum-crc32",
			extraHeaders: map[string]string{"x-amz-checksum-crc32": crc32Base64([]byte("x"))}}},
		{"the algorithm header names another algorithm", streamSpec{mode: streamUnsignedTrailer, data: []byte("x"), trailerName: "x-amz-checksum-crc32",
			extraHeaders: map[string]string{"x-amz-sdk-checksum-algorithm": "SHA256"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db, tok, secret := fullSetupTestHandler(t)
			chunkedTestBucket(t, db, tok, "chunk-bkt")
			before := walkDataDir(t, h)

			w := httptest.NewRecorder()
			h.ServeHTTP(w, streamingRequest(t, "/chunk-bkt/obj.bin", tok, secret, tc.spec))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
			}
			if _, _, err := db.GetBucketAndObject("chunk-bkt", "obj.bin"); err == nil {
				t.Fatal("object committed")
			}
			if after := walkDataDir(t, h); len(after) != len(before) {
				t.Fatalf("data dir changed: %v → %v", before, after)
			}
		})
	}
}

// Every request carrying aws-chunked framing that jay will NOT decode answers
// 501 before authentication, and writes nothing. Refusing is the honest answer
// where decoding would be unverifiable (no seed signature) or unsafe (a
// handler that acts before the end of the body).
func TestChunkedBody_RefusedWhereItCannotBeDecoded(t *testing.T) {
	sigv4 := func(t *testing.T, tok *meta.Token, secret, method, target string) *http.Request {
		req := streamingRequest(t, "/chunk-bkt/obj.txt", tok, secret, streamSpec{mode: streamSigned, data: []byte("hola")})
		out := httptest.NewRequest(method, target, req.Body)
		out.Header = req.Header.Clone()
		return out
	}
	tests := []struct {
		name  string
		build func(t *testing.T, tok *meta.Token, secret string) *http.Request
	}{
		{"PutObject under a bearer token", func(t *testing.T, tok *meta.Token, secret string) *http.Request {
			req := httptest.NewRequest(http.MethodPut, "/chunk-bkt/obj.txt", strings.NewReader(awsChunkedBody))
			req.Header.Set("Authorization", authHeader(tok, secret))
			req.Header.Set("x-amz-content-sha256", streamSigned)
			req.Header.Set("x-amz-decoded-content-length", "15")
			return req
		}},
		{"PutObject announced only by Content-Encoding, bearer", func(t *testing.T, tok *meta.Token, secret string) *http.Request {
			req := httptest.NewRequest(http.MethodPut, "/chunk-bkt/obj.txt", strings.NewReader(awsChunkedBody))
			req.Header.Set("Authorization", authHeader(tok, secret))
			req.Header.Set("Content-Encoding", "aws-chunked")
			return req
		}},
		{"PutObject with no credentials at all", func(t *testing.T, _ *meta.Token, _ string) *http.Request {
			req := httptest.NewRequest(http.MethodPut, "/chunk-bkt/obj.txt", strings.NewReader(awsChunkedBody))
			req.Header.Set("x-amz-content-sha256", streamSigned)
			return req
		}},
		{"PutObject by SigV4 presigned URL", func(t *testing.T, tok *meta.Token, secret string) *http.Request {
			spec := presignSpec{accessKey: tok.TokenID, secret: secret, method: http.MethodPut, path: "/chunk-bkt/obj.txt"}
			req := presignedRequest(t, http.MethodPut, presignedTarget(t, spec), awsChunkedBody, spec)
			req.Header.Set("x-amz-content-sha256", streamUnsignedTrailer)
			req.Header.Set("x-amz-decoded-content-length", "15")
			return req
		}},
		{"PutObject by jay presigned URL", func(t *testing.T, tok *meta.Token, _ string) *http.Request {
			req := httptest.NewRequest(http.MethodPut,
				"/chunk-bkt/obj.txt?X-Jay-Token="+tok.TokenID+"&X-Jay-Expires=9999999999&X-Jay-Signature=00",
				strings.NewReader(awsChunkedBody))
			req.Header.Set("Content-Encoding", "aws-chunked")
			return req
		}},
		{"SigV4a ECDSA streaming", func(t *testing.T, tok *meta.Token, secret string) *http.Request {
			return streamingRequest(t, "/chunk-bkt/obj.txt", tok, secret,
				streamSpec{mode: "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD", data: []byte("hola")})
		}},
		{"CreateBucket", func(t *testing.T, tok *meta.Token, secret string) *http.Request {
			return sigv4(t, tok, secret, http.MethodPut, "/another-bkt")
		}},
		{"DeleteObjects", func(t *testing.T, tok *meta.Token, secret string) *http.Request {
			return sigv4(t, tok, secret, http.MethodPost, "/chunk-bkt?delete")
		}},
		{"CompleteMultipartUpload", func(t *testing.T, tok *meta.Token, secret string) *http.Request {
			return sigv4(t, tok, secret, http.MethodPost, "/chunk-bkt/obj.txt?uploadId=nope")
		}},
		{"CopyObject", func(t *testing.T, tok *meta.Token, secret string) *http.Request {
			req := sigv4(t, tok, secret, http.MethodPut, "/chunk-bkt/obj.txt")
			req.Header.Set("x-amz-copy-source", "/chunk-bkt/other.txt")
			return req
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, db, tok, secret := fullSetupTestHandler(t)
			chunkedTestBucket(t, db, tok, "chunk-bkt")
			before := walkDataDir(t, h)

			w := httptest.NewRecorder()
			h.ServeHTTP(w, tc.build(t, tok, secret))

			if w.Code != http.StatusNotImplemented {
				t.Fatalf("want 501, got %d: %s", w.Code, w.Body.String())
			}
			errResp := decodeS3Error(t, w)
			if errResp.Code != S3ErrNotImplemented {
				t.Errorf("Code = %q, want %q", errResp.Code, S3ErrNotImplemented)
			}
			if errResp.RequestID == "" {
				t.Error("RequestId is empty")
			}
			if after := walkDataDir(t, h); len(after) != len(before) {
				t.Errorf("data dir changed after a refused request:\nbefore %v\nafter  %v", before, after)
			}
			if _, _, err := db.GetBucketAndObject("chunk-bkt", "obj.txt"); err == nil {
				t.Error("object metadata was committed for a refused request")
			}
			if _, err := db.GetBucket("another-bkt"); err == nil {
				t.Error("a bucket was created by a refused request")
			}
		})
	}
}

// A valid jay presigned URL cannot carry framing past the gate by adding a
// header that only looks like SigV4. withChunkedBodyGate admits framing for a
// SigV4 Authorization header — AuthenticateSigV4 decodes it — so the X-Jay
// branch must not serve such a request as a presign, or the framing is stored
// as the object with a 200 (the PND-0186 defect, reached by another door).
func TestChunkedBody_JayPresignCannotSmuggleFraming(t *testing.T) {
	jayPresigned := func(h *Handler, tok *meta.Token) string {
		expires := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
		sig := computeSignature(h.signingSecret, tok.TokenID, http.MethodPut, "/chunk-bkt/obj.txt", "", expires)
		return "/chunk-bkt/obj.txt?X-Jay-Token=" + tok.TokenID + "&X-Jay-Expires=" + expires + "&X-Jay-Signature=" + sig
	}
	framed := func(target string) *http.Request {
		req := httptest.NewRequest(http.MethodPut, target, strings.NewReader(awsChunkedBody))
		req.Header.Set("x-amz-content-sha256", streamSigned)
		req.Header.Set("x-amz-decoded-content-length", "15")
		req.Header.Set("Content-Encoding", "aws-chunked")
		return req
	}
	assertNothingWritten := func(t *testing.T, h *Handler, db *meta.DB, before []string) {
		t.Helper()
		if after := walkDataDir(t, h); len(after) != len(before) {
			t.Errorf("data dir changed after a refused request:\nbefore %v\nafter  %v", before, after)
		}
		if _, _, err := db.GetBucketAndObject("chunk-bkt", "obj.txt"); err == nil {
			t.Error("object metadata was committed for a refused request")
		}
	}

	t.Run("with a forged SigV4 header, through the full chain", func(t *testing.T) {
		h, db, tok, _ := fullSetupTestHandler(t)
		h.signingSecret = "server-signing-secret-at-least-32-chars"
		chunkedTestBucket(t, db, tok, "chunk-bkt")
		before := walkDataDir(t, h)

		req := framed(jayPresigned(h, tok))
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 garbage")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		// The header wins, so this is an ordinary SigV4 request whose
		// signature does not parse: refused by auth, never served as a presign.
		if w.Code != http.StatusForbidden {
			t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
		}
		assertNothingWritten(t, h, db, before)
	})

	t.Run("the presign path refuses framing on its own", func(t *testing.T) {
		h, db, tok, _ := fullSetupTestHandler(t)
		h.signingSecret = "server-signing-secret-at-least-32-chars"
		chunkedTestBucket(t, db, tok, "chunk-bkt")
		before := walkDataDir(t, h)

		// withPresigned alone, without withChunkedBodyGate in front: the
		// second lock must hold even if the middleware order changes.
		w := httptest.NewRecorder()
		h.withPresigned(func(http.ResponseWriter, *http.Request) {
			t.Fatal("a valid X-Jay presign fell through to the normal auth path")
		})(w, framed(jayPresigned(h, tok)))

		if w.Code != http.StatusNotImplemented {
			t.Fatalf("want 501, got %d: %s", w.Code, w.Body.String())
		}
		if code := decodeS3Error(t, w).Code; code != S3ErrNotImplemented {
			t.Errorf("Code = %q, want %q", code, S3ErrNotImplemented)
		}
		assertNothingWritten(t, h, db, before)
	})

	t.Run("an unframed X-Jay presign still stores its body", func(t *testing.T) {
		h, db, tok, secret := fullSetupTestHandler(t)
		h.signingSecret = "server-signing-secret-at-least-32-chars"
		chunkedTestBucket(t, db, tok, "chunk-bkt")

		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPut, jayPresigned(h, tok), strings.NewReader("hola desde jay\n")))
		if w.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
		}
		if got, code := storedBytes(t, h, tok, secret, "chunk-bkt", "obj.txt"); code != http.StatusOK || string(got) != "hola desde jay\n" {
			t.Errorf("stored %q (GET %d), want the 15-byte payload", got, code)
		}
	})
}

// An announcement that does not add up answers 400 before a byte is read.
func TestChunkedBody_MalformedAnnouncementRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"x-amz-decoded-content-length missing", func(r *http.Request) { r.Header.Del("x-amz-decoded-content-length") }},
		{"x-amz-decoded-content-length not a number", func(r *http.Request) { r.Header.Set("x-amz-decoded-content-length", "15 bytes") }},
		{"framing announced without a streaming mode", func(r *http.Request) { r.Header.Set("x-amz-content-sha256", "UNSIGNED-PAYLOAD") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, db, tok, secret := fullSetupTestHandler(t)
			chunkedTestBucket(t, db, tok, "chunk-bkt")
			req := streamingRequest(t, "/chunk-bkt/obj.txt", tok, secret, streamSpec{mode: streamSigned, data: []byte("hola")})
			tc.mutate(req)

			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest || decodeS3Error(t, w).Code != s3ErrInvalidRequest {
				t.Fatalf("want 400 InvalidRequest, got %d: %s", w.Code, w.Body.String())
			}
			if _, _, err := db.GetBucketAndObject("chunk-bkt", "obj.txt"); err == nil {
				t.Fatal("object committed")
			}
		})
	}
}

// A body with no framing is untouched by the gate. This is the aws-cli path:
// a real payload hash, no x-amz-decoded-content-length, no aws-chunked coding.
func TestUnframedBodyStillAccepted(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	chunkedTestBucket(t, db, tok, "chunk-bkt")

	body := "hola desde jay\n"
	req := httptest.NewRequest(http.MethodPut, "/chunk-bkt/plain.txt", strings.NewReader(body))
	req.Header.Set("Authorization", authHeader(tok, secret))
	req.Header.Set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	got, _ := storedBytes(t, h, tok, secret, "chunk-bkt", "plain.txt")
	if string(got) != body {
		t.Errorf("stored %q, want %q", got, body)
	}
}

// Guard for the encoder above: a request it builds must actually be what the
// server decodes, or every refusal test here would pass for the wrong reason.
func TestStreamingEncoder_ProducesAVerifiableRequest(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	chunkedTestBucket(t, db, tok, "chunk-bkt")
	req := streamingRequest(t, "/chunk-bkt/guard.bin", tok, secret, streamSpec{mode: streamSigned, data: []byte("guard")})
	raw, _ := io.ReadAll(req.Body)
	if !bytes.Contains(raw, []byte(";chunk-signature=")) || !bytes.HasSuffix(raw, []byte("\r\n\r\n")) {
		t.Fatalf("encoder produced an unframed body: %q", raw)
	}
	req.Body = io.NopCloser(bytes.NewReader(raw))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}
