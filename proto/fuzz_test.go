package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"testing"
)

// Fuzz targets for the hand-written binary decoder.
//
// Everything here parses bytes that came off a socket. ReadHandshake and
// ReadHeader run BEFORE authentication, so any peer that can reach the native
// port can drive them with whatever it likes. The size caps that already
// existed (MaxMetaSize, the uint16 prefixes, MaxDrainSize) bound how MUCH
// hostile input can arrive; they say nothing about its SHAPE.
//
// The invariant every target asserts is the same and is deliberately weak:
// never panic, always terminate, and either return an error or a value that
// is self-consistent. A decoder is allowed to reject anything; it is not
// allowed to crash the process or to hand back a value it did not verify.
//
// Run the corpus (fast, part of `make test`):
//
//	go test ./proto/ -run Fuzz
//
// Actually fuzz (slow, its own CI job — see .github/workflows/fuzz.yml):
//
//	go test ./proto/ -fuzz FuzzDecoder -fuzztime 60s

// seedMetas returns encoded messages used to seed several corpora, plus the
// edge cases the limit tests in proto_test.go already established.
func seedMetas() [][]byte {
	var seeds [][]byte

	add := func(bs []byte, err error) {
		if err == nil {
			seeds = append(seeds, bs)
		}
	}

	add(EncodeBucketKey("bucket", "key"))
	add(EncodeBucket("bucket"))
	add(EncodePutObjectRequest("b", "k", "text/plain", map[string]string{"a": "1"}, true))
	add(EncodePutResponse("etag", "checksum"))
	add(EncodeObjectInfo("text/plain", 42, "etag", "cs", "2026-01-01T00:00:00Z", nil))
	add(EncodeBucketInfo("id", "name", "2026-01-01T00:00:00Z", "private"))
	add(EncodeListObjectsRequest("b", "p/", "/", "after", 1000))
	add(EncodeListObjectsResponse(
		[]ListObjectEntry{{Key: "k", Size: 1, ETag: "e", ChecksumSHA256: "c", LastModified: "t", ContentType: "ct"}},
		[]string{"p/"}, true, "next"))
	add(EncodeCreateMultipartRequest("b", "k", "ct"))
	add(EncodeUploadPartRequest("b", "k", "u", 1))
	add(EncodeCompleteMultipartRequest("b", "k", "u", []int{1, 2, 3}))
	add(EncodeBucketKeyUpload("b", "k", "u"))
	add(EncodeCompleteMultipartResponse("e", "c", 99))
	add(EncodeListPartsResponse([]PartInfoEntry{{PartNumber: 1, Size: 2, ETag: "e", ChecksumSHA256: "c"}}))
	add(EncodeBucketList([]string{"b1", "b2"}, []string{"t1", "t2"}))
	seeds = append(seeds, EncodeError("boom", "InternalError"))

	// Hostile shapes, not just valid messages. These are the ones that
	// actually exercise the bounds checks.
	seeds = append(seeds,
		nil,                            // empty
		[]byte{0x00},                   // half a length prefix
		[]byte{0xFF, 0xFF},             // max count, no data behind it
		[]byte{0xFF, 0xFF, 0xFF, 0xFF}, // max string length, no data behind it
		[]byte{0x00, 0x01},             // one-byte string promised, none given
		[]byte{0x00, 0x00},             // empty string / zero count
		bytes.Repeat([]byte{0x00}, 64), // all zeroes
		bytes.Repeat([]byte{0xFF}, 64), // all ones
	)

	return seeds
}

// FuzzDecoder drives the primitive reader with arbitrary bytes. It reads every
// field type in sequence so a single input exercises several bounds checks.
func FuzzDecoder(f *testing.F) {
	for _, s := range seedMetas() {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		d := NewDecoder(data)

		// Interleave types so offsets land at odd alignments.
		_ = d.String()
		_ = d.Int64()
		_ = d.Int32()
		_ = d.Bool()
		_ = d.StringMap()
		_ = d.Strings()
		_ = d.Ints()
		_ = d.String()

		// The decoder must never read past its buffer, error or not.
		if d.off > len(d.buf) {
			t.Fatalf("decoder offset %d past buffer length %d", d.off, len(d.buf))
		}
		// A latched error must stay latched: HasMore is what optional trailing
		// fields branch on, and it must never resurrect a failed decode.
		if d.Err() != nil && d.HasMore() {
			t.Fatal("HasMore reports true after an error was latched")
		}
	})
}

// FuzzDecodeMessages runs every Decode* entry point over the same input. These
// are the functions the server calls on a frame's metadata.
func FuzzDecodeMessages(f *testing.F) {
	for _, s := range seedMetas() {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// None of these may panic. Return values are ignored on purpose: the
		// property under test is that a hostile buffer cannot crash a decoder,
		// not that it produces anything in particular.
		_, _, _ = DecodeBucketKey(data)
		_, _ = DecodeBucket(data)
		_, _, _, _, _, _ = DecodePutObjectRequest(data)
		_, _, _ = DecodePutResponse(data)
		_, _, _, _, _, _, _ = DecodeObjectInfo(data)
		_, _, _ = DecodeError(data)
		_, _, _, _, _ = DecodeBucketInfo(data)
		_, _, _, _, _, _ = DecodeListObjectsRequest(data)
		_, _, _, _, _ = DecodeListObjectsResponse(data)
		_, _, _, _ = DecodeCreateMultipartRequest(data)
		_, _, _, _, _ = DecodeUploadPartRequest(data)
		_, _, _, _, _ = DecodeCompleteMultipartRequest(data)
		_, _, _, _ = DecodeBucketKeyUpload(data)
		_, _, _, _ = DecodeCompleteMultipartResponse(data)
		_, _ = DecodeListPartsResponse(data)
		_, _, _ = DecodeBucketList(data)

		// A decoder that reports success must have produced a value that
		// survives being re-encoded. Anything else means it accepted bytes it
		// did not actually understand.
		if objs, prefixes, truncated, next, err := DecodeListObjectsResponse(data); err == nil {
			reencoded, encErr := EncodeListObjectsResponse(objs, prefixes, truncated, next)
			if encErr != nil {
				t.Fatalf("decoded a ListObjectsResponse that cannot be re-encoded: %v", encErr)
			}
			objs2, prefixes2, truncated2, next2, err2 := DecodeListObjectsResponse(reencoded)
			if err2 != nil {
				t.Fatalf("re-encoded ListObjectsResponse no longer decodes: %v", err2)
			}
			if len(objs2) != len(objs) || len(prefixes2) != len(prefixes) ||
				truncated2 != truncated || next2 != next {
				t.Fatal("ListObjectsResponse is not stable across a decode/encode/decode cycle")
			}
		}
	})
}

// FuzzReadHandshake covers the pre-auth surface: these bytes are parsed before
// any credential is examined.
func FuzzReadHandshake(f *testing.F) {
	valid := &bytes.Buffer{}
	_ = WriteHandshake(valid, "token:secret")
	f.Add(valid.Bytes())

	f.Add([]byte{})
	f.Add([]byte{0x4A, 0x41, 0x59, 0x00})                                     // magic only
	f.Add([]byte{0x4A, 0x41, 0x59, 0x00, 0x01, 0x00, 0x00, 0x00})             // zero-length creds
	f.Add([]byte{0x4A, 0x41, 0x59, 0x00, 0x01, 0x00, 0xFF, 0xFF})             // 64 KiB promised, none sent
	f.Add([]byte{0x4A, 0x41, 0x59, 0x00, 0x02, 0x00, 0x00, 0x01, 0x41})       // wrong version
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00, 0x00, 0x01, 0x41})       // wrong magic
	f.Add([]byte{0x4A, 0x41, 0x59, 0x00, 0x01, 0xFF, 0x00, 0x01, 0x41})       // non-zero reserved flags
	f.Add([]byte{0x4A, 0x41, 0x59, 0x00, 0x01, 0x00, 0x00, 0x03, 0x61, 0x3A}) // truncated creds

	f.Fuzz(func(t *testing.T, data []byte) {
		creds, err := ReadHandshake(bytes.NewReader(data))
		if err != nil {
			// A protocol disagreement must be classifiable as the specific
			// thing that is wrong, because the server answers with a status
			// derived from it. Getting this wrong is what made every failure
			// — including a severed socket — report "version mismatch".
			if len(data) >= HandshakeSize {
				switch {
				case binary.BigEndian.Uint32(data[0:4]) != Magic:
					if !errors.Is(err, ErrHandshakeMagic) {
						t.Fatalf("bad magic must yield ErrHandshakeMagic, got %v", err)
					}
				case data[4] != Version:
					if !errors.Is(err, ErrHandshakeVersion) {
						t.Fatalf("bad version must yield ErrHandshakeVersion, got %v", err)
					}
				case binary.BigEndian.Uint16(data[6:8]) == 0:
					if !errors.Is(err, ErrHandshakeCredentials) {
						t.Fatalf("empty credentials must yield ErrHandshakeCredentials, got %v", err)
					}
				default:
					// Credentials were declared but not fully delivered: an
					// I/O failure, correctly left unclassified so the server
					// stays silent instead of inventing a diagnosis.
					if _, respond := handshakeRejection(err); respond {
						t.Fatalf("a truncated credential read must not be classified as a protocol status, got %v", err)
					}
				}
			}
			return
		}

		// A success means the magic and version matched exactly and a
		// non-empty credential was fully read.
		if len(data) < HandshakeSize {
			t.Fatalf("accepted a handshake shorter than %d bytes", HandshakeSize)
		}
		if binary.BigEndian.Uint32(data[0:4]) != Magic {
			t.Fatal("accepted a handshake with the wrong magic")
		}
		if data[4] != Version {
			t.Fatal("accepted a handshake with the wrong version")
		}
		if creds == "" {
			t.Fatal("accepted empty credentials")
		}
		if want := int(binary.BigEndian.Uint16(data[6:8])); len(creds) != want {
			t.Fatalf("credentials length %d does not match the declared %d", len(creds), want)
		}

		// The reserved flags byte must not affect the outcome: a future
		// version that assigns it needs today's servers to have ignored it.
		flipped := append([]byte(nil), data...)
		flipped[5] ^= 0xFF
		creds2, err2 := ReadHandshake(bytes.NewReader(flipped))
		if err2 != nil || creds2 != creds {
			t.Fatal("the reserved flags byte changed the handshake result; it must be ignored")
		}
	})
}

// FuzzReadHeader covers the other pre-auth parser. Every frame on a connection
// starts here, including the first one after a rejected handshake.
func FuzzReadHeader(f *testing.F) {
	valid := &bytes.Buffer{}
	_ = WriteHeader(valid, OpGetObject, 0, 10, 100)
	f.Add(valid.Bytes())

	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0x00}, HeaderSize))
	f.Add(bytes.Repeat([]byte{0xFF}, HeaderSize)) // negative data_len
	f.Add(bytes.Repeat([]byte{0x00}, HeaderSize-1))

	f.Fuzz(func(t *testing.T, data []byte) {
		op, streamID, metaLen, dataLen, err := ReadHeader(bytes.NewReader(data))
		if err != nil {
			return
		}

		if len(data) < HeaderSize {
			t.Fatalf("accepted a header shorter than %d bytes", HeaderSize)
		}
		// A negative data_len would make io.CopyN and LimitReader behave in
		// ways the callers do not expect; it must be rejected, never returned.
		if dataLen < 0 {
			t.Fatalf("returned a negative data_len: %d", dataLen)
		}

		// The header must round-trip: what we read is what a peer would write.
		var buf bytes.Buffer
		if err := WriteHeader(&buf, op, streamID, metaLen, dataLen); err != nil {
			t.Fatalf("cannot re-encode a header we accepted: %v", err)
		}
		if !bytes.Equal(buf.Bytes(), data[:HeaderSize]) {
			t.Fatalf("header does not round-trip:\nread  %x\nwrote %x", data[:HeaderSize], buf.Bytes())
		}
	})
}

// FuzzRoundTrip generates structured values, encodes them, and requires the
// decoder to return exactly what went in. This catches an ASYMMETRY between
// encoder and decoder, which the byte-exact golden tests cannot see and which
// the other direction of fuzzing does not reach.
func FuzzRoundTrip(f *testing.F) {
	f.Add("bucket", "key", "text/plain", int64(42), true)
	f.Add("", "", "", int64(0), false)
	f.Add("b", "k", "ct", int64(-1), true)

	f.Fuzz(func(t *testing.T, bucket, key, contentType string, size int64, flag bool) {
		// Values beyond the wire limits must be rejected by the encoder, not
		// silently truncated. That is a separate, already-tested property.
		if len(bucket) > maxWireStringLen || len(key) > maxWireStringLen || len(contentType) > maxWireStringLen {
			return
		}

		encoded, err := EncodePutObjectRequest(bucket, key, contentType, nil, flag)
		if err != nil {
			t.Fatalf("encode failed for values within the wire limits: %v", err)
		}
		gotBucket, gotKey, gotCT, _, gotFlag, err := DecodePutObjectRequest(encoded)
		if err != nil {
			t.Fatalf("cannot decode what we just encoded: %v", err)
		}
		if gotBucket != bucket || gotKey != key || gotCT != contentType || gotFlag != flag {
			t.Fatalf("PutObjectRequest round trip lost data:\nin  %q %q %q %v\nout %q %q %q %v",
				bucket, key, contentType, flag, gotBucket, gotKey, gotCT, gotFlag)
		}

		info, err := EncodeObjectInfo(contentType, size, bucket, key, "", nil)
		if err != nil {
			t.Fatalf("encode ObjectInfo failed: %v", err)
		}
		gotCT2, gotSize, gotETag, gotChecksum, _, _, err := DecodeObjectInfo(info)
		if err != nil {
			t.Fatalf("cannot decode the ObjectInfo we just encoded: %v", err)
		}
		if gotCT2 != contentType || gotSize != size || gotETag != bucket || gotChecksum != key {
			t.Fatal("ObjectInfo round trip lost data")
		}
	})
}

// TestDecoderDoesNotTrustCounts is the regression test for the allocation
// amplification the fuzz work turned up: a 2-byte count was believed before
// anything checked whether the data behind it existed, so 2 bytes of input
// bought 5.7 MB of allocation on a ListObjects response.
//
// It asserts bytes allocated rather than a returned capacity, because the
// decoders return nil on error — the allocation happened before the failure
// and a capacity check could not see it.
func TestDecoderDoesNotTrustCounts(t *testing.T) {
	maxCount := []byte{0xFF, 0xFF} // 65535 elements promised, none delivered

	cases := []struct {
		name   string
		decode func([]byte)
	}{
		{"ListObjectsResponse", func(d []byte) { _, _, _, _, _ = DecodeListObjectsResponse(d) }},
		{"ListPartsResponse", func(d []byte) { _, _ = DecodeListPartsResponse(d) }},
		{"BucketList", func(d []byte) { _, _, _ = DecodeBucketList(d) }},
		{"Strings", func(d []byte) { _ = NewDecoder(d).Strings() }},
		{"Ints", func(d []byte) { _ = NewDecoder(d).Ints() }},
		{"StringMap", func(d []byte) { _ = NewDecoder(d).StringMap() }},
	}

	// Generous: the point is to catch megabytes from two bytes, not to
	// police a few hundred bytes of bookkeeping.
	const budgetPerCall = 4096
	const iterations = 100

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			for range iterations {
				tc.decode(maxCount)
			}
			runtime.ReadMemStats(&after)

			perCall := (after.TotalAlloc - before.TotalAlloc) / iterations
			if perCall > budgetPerCall {
				t.Errorf("decoding a 2-byte hostile count allocated %d bytes per call (budget %d): "+
					"the element count is being trusted before the data behind it is checked",
					perCall, budgetPerCall)
			}
		})
	}
}

// TestDecoderAcceptsHonestCounts is the other half: the bound must not reject
// a message whose count IS backed by data, including the smallest legal
// encoding of each element.
func TestDecoderAcceptsHonestCounts(t *testing.T) {
	t.Run("ListObjectsResponse with minimal entries", func(t *testing.T) {
		// Two entries with every string empty — the tightest legal encoding,
		// and exactly where an off-by-one in the bound would show up.
		entries := []ListObjectEntry{{}, {}}
		encoded, err := EncodeListObjectsResponse(entries, nil, false, "")
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		got, _, _, _, err := DecodeListObjectsResponse(encoded)
		if err != nil {
			t.Fatalf("a legal minimal encoding was rejected: %v", err)
		}
		if len(got) != len(entries) {
			t.Fatalf("got %d entries, want %d", len(got), len(entries))
		}
	})

	t.Run("collections of empty strings", func(t *testing.T) {
		e := NewEncoder(nil)
		e.Strings([]string{"", "", ""})
		if err := e.Err(); err != nil {
			t.Fatalf("encode: %v", err)
		}
		d := NewDecoder(e.Bytes())
		if got := d.Strings(); len(got) != 3 || d.Err() != nil {
			t.Fatalf("got %d strings, err %v; want 3 and nil", len(got), d.Err())
		}
	})

	t.Run("map of empty strings", func(t *testing.T) {
		e := NewEncoder(nil)
		e.StringMap(map[string]string{"": ""})
		d := NewDecoder(e.Bytes())
		if got := d.StringMap(); len(got) != 1 || d.Err() != nil {
			t.Fatalf("got %d entries, err %v; want 1 and nil", len(got), d.Err())
		}
	})

	t.Run("full multipart part list", func(t *testing.T) {
		// 10000 parts is S3's maximum and must still decode.
		parts := make([]int, 10000)
		for i := range parts {
			parts[i] = i + 1
		}
		encoded, err := EncodeCompleteMultipartRequest("b", "k", "u", parts)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		_, _, _, got, err := DecodeCompleteMultipartRequest(encoded)
		if err != nil {
			t.Fatalf("a 10000-part upload was rejected: %v", err)
		}
		if len(got) != len(parts) {
			t.Fatalf("got %d parts, want %d", len(got), len(parts))
		}
	})
}
