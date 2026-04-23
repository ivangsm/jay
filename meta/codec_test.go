package meta

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func sampleObject() Object {
	createdAt := time.Date(2026, 4, 22, 12, 34, 56, 0, time.UTC)
	updatedAt := createdAt.Add(30 * time.Second)
	return Object{
		BucketID:       "bkt_01HX1ABCDE",
		Key:            "uploads/avatars/ivan.webp",
		ObjectID:       "obj_01HX1FGHIJ",
		State:          "active",
		SizeBytes:      4096,
		ContentType:    "image/webp",
		ETag:           `"d41d8cd98f00b204e9800998ecf8427e"`,
		ChecksumSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		LocationRef:    "ab/cd/obj_01HX1FGHIJ",
		CreatedAt:      createdAt,
		UpdatedAt:      updatedAt,
		MetadataHeaders: map[string]string{
			"x-amz-meta-uploader": "falco",
			"x-amz-meta-variant":  "original",
		},
	}
}

func TestCodecRoundTrip(t *testing.T) {
	orig := sampleObject()

	data, err := encodeObject(&orig)
	if err != nil {
		t.Fatalf("encodeObject: %v", err)
	}
	if len(data) < 2 {
		t.Fatalf("encoded payload too short: len=%d", len(data))
	}
	if data[0] != formatGob {
		t.Fatalf("expected leading format byte 0x%02x, got 0x%02x", formatGob, data[0])
	}

	var decoded Object
	if err := decodeObject(data, &decoded); err != nil {
		t.Fatalf("decodeObject: %v", err)
	}

	if !reflect.DeepEqual(orig, decoded) {
		t.Fatalf("round-trip mismatch:\n orig   = %#v\n decoded= %#v", orig, decoded)
	}
}

func TestCodecDecodeLegacyJSON(t *testing.T) {
	orig := sampleObject()

	raw, err := json.Marshal(&orig)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if raw[0] != '{' {
		t.Fatalf("expected JSON to start with '{', got 0x%02x", raw[0])
	}

	var decoded Object
	if err := decodeObject(raw, &decoded); err != nil {
		t.Fatalf("decodeObject on legacy JSON: %v", err)
	}

	if !reflect.DeepEqual(orig, decoded) {
		t.Fatalf("legacy JSON decode mismatch:\n orig   = %#v\n decoded= %#v", orig, decoded)
	}
}

func TestCodecDecodeEmpty(t *testing.T) {
	var o Object
	if err := decodeObject(nil, &o); err == nil {
		t.Fatalf("decodeObject(nil) expected error, got nil")
	}
	if err := decodeObject([]byte{}, &o); err == nil {
		t.Fatalf("decodeObject([]byte{}) expected error, got nil")
	}
}

func TestCodecDecodeUnknownFormatByte(t *testing.T) {
	var o Object
	err := decodeObject([]byte{0x02, 0x00, 0x00}, &o)
	if err == nil {
		t.Fatalf("decodeObject with leading 0x02 expected error, got nil")
	}
}

