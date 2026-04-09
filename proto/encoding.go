package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

// Binary encoding helpers for the native wire protocol.
// All strings are length-prefixed: [2B len][bytes].
// All int64 values are 8 bytes big-endian.
// Maps are: [2B count][for each: string(key), string(value)].

var errShortBuffer = errors.New("proto: short buffer")

// Encoder appends binary-encoded fields to a byte slice.
type Encoder struct {
	buf []byte
}

func NewEncoder(buf []byte) *Encoder {
	return &Encoder{buf: buf[:0]}
}

func (e *Encoder) Bytes() []byte { return e.buf }

func (e *Encoder) String(s string) {
	e.buf = appendString(e.buf, s)
}

func (e *Encoder) Int64(v int64) {
	e.buf = binary.BigEndian.AppendUint64(e.buf, uint64(v))
}

func (e *Encoder) Int32(v int32) {
	e.buf = binary.BigEndian.AppendUint32(e.buf, uint32(v))
}

func (e *Encoder) Bool(v bool) {
	if v {
		e.buf = append(e.buf, 1)
	} else {
		e.buf = append(e.buf, 0)
	}
}

func (e *Encoder) StringMap(m map[string]string) {
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(len(m)))
	for k, v := range m {
		e.buf = appendString(e.buf, k)
		e.buf = appendString(e.buf, v)
	}
}

func (e *Encoder) Strings(ss []string) {
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(len(ss)))
	for _, s := range ss {
		e.buf = appendString(e.buf, s)
	}
}

func (e *Encoder) Ints(ii []int) {
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(len(ii)))
	for _, v := range ii {
		e.buf = binary.BigEndian.AppendUint32(e.buf, uint32(v))
	}
}

func appendString(buf []byte, s string) []byte {
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(s)))
	return append(buf, s...)
}

// Decoder reads binary-encoded fields from a byte slice.
type Decoder struct {
	buf []byte
	off int
	err error
}

func NewDecoder(buf []byte) *Decoder {
	return &Decoder{buf: buf}
}

func (d *Decoder) Err() error { return d.err }

func (d *Decoder) String() string {
	if d.err != nil {
		return ""
	}
	if d.off+2 > len(d.buf) {
		d.err = errShortBuffer
		return ""
	}
	n := int(binary.BigEndian.Uint16(d.buf[d.off:]))
	d.off += 2
	if d.off+n > len(d.buf) {
		d.err = errShortBuffer
		return ""
	}
	s := string(d.buf[d.off : d.off+n])
	d.off += n
	return s
}

func (d *Decoder) Int64() int64 {
	if d.err != nil {
		return 0
	}
	if d.off+8 > len(d.buf) {
		d.err = errShortBuffer
		return 0
	}
	v := int64(binary.BigEndian.Uint64(d.buf[d.off:]))
	d.off += 8
	return v
}

func (d *Decoder) Int32() int32 {
	if d.err != nil {
		return 0
	}
	if d.off+4 > len(d.buf) {
		d.err = errShortBuffer
		return 0
	}
	v := int32(binary.BigEndian.Uint32(d.buf[d.off:]))
	d.off += 4
	return v
}

func (d *Decoder) Bool() bool {
	if d.err != nil {
		return false
	}
	if d.off+1 > len(d.buf) {
		d.err = errShortBuffer
		return false
	}
	v := d.buf[d.off] != 0
	d.off++
	return v
}

func (d *Decoder) StringMap() map[string]string {
	if d.err != nil {
		return nil
	}
	if d.off+2 > len(d.buf) {
		d.err = errShortBuffer
		return nil
	}
	n := int(binary.BigEndian.Uint16(d.buf[d.off:]))
	d.off += 2
	if n == 0 {
		return nil
	}
	m := make(map[string]string, n)
	for range n {
		k := d.String()
		v := d.String()
		if d.err != nil {
			return nil
		}
		m[k] = v
	}
	return m
}

func (d *Decoder) Strings() []string {
	if d.err != nil {
		return nil
	}
	if d.off+2 > len(d.buf) {
		d.err = errShortBuffer
		return nil
	}
	n := int(binary.BigEndian.Uint16(d.buf[d.off:]))
	d.off += 2
	if n == 0 {
		return nil
	}
	ss := make([]string, n)
	for i := range n {
		ss[i] = d.String()
		if d.err != nil {
			return nil
		}
	}
	return ss
}

func (d *Decoder) Ints() []int {
	if d.err != nil {
		return nil
	}
	if d.off+2 > len(d.buf) {
		d.err = errShortBuffer
		return nil
	}
	n := int(binary.BigEndian.Uint16(d.buf[d.off:]))
	d.off += 2
	if n == 0 {
		return nil
	}
	ii := make([]int, n)
	for i := range n {
		if d.off+4 > len(d.buf) {
			d.err = errShortBuffer
			return nil
		}
		ii[i] = int(binary.BigEndian.Uint32(d.buf[d.off:]))
		d.off += 4
	}
	return ii
}

// --- Encoding functions for common wire types ---

// EncodeBucketKey encodes a bucket+key pair (used by Get, Head, Delete).
func EncodeBucketKey(bucket, key string) []byte {
	buf := make([]byte, 0, 4+len(bucket)+len(key))
	buf = appendString(buf, bucket)
	buf = appendString(buf, key)
	return buf
}

// DecodeBucketKey decodes a bucket+key pair.
func DecodeBucketKey(data []byte) (bucket, key string, err error) {
	d := NewDecoder(data)
	bucket = d.String()
	key = d.String()
	return bucket, key, d.Err()
}

// EncodeBucket encodes a bucket name.
func EncodeBucket(bucket string) []byte {
	buf := make([]byte, 0, 2+len(bucket))
	return appendString(buf, bucket)
}

// DecodeBucket decodes a bucket name.
func DecodeBucket(data []byte) (string, error) {
	d := NewDecoder(data)
	s := d.String()
	return s, d.Err()
}

// EncodePutObjectRequest encodes a PutObject request.
func EncodePutObjectRequest(bucket, key, contentType string, metadata map[string]string) []byte {
	n := 2 + len(bucket) + 2 + len(key) + 2 + len(contentType) + 2
	for k, v := range metadata {
		n += 4 + len(k) + len(v)
	}
	e := NewEncoder(make([]byte, n))
	e.String(bucket)
	e.String(key)
	e.String(contentType)
	e.StringMap(metadata)
	return e.Bytes()
}

// DecodePutObjectRequest decodes a PutObject request.
func DecodePutObjectRequest(data []byte) (bucket, key, contentType string, metadata map[string]string, err error) {
	d := NewDecoder(data)
	bucket = d.String()
	key = d.String()
	contentType = d.String()
	metadata = d.StringMap()
	return bucket, key, contentType, metadata, d.Err()
}

// EncodePutResponse encodes a PutObject/UploadPart response.
func EncodePutResponse(etag, checksum string) []byte {
	buf := make([]byte, 0, 4+len(etag)+len(checksum))
	buf = appendString(buf, etag)
	buf = appendString(buf, checksum)
	return buf
}

// DecodePutResponse decodes a PutObject/UploadPart response.
func DecodePutResponse(data []byte) (etag, checksum string, err error) {
	d := NewDecoder(data)
	etag = d.String()
	checksum = d.String()
	return etag, checksum, d.Err()
}

// EncodeObjectInfo encodes object metadata for Get/Head responses.
func EncodeObjectInfo(contentType string, size int64, etag, checksum, lastModified string, metadata map[string]string) []byte {
	n := 2 + len(contentType) + 8 + 2 + len(etag) + 2 + len(checksum) + 2 + len(lastModified) + 2
	for k, v := range metadata {
		n += 4 + len(k) + len(v)
	}
	e := NewEncoder(make([]byte, n))
	e.String(contentType)
	e.Int64(size)
	e.String(etag)
	e.String(checksum)
	e.String(lastModified)
	e.StringMap(metadata)
	return e.Bytes()
}

// DecodeObjectInfo decodes object metadata.
func DecodeObjectInfo(data []byte) (contentType string, size int64, etag, checksum, lastModified string, metadata map[string]string, err error) {
	d := NewDecoder(data)
	contentType = d.String()
	size = d.Int64()
	etag = d.String()
	checksum = d.String()
	lastModified = d.String()
	metadata = d.StringMap()
	return contentType, size, etag, checksum, lastModified, metadata, d.Err()
}

// EncodeError encodes an error response.
func EncodeError(message, code string) []byte {
	buf := make([]byte, 0, 4+len(message)+len(code))
	buf = appendString(buf, message)
	buf = appendString(buf, code)
	return buf
}

// DecodeError decodes an error response.
func DecodeError(data []byte) (message, code string, err error) {
	d := NewDecoder(data)
	message = d.String()
	code = d.String()
	return message, code, d.Err()
}

// EncodeBucketInfo encodes bucket metadata.
func EncodeBucketInfo(bucketID, name, createdAt, visibility string) []byte {
	n := 2 + len(bucketID) + 2 + len(name) + 2 + len(createdAt) + 2 + len(visibility)
	buf := make([]byte, 0, n)
	buf = appendString(buf, bucketID)
	buf = appendString(buf, name)
	buf = appendString(buf, createdAt)
	buf = appendString(buf, visibility)
	return buf
}

// DecodeBucketInfo decodes bucket metadata.
func DecodeBucketInfo(data []byte) (bucketID, name, createdAt, visibility string, err error) {
	d := NewDecoder(data)
	bucketID = d.String()
	name = d.String()
	createdAt = d.String()
	visibility = d.String()
	return bucketID, name, createdAt, visibility, d.Err()
}

// EncodeListObjectsRequest encodes a ListObjects request.
func EncodeListObjectsRequest(bucket, prefix, delimiter, startAfter string, maxKeys int) []byte {
	n := 2 + len(bucket) + 2 + len(prefix) + 2 + len(delimiter) + 2 + len(startAfter) + 4
	e := NewEncoder(make([]byte, n))
	e.String(bucket)
	e.String(prefix)
	e.String(delimiter)
	e.String(startAfter)
	e.Int32(int32(maxKeys))
	return e.Bytes()
}

// DecodeListObjectsRequest decodes a ListObjects request.
func DecodeListObjectsRequest(data []byte) (bucket, prefix, delimiter, startAfter string, maxKeys int, err error) {
	d := NewDecoder(data)
	bucket = d.String()
	prefix = d.String()
	delimiter = d.String()
	startAfter = d.String()
	maxKeys = int(d.Int32())
	return bucket, prefix, delimiter, startAfter, maxKeys, d.Err()
}

// ListObjectEntry is used for encoding list object entries.
type ListObjectEntry struct {
	Key            string
	Size           int64
	ETag           string
	ChecksumSHA256 string
	LastModified   string
	ContentType    string
}

// EncodeListObjectsResponse encodes a ListObjects response.
func EncodeListObjectsResponse(objects []ListObjectEntry, commonPrefixes []string, isTruncated bool, nextStartAfter string) []byte {
	// Estimate size
	n := 2 // object count
	for _, o := range objects {
		n += 2 + len(o.Key) + 8 + 2 + len(o.ETag) + 2 + len(o.ChecksumSHA256) + 2 + len(o.LastModified) + 2 + len(o.ContentType)
	}
	n += 2 // commonPrefixes count
	for _, cp := range commonPrefixes {
		n += 2 + len(cp)
	}
	n += 1 + 2 + len(nextStartAfter) // bool + string

	e := NewEncoder(make([]byte, n))
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(len(objects)))
	for _, o := range objects {
		e.String(o.Key)
		e.Int64(o.Size)
		e.String(o.ETag)
		e.String(o.ChecksumSHA256)
		e.String(o.LastModified)
		e.String(o.ContentType)
	}
	e.Strings(commonPrefixes)
	e.Bool(isTruncated)
	e.String(nextStartAfter)
	return e.Bytes()
}

// DecodeListObjectsResponse decodes a ListObjects response.
func DecodeListObjectsResponse(data []byte) (objects []ListObjectEntry, commonPrefixes []string, isTruncated bool, nextStartAfter string, err error) {
	d := NewDecoder(data)
	if d.off+2 > len(d.buf) {
		return nil, nil, false, "", errShortBuffer
	}
	count := int(binary.BigEndian.Uint16(d.buf[d.off:]))
	d.off += 2
	objects = make([]ListObjectEntry, count)
	for i := range count {
		objects[i].Key = d.String()
		objects[i].Size = d.Int64()
		objects[i].ETag = d.String()
		objects[i].ChecksumSHA256 = d.String()
		objects[i].LastModified = d.String()
		objects[i].ContentType = d.String()
	}
	commonPrefixes = d.Strings()
	isTruncated = d.Bool()
	nextStartAfter = d.String()
	return objects, commonPrefixes, isTruncated, nextStartAfter, d.Err()
}

// EncodeCreateMultipartRequest encodes a CreateMultipartUpload request.
func EncodeCreateMultipartRequest(bucket, key, contentType string) []byte {
	buf := make([]byte, 0, 6+len(bucket)+len(key)+len(contentType))
	buf = appendString(buf, bucket)
	buf = appendString(buf, key)
	buf = appendString(buf, contentType)
	return buf
}

// DecodeCreateMultipartRequest decodes a CreateMultipartUpload request.
func DecodeCreateMultipartRequest(data []byte) (bucket, key, contentType string, err error) {
	d := NewDecoder(data)
	bucket = d.String()
	key = d.String()
	contentType = d.String()
	return bucket, key, contentType, d.Err()
}

// EncodeUploadPartRequest encodes an UploadPart request.
func EncodeUploadPartRequest(bucket, key, uploadID string, partNumber int) []byte {
	buf := make([]byte, 0, 10+len(bucket)+len(key)+len(uploadID))
	buf = appendString(buf, bucket)
	buf = appendString(buf, key)
	buf = appendString(buf, uploadID)
	buf = binary.BigEndian.AppendUint32(buf, uint32(partNumber))
	return buf
}

// DecodeUploadPartRequest decodes an UploadPart request.
func DecodeUploadPartRequest(data []byte) (bucket, key, uploadID string, partNumber int, err error) {
	d := NewDecoder(data)
	bucket = d.String()
	key = d.String()
	uploadID = d.String()
	partNumber = int(d.Int32())
	return bucket, key, uploadID, partNumber, d.Err()
}

// EncodeCompleteMultipartRequest encodes a CompleteMultipartUpload request.
func EncodeCompleteMultipartRequest(bucket, key, uploadID string, partNumbers []int) []byte {
	n := 6 + len(bucket) + len(key) + 2 + len(uploadID) + 2 + 4*len(partNumbers)
	e := NewEncoder(make([]byte, n))
	e.String(bucket)
	e.String(key)
	e.String(uploadID)
	e.Ints(partNumbers)
	return e.Bytes()
}

// DecodeCompleteMultipartRequest decodes a CompleteMultipartUpload request.
func DecodeCompleteMultipartRequest(data []byte) (bucket, key, uploadID string, partNumbers []int, err error) {
	d := NewDecoder(data)
	bucket = d.String()
	key = d.String()
	uploadID = d.String()
	partNumbers = d.Ints()
	return bucket, key, uploadID, partNumbers, d.Err()
}

// EncodeBucketKeyUpload encodes a bucket+key+uploadID triple (for abort/list parts).
func EncodeBucketKeyUpload(bucket, key, uploadID string) []byte {
	buf := make([]byte, 0, 6+len(bucket)+len(key)+len(uploadID))
	buf = appendString(buf, bucket)
	buf = appendString(buf, key)
	buf = appendString(buf, uploadID)
	return buf
}

// DecodeBucketKeyUpload decodes a bucket+key+uploadID triple.
func DecodeBucketKeyUpload(data []byte) (bucket, key, uploadID string, err error) {
	d := NewDecoder(data)
	bucket = d.String()
	key = d.String()
	uploadID = d.String()
	return bucket, key, uploadID, d.Err()
}

// EncodeCompleteMultipartResponse encodes a CompleteMultipartUpload response.
func EncodeCompleteMultipartResponse(etag, checksum string, size int64) []byte {
	buf := make([]byte, 0, 4+len(etag)+len(checksum)+8)
	buf = appendString(buf, etag)
	buf = appendString(buf, checksum)
	buf = binary.BigEndian.AppendUint64(buf, uint64(size))
	return buf
}

// DecodeCompleteMultipartResponse decodes a CompleteMultipartUpload response.
func DecodeCompleteMultipartResponse(data []byte) (etag, checksum string, size int64, err error) {
	d := NewDecoder(data)
	etag = d.String()
	checksum = d.String()
	size = d.Int64()
	return etag, checksum, size, d.Err()
}

// PartInfoEntry for list parts response.
type PartInfoEntry struct {
	PartNumber     int
	Size           int64
	ETag           string
	ChecksumSHA256 string
}

// EncodeListPartsResponse encodes a ListParts response.
func EncodeListPartsResponse(parts []PartInfoEntry) []byte {
	n := 2
	for _, p := range parts {
		n += 4 + 8 + 2 + len(p.ETag) + 2 + len(p.ChecksumSHA256)
	}
	e := NewEncoder(make([]byte, n))
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(len(parts)))
	for _, p := range parts {
		e.Int32(int32(p.PartNumber))
		e.Int64(p.Size)
		e.String(p.ETag)
		e.String(p.ChecksumSHA256)
	}
	return e.Bytes()
}

// DecodeListPartsResponse decodes a ListParts response.
func DecodeListPartsResponse(data []byte) ([]PartInfoEntry, error) {
	d := NewDecoder(data)
	if d.off+2 > len(d.buf) {
		return nil, errShortBuffer
	}
	count := int(binary.BigEndian.Uint16(d.buf[d.off:]))
	d.off += 2
	parts := make([]PartInfoEntry, count)
	for i := range count {
		parts[i].PartNumber = int(d.Int32())
		parts[i].Size = d.Int64()
		parts[i].ETag = d.String()
		parts[i].ChecksumSHA256 = d.String()
	}
	return parts, d.Err()
}

// EncodeBucketList encodes a list of buckets.
func EncodeBucketList(names []string, createdAts []string) []byte {
	n := 2
	for i := range names {
		n += 2 + len(names[i]) + 2 + len(createdAts[i])
	}
	e := NewEncoder(make([]byte, n))
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(len(names)))
	for i := range names {
		e.String(names[i])
		e.String(createdAts[i])
	}
	return e.Bytes()
}

// DecodeBucketList decodes a list of buckets.
func DecodeBucketList(data []byte) (names []string, createdAts []string, err error) {
	d := NewDecoder(data)
	if d.off+2 > len(d.buf) {
		return nil, nil, errShortBuffer
	}
	count := int(binary.BigEndian.Uint16(d.buf[d.off:]))
	d.off += 2
	names = make([]string, count)
	createdAts = make([]string, count)
	for i := range count {
		names[i] = d.String()
		createdAts[i] = d.String()
	}
	return names, createdAts, d.Err()
}

// frameBufPool pools buffers for WriteFrameCombined to avoid per-response allocations.
// Most meta-only responses (the majority of traffic) fit within 4KB.
var frameBufPool = sync.Pool{
	New: func() any { return make([]byte, 0, 4096) },
}

// WriteFrameCombined writes header + meta in a single write when possible.
// This is an optimization over WriteFrame for responses without data.
func WriteFrameCombined(w io.Writer, opOrStatus byte, streamID uint32, meta []byte) error {
	metaLen := len(meta)
	if metaLen > math.MaxUint32 {
		return fmt.Errorf("meta too large")
	}
	total := HeaderSize + metaLen

	var buf []byte
	if total <= 4096 {
		buf = frameBufPool.Get().([]byte)[:total]
		defer frameBufPool.Put(buf[:0])
	} else {
		buf = make([]byte, total)
	}

	buf[0] = opOrStatus
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	binary.BigEndian.PutUint32(buf[5:9], uint32(metaLen))
	binary.BigEndian.PutUint64(buf[9:17], 0) // dataLen = 0
	copy(buf[HeaderSize:], meta)
	_, err := w.Write(buf)
	return err
}
