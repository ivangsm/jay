package client

import (
	"context"
	"fmt"
	"io"

	"github.com/ivangsm/jay/proto"
)

// PutOptions are optional parameters for PutObject.
type PutOptions struct {
	ContentType string
	Metadata    map[string]string

	// SkipETag asks jay to skip computing the MD5 ETag for this upload.
	// ChecksumSHA256 on the returned PutResult is unaffected — jay always
	// computes that one. Only set this when nothing reads PutResult.ETag:
	// jay's S3 HTTP API always returns a real ETag regardless of this field,
	// since that surface's clients expect one; this only saves the native
	// protocol's own MD5 pass, which profiling showed costs more CPU per
	// upload than the SHA-256 checksum jay computes either way.
	SkipETag bool
}

// PutResult contains the result of a PutObject operation.
type PutResult struct {
	ETag           string
	ChecksumSHA256 string
}

// ObjectInfo contains object metadata.
type ObjectInfo struct {
	ContentType    string
	Size           int64
	ETag           string
	ChecksumSHA256 string
	LastModified   string
	Metadata       map[string]string
}

// GetResult contains the object data and metadata from GetObject and
// GetObjectRange. The caller must call Body.Close() when done reading.
type GetResult struct {
	ObjectInfo

	// ContentLength is how many bytes Body yields. For GetObject it equals
	// Size; for GetObjectRange it is the served slice, which can be shorter
	// than the length asked for when the range ran past the end.
	ContentLength int64

	Body io.ReadCloser
}

// CopyResult describes the object a CopyObject wrote.
type CopyResult struct {
	ETag           string
	ChecksumSHA256 string
	Size           int64
	LastModified   string
}

// PutObject uploads an object. The data reader must provide exactly size bytes.
//
// A cancelled ctx aborts the upload and costs the connection — the reader
// cannot be rewound, so nothing is retried — and nothing is stored: the server
// only commits an object whose declared size arrived in full.
func (c *Client) PutObject(ctx context.Context, bucket, key string, data io.Reader, size int64, opts *PutOptions) (*PutResult, error) {
	var contentType string
	var metadata map[string]string
	var skipETag bool
	if opts != nil {
		contentType = opts.ContentType
		metadata = opts.Metadata
		skipETag = opts.SkipETag
	}

	meta, err := proto.EncodePutObjectRequest(bucket, key, contentType, metadata, skipETag)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	status, respMeta, err := c.doRequestWithData(ctx, proto.OpPutObject, meta, data, size)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}
	etag, checksum, err := proto.DecodePutResponse(respMeta)
	if err != nil {
		return nil, fmt.Errorf("decode put response: %w", err)
	}
	return &PutResult{ETag: etag, ChecksumSHA256: checksum}, nil
}

// GetObject downloads an object. Returns object info and a streaming body.
// The caller must call result.Body.Close() when done reading.
//
// ctx stays in force while the body is read: cancelling it fails the next
// Read with the context's error and drops the connection on Close.
func (c *Client) GetObject(ctx context.Context, bucket, key string) (*GetResult, error) {
	meta, err := proto.EncodeBucketKey(bucket, key)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	return c.fetchObject(ctx, proto.OpGetObject, meta)
}

// GetObjectRange downloads length bytes of an object starting at offset.
// length <= 0 means "to the end". The returned Size is the whole object's;
// ContentLength is what Body yields, clamped to the end of the object.
//
// A range that does not intersect the object — offset at or past the end, or
// any range on an empty object — is refused with code InvalidRange, the native
// counterpart of HTTP 416. A server that predates this operation answers
// UnknownOp (see IsUnknownOp).
func (c *Client) GetObjectRange(ctx context.Context, bucket, key string, offset, length int64) (*GetResult, error) {
	meta, err := proto.EncodeGetObjectRangeRequest(bucket, key, offset, length)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	return c.fetchObject(ctx, proto.OpGetObjectRange, meta)
}

func (c *Client) fetchObject(ctx context.Context, op byte, meta []byte) (*GetResult, error) {
	status, respMeta, dataReader, dataLen, err := c.doRequestWithDataResponse(ctx, op, meta)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		if dataReader != nil {
			_ = dataReader.Close()
		}
		return nil, err
	}

	contentType, size, etag, checksum, lastModified, metadata, err := proto.DecodeObjectInfo(respMeta)
	if err != nil {
		if dataReader != nil {
			_ = dataReader.Close()
		}
		return nil, fmt.Errorf("decode get response: %w", err)
	}

	result := &GetResult{
		ObjectInfo: ObjectInfo{
			ContentType:    contentType,
			Size:           size,
			ETag:           etag,
			ChecksumSHA256: checksum,
			LastModified:   lastModified,
			Metadata:       metadata,
		},
		ContentLength: dataLen,
	}
	if dataReader != nil {
		result.Body = dataReader
	} else {
		result.Body = io.NopCloser(&emptyReader{})
	}
	return result, nil
}

// HeadObject returns object metadata without downloading the content.
func (c *Client) HeadObject(ctx context.Context, bucket, key string) (*ObjectInfo, error) {
	meta, err := proto.EncodeBucketKey(bucket, key)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	status, respMeta, err := c.doRequest(ctx, proto.OpHeadObject, meta)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}
	contentType, size, etag, checksum, lastModified, metadata, err := proto.DecodeObjectInfo(respMeta)
	if err != nil {
		return nil, fmt.Errorf("decode head response: %w", err)
	}
	return &ObjectInfo{
		ContentType:    contentType,
		Size:           size,
		ETag:           etag,
		ChecksumSHA256: checksum,
		LastModified:   lastModified,
		Metadata:       metadata,
	}, nil
}

// DeleteObject deletes an object. Deleting one that does not exist is not an
// error (S3 semantics).
func (c *Client) DeleteObject(ctx context.Context, bucket, key string) error {
	meta, err := proto.EncodeBucketKey(bucket, key)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	status, respMeta, err := c.doRequest(ctx, proto.OpDeleteObject, meta)
	if err != nil {
		return err
	}
	return checkError(status, respMeta)
}

// CopyObject copies an object on the server, without its bytes crossing the
// wire. Content type and user metadata carry over from the source. The token
// needs object:get on the source and object:put on the destination, and a
// bucket policy that denies reading the source denies the copy too.
//
// An error about a missing bucket or object has the side ("source" or
// "destination") at the front of its message; the code is the usual
// NoSuchBucket / NoSuchKey. A server that predates this operation answers
// UnknownOp (see IsUnknownOp).
func (c *Client) CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) (*CopyResult, error) {
	meta, err := proto.EncodeCopyObjectRequest(srcBucket, srcKey, dstBucket, dstKey)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	status, respMeta, err := c.doRequest(ctx, proto.OpCopyObject, meta)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}
	etag, checksum, size, lastModified, err := proto.DecodeCopyObjectResponse(respMeta)
	if err != nil {
		return nil, fmt.Errorf("decode copy response: %w", err)
	}
	return &CopyResult{ETag: etag, ChecksumSHA256: checksum, Size: size, LastModified: lastModified}, nil
}

type emptyReader struct{}

func (e *emptyReader) Read(p []byte) (int, error) { return 0, io.EOF }
