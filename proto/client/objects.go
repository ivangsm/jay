package client

import (
	"fmt"
	"io"

	"github.com/ivangsm/jay/proto"
)

// PutOptions are optional parameters for PutObject.
type PutOptions struct {
	ContentType string
	Metadata    map[string]string
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

// GetResult contains the object data and metadata from GetObject.
// The caller must call Close() when done reading Body.
type GetResult struct {
	ObjectInfo
	Body io.ReadCloser
}

// PutObject uploads an object. The data reader must provide exactly size bytes.
func (c *Client) PutObject(bucket, key string, data io.Reader, size int64, opts *PutOptions) (*PutResult, error) {
	var contentType string
	var metadata map[string]string
	if opts != nil {
		contentType = opts.ContentType
		metadata = opts.Metadata
	}

	meta := proto.EncodePutObjectRequest(bucket, key, contentType, metadata)
	status, respMeta, err := c.doRequestWithData(proto.OpPutObject, meta, data, size)
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
func (c *Client) GetObject(bucket, key string) (*GetResult, error) {
	meta := proto.EncodeBucketKey(bucket, key)
	status, respMeta, dataReader, _, err := c.doRequestWithDataResponse(proto.OpGetObject, meta)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		if dataReader != nil {
			dataReader.Close()
		}
		return nil, err
	}

	contentType, size, etag, checksum, lastModified, metadata, err := proto.DecodeObjectInfo(respMeta)
	if err != nil {
		if dataReader != nil {
			dataReader.Close()
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
	}
	if dataReader != nil {
		result.Body = dataReader
	} else {
		result.Body = io.NopCloser(&emptyReader{})
	}
	return result, nil
}

// HeadObject returns object metadata without downloading the content.
func (c *Client) HeadObject(bucket, key string) (*ObjectInfo, error) {
	meta := proto.EncodeBucketKey(bucket, key)
	status, respMeta, err := c.doRequest(proto.OpHeadObject, meta)
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

// DeleteObject deletes an object.
func (c *Client) DeleteObject(bucket, key string) error {
	meta := proto.EncodeBucketKey(bucket, key)
	status, respMeta, err := c.doRequest(proto.OpDeleteObject, meta)
	if err != nil {
		return err
	}
	return checkError(status, respMeta)
}

type emptyReader struct{}

func (e *emptyReader) Read(p []byte) (int, error) { return 0, io.EOF }
