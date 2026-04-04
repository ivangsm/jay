package client

import (
	"encoding/json"
	"io"

	"github.com/ivangsm/jay/proto"
)

// PutOptions are optional parameters for PutObject.
type PutOptions struct {
	ContentType string            `json:"content_type,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// PutResult contains the result of a PutObject operation.
type PutResult struct {
	ETag           string `json:"etag"`
	ChecksumSHA256 string `json:"checksum_sha256"`
}

// ObjectInfo contains object metadata.
type ObjectInfo struct {
	ContentType    string            `json:"content_type"`
	Size           int64             `json:"size"`
	ETag           string            `json:"etag"`
	ChecksumSHA256 string            `json:"checksum_sha256"`
	LastModified   string            `json:"last_modified"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// GetResult contains the object data and metadata from GetObject.
// The caller must call Close() when done reading Body.
type GetResult struct {
	ObjectInfo
	Body io.ReadCloser
}

// PutObject uploads an object. The data reader must provide exactly size bytes.
func (c *Client) PutObject(bucket, key string, data io.Reader, size int64, opts *PutOptions) (*PutResult, error) {
	reqMeta := struct {
		Bucket      string            `json:"bucket"`
		Key         string            `json:"key"`
		ContentType string            `json:"content_type,omitempty"`
		Metadata    map[string]string `json:"metadata,omitempty"`
	}{
		Bucket: bucket,
		Key:    key,
	}
	if opts != nil {
		reqMeta.ContentType = opts.ContentType
		reqMeta.Metadata = opts.Metadata
	}

	meta, _ := json.Marshal(reqMeta)
	status, respMeta, err := c.doRequestWithData(proto.OpPutObject, meta, data, size)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}
	var result PutResult
	json.Unmarshal(respMeta, &result)
	return &result, nil
}

// GetObject downloads an object. Returns object info and a streaming body.
// The caller must call result.Body.Close() when done reading.
func (c *Client) GetObject(bucket, key string) (*GetResult, error) {
	meta, _ := json.Marshal(map[string]string{"bucket": bucket, "key": key})
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

	var info ObjectInfo
	json.Unmarshal(respMeta, &info)

	result := &GetResult{ObjectInfo: info}
	if dataReader != nil {
		result.Body = dataReader
	} else {
		result.Body = io.NopCloser(&emptyReader{})
	}
	return result, nil
}

// HeadObject returns object metadata without downloading the content.
func (c *Client) HeadObject(bucket, key string) (*ObjectInfo, error) {
	meta, _ := json.Marshal(map[string]string{"bucket": bucket, "key": key})
	status, respMeta, err := c.doRequest(proto.OpHeadObject, meta)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}
	var info ObjectInfo
	json.Unmarshal(respMeta, &info)
	return &info, nil
}

// DeleteObject deletes an object.
func (c *Client) DeleteObject(bucket, key string) error {
	meta, _ := json.Marshal(map[string]string{"bucket": bucket, "key": key})
	status, respMeta, err := c.doRequest(proto.OpDeleteObject, meta)
	if err != nil {
		return err
	}
	return checkError(status, respMeta)
}

type emptyReader struct{}

func (e *emptyReader) Read(p []byte) (int, error) { return 0, io.EOF }
