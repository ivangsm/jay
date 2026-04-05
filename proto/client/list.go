package client

import (
	"encoding/json"
	"fmt"

	"github.com/ivangsm/jay/proto"
)

// ListOptions configures a ListObjects request.
type ListOptions struct {
	Prefix     string `json:"prefix,omitempty"`
	Delimiter  string `json:"delimiter,omitempty"`
	StartAfter string `json:"start_after,omitempty"`
	MaxKeys    int    `json:"max_keys,omitempty"`
}

// ListEntry represents an object in a list response.
type ListEntry struct {
	Key            string `json:"key"`
	Size           int64  `json:"size"`
	ETag           string `json:"etag"`
	ChecksumSHA256 string `json:"checksum_sha256"`
	LastModified   string `json:"last_modified"`
	ContentType    string `json:"content_type"`
}

// ListResult contains the result of a ListObjects operation.
type ListResult struct {
	Objects        []ListEntry `json:"objects"`
	CommonPrefixes []string    `json:"common_prefixes,omitempty"`
	IsTruncated    bool        `json:"is_truncated"`
	NextStartAfter string      `json:"next_start_after,omitempty"`
}

// ListObjects lists objects in a bucket with optional filtering.
func (c *Client) ListObjects(bucket string, opts *ListOptions) (*ListResult, error) {
	reqMeta := struct {
		Bucket     string `json:"bucket"`
		Prefix     string `json:"prefix,omitempty"`
		Delimiter  string `json:"delimiter,omitempty"`
		StartAfter string `json:"start_after,omitempty"`
		MaxKeys    int    `json:"max_keys,omitempty"`
	}{
		Bucket: bucket,
	}
	if opts != nil {
		reqMeta.Prefix = opts.Prefix
		reqMeta.Delimiter = opts.Delimiter
		reqMeta.StartAfter = opts.StartAfter
		reqMeta.MaxKeys = opts.MaxKeys
	}

	meta, _ := json.Marshal(reqMeta)
	status, respMeta, err := c.doRequest(proto.OpListObjects, meta)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}
	var result ListResult
	if err := json.Unmarshal(respMeta, &result); err != nil {
		return nil, fmt.Errorf("unmarshal list objects response: %w", err)
	}
	return &result, nil
}
