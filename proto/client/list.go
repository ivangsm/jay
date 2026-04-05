package client

import (
	"fmt"

	"github.com/ivangsm/jay/proto"
)

// ListOptions configures a ListObjects request.
type ListOptions struct {
	Prefix     string
	Delimiter  string
	StartAfter string
	MaxKeys    int
}

// ListEntry represents an object in a list response.
type ListEntry struct {
	Key            string
	Size           int64
	ETag           string
	ChecksumSHA256 string
	LastModified   string
	ContentType    string
}

// ListResult contains the result of a ListObjects operation.
type ListResult struct {
	Objects        []ListEntry
	CommonPrefixes []string
	IsTruncated    bool
	NextStartAfter string
}

// ListObjects lists objects in a bucket with optional filtering.
func (c *Client) ListObjects(bucket string, opts *ListOptions) (*ListResult, error) {
	var prefix, delimiter, startAfter string
	var maxKeys int
	if opts != nil {
		prefix = opts.Prefix
		delimiter = opts.Delimiter
		startAfter = opts.StartAfter
		maxKeys = opts.MaxKeys
	}

	meta := proto.EncodeListObjectsRequest(bucket, prefix, delimiter, startAfter, maxKeys)
	status, respMeta, err := c.doRequest(proto.OpListObjects, meta)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}

	objects, commonPrefixes, isTruncated, nextStartAfter, err := proto.DecodeListObjectsResponse(respMeta)
	if err != nil {
		return nil, fmt.Errorf("decode list objects response: %w", err)
	}

	entries := make([]ListEntry, len(objects))
	for i, o := range objects {
		entries[i] = ListEntry{
			Key:            o.Key,
			Size:           o.Size,
			ETag:           o.ETag,
			ChecksumSHA256: o.ChecksumSHA256,
			LastModified:   o.LastModified,
			ContentType:    o.ContentType,
		}
	}

	return &ListResult{
		Objects:        entries,
		CommonPrefixes: commonPrefixes,
		IsTruncated:    isTruncated,
		NextStartAfter: nextStartAfter,
	}, nil
}
