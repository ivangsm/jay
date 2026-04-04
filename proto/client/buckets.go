package client

import (
	"encoding/json"
	"time"

	"github.com/ivangsm/jay/proto"
)

// BucketInfo contains bucket metadata.
type BucketInfo struct {
	BucketID   string    `json:"bucket_id"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	Visibility string    `json:"visibility"`
}

// BucketEntry is a bucket in a list response.
type BucketEntry struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateBucket creates a new bucket.
func (c *Client) CreateBucket(name string) (*BucketInfo, error) {
	meta, _ := json.Marshal(map[string]string{"bucket": name})
	status, respMeta, err := c.doRequest(proto.OpCreateBucket, meta)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}
	var info BucketInfo
	json.Unmarshal(respMeta, &info)
	return &info, nil
}

// DeleteBucket deletes a bucket. Fails if the bucket is not empty.
func (c *Client) DeleteBucket(name string) error {
	meta, _ := json.Marshal(map[string]string{"bucket": name})
	status, respMeta, err := c.doRequest(proto.OpDeleteBucket, meta)
	if err != nil {
		return err
	}
	return checkError(status, respMeta)
}

// HeadBucket checks if a bucket exists and returns its info.
func (c *Client) HeadBucket(name string) (*BucketInfo, error) {
	meta, _ := json.Marshal(map[string]string{"bucket": name})
	status, respMeta, err := c.doRequest(proto.OpHeadBucket, meta)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}
	var info BucketInfo
	json.Unmarshal(respMeta, &info)
	return &info, nil
}

// ListBuckets returns all buckets accessible to this token.
func (c *Client) ListBuckets() ([]BucketEntry, error) {
	status, respMeta, err := c.doRequest(proto.OpListBuckets, []byte("{}"))
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}
	var result struct {
		Buckets []BucketEntry `json:"buckets"`
	}
	json.Unmarshal(respMeta, &result)
	return result.Buckets, nil
}

// Ping sends a keepalive ping to the server.
func (c *Client) Ping() error {
	status, respMeta, err := c.doRequest(proto.OpPing, nil)
	if err != nil {
		return err
	}
	return checkError(status, respMeta)
}
