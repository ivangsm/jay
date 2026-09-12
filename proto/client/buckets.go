package client

import (
	"context"
	"fmt"

	"github.com/ivangsm/jay/proto"
)

// BucketInfo contains bucket metadata.
type BucketInfo struct {
	BucketID   string
	Name       string
	CreatedAt  string
	Visibility string
}

// BucketEntry is a bucket in a list response.
type BucketEntry struct {
	Name      string
	CreatedAt string
}

// CreateBucket creates a new bucket.
func (c *Client) CreateBucket(ctx context.Context, name string) (*BucketInfo, error) {
	meta, err := proto.EncodeBucket(name)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	status, respMeta, err := c.doRequest(ctx, proto.OpCreateBucket, meta)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}
	id, n, createdAt, visibility, err := proto.DecodeBucketInfo(respMeta)
	if err != nil {
		return nil, fmt.Errorf("decode bucket info: %w", err)
	}
	return &BucketInfo{BucketID: id, Name: n, CreatedAt: createdAt, Visibility: visibility}, nil
}

// DeleteBucket deletes a bucket.
func (c *Client) DeleteBucket(ctx context.Context, name string) error {
	meta, err := proto.EncodeBucket(name)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	status, respMeta, err := c.doRequest(ctx, proto.OpDeleteBucket, meta)
	if err != nil {
		return err
	}
	return checkError(status, respMeta)
}

// HeadBucket returns metadata about a bucket.
func (c *Client) HeadBucket(ctx context.Context, name string) (*BucketInfo, error) {
	meta, err := proto.EncodeBucket(name)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	status, respMeta, err := c.doRequest(ctx, proto.OpHeadBucket, meta)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}
	id, n, createdAt, visibility, err := proto.DecodeBucketInfo(respMeta)
	if err != nil {
		return nil, fmt.Errorf("decode bucket info: %w", err)
	}
	return &BucketInfo{BucketID: id, Name: n, CreatedAt: createdAt, Visibility: visibility}, nil
}

// ListBuckets returns all buckets the authenticated user has access to.
func (c *Client) ListBuckets(ctx context.Context) ([]BucketEntry, error) {
	status, respMeta, err := c.doRequest(ctx, proto.OpListBuckets, nil)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}
	names, createdAts, err := proto.DecodeBucketList(respMeta)
	if err != nil {
		return nil, fmt.Errorf("decode bucket list: %w", err)
	}
	entries := make([]BucketEntry, len(names))
	for i := range names {
		entries[i] = BucketEntry{Name: names[i], CreatedAt: createdAts[i]}
	}
	return entries, nil
}

// Ping sends a ping to the server.
func (c *Client) Ping(ctx context.Context) error {
	status, respMeta, err := c.doRequest(ctx, proto.OpPing, nil)
	if err != nil {
		return err
	}
	return checkError(status, respMeta)
}
