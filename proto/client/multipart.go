package client

import (
	"fmt"
	"io"

	"github.com/ivangsm/jay/proto"
)

// CompletePart identifies a part to include when completing a multipart upload.
type CompletePart struct {
	PartNumber int
	ETag       string
}

// PartInfo describes an uploaded part returned by ListParts.
type PartInfo struct {
	PartNumber     int
	Size           int64
	ETag           string
	ChecksumSHA256 string
}

// CreateMultipartUpload initiates a new multipart upload and returns the upload ID.
func (c *Client) CreateMultipartUpload(bucket, key string, opts *PutOptions) (string, error) {
	var contentType string
	if opts != nil {
		contentType = opts.ContentType
	}

	meta := proto.EncodeCreateMultipartRequest(bucket, key, contentType)
	status, respMeta, err := c.doRequest(proto.OpCreateMultipartUpload, meta)
	if err != nil {
		return "", err
	}
	if err := checkError(status, respMeta); err != nil {
		return "", err
	}

	uploadID, err := proto.DecodeBucket(respMeta) // uploadID encoded as a string
	if err != nil {
		return "", fmt.Errorf("decode create multipart response: %w", err)
	}
	return uploadID, nil
}

// UploadPart uploads a single part of a multipart upload.
func (c *Client) UploadPart(bucket, key, uploadID string, partNumber int, data io.Reader, size int64) (string, error) {
	meta := proto.EncodeUploadPartRequest(bucket, key, uploadID, partNumber)
	status, respMeta, err := c.doRequestWithData(proto.OpUploadPart, meta, data, size)
	if err != nil {
		return "", err
	}
	if err := checkError(status, respMeta); err != nil {
		return "", err
	}

	etag, _, err := proto.DecodePutResponse(respMeta)
	if err != nil {
		return "", fmt.Errorf("decode upload part response: %w", err)
	}
	return etag, nil
}

// CompleteMultipartUpload finalises a multipart upload.
func (c *Client) CompleteMultipartUpload(bucket, key, uploadID string, parts []CompletePart) (*PutResult, error) {
	partNumbers := make([]int, len(parts))
	for i, p := range parts {
		partNumbers[i] = p.PartNumber
	}

	meta := proto.EncodeCompleteMultipartRequest(bucket, key, uploadID, partNumbers)
	status, respMeta, err := c.doRequest(proto.OpCompleteMultipart, meta)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}

	etag, checksum, _, err := proto.DecodeCompleteMultipartResponse(respMeta)
	if err != nil {
		return nil, fmt.Errorf("decode complete multipart response: %w", err)
	}
	return &PutResult{ETag: etag, ChecksumSHA256: checksum}, nil
}

// AbortMultipartUpload cancels a multipart upload.
func (c *Client) AbortMultipartUpload(bucket, key, uploadID string) error {
	meta := proto.EncodeBucketKeyUpload(bucket, key, uploadID)
	status, respMeta, err := c.doRequest(proto.OpAbortMultipart, meta)
	if err != nil {
		return err
	}
	return checkError(status, respMeta)
}

// ListParts returns the parts that have been uploaded for a multipart upload.
func (c *Client) ListParts(bucket, key, uploadID string) ([]PartInfo, error) {
	meta := proto.EncodeBucketKeyUpload(bucket, key, uploadID)
	status, respMeta, err := c.doRequest(proto.OpListParts, meta)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}

	entries, err := proto.DecodeListPartsResponse(respMeta)
	if err != nil {
		return nil, fmt.Errorf("decode list parts response: %w", err)
	}
	parts := make([]PartInfo, len(entries))
	for i, e := range entries {
		parts[i] = PartInfo{
			PartNumber:     e.PartNumber,
			Size:           e.Size,
			ETag:           e.ETag,
			ChecksumSHA256: e.ChecksumSHA256,
		}
	}
	return parts, nil
}
