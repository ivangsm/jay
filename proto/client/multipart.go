package client

import (
	"encoding/json"
	"io"

	"github.com/ivangsm/jay/proto"
)

// CompletePart identifies a part to include when completing a multipart upload.
type CompletePart struct {
	PartNumber int    `json:"part_number"`
	ETag       string `json:"etag"`
}

// PartInfo describes an uploaded part returned by ListParts.
type PartInfo struct {
	PartNumber     int    `json:"part_number"`
	Size           int64  `json:"size"`
	ETag           string `json:"etag"`
	ChecksumSHA256 string `json:"checksum_sha256"`
}

// CreateMultipartUpload initiates a new multipart upload and returns the upload ID.
func (c *Client) CreateMultipartUpload(bucket, key string, opts *PutOptions) (string, error) {
	reqMeta := struct {
		Bucket      string `json:"bucket"`
		Key         string `json:"key"`
		ContentType string `json:"content_type,omitempty"`
	}{
		Bucket: bucket,
		Key:    key,
	}
	if opts != nil {
		reqMeta.ContentType = opts.ContentType
	}

	meta, _ := json.Marshal(reqMeta)
	status, respMeta, err := c.doRequest(proto.OpCreateMultipartUpload, meta)
	if err != nil {
		return "", err
	}
	if err := checkError(status, respMeta); err != nil {
		return "", err
	}

	var resp struct {
		UploadID string `json:"upload_id"`
	}
	json.Unmarshal(respMeta, &resp)
	return resp.UploadID, nil
}

// UploadPart uploads a single part of a multipart upload.
// The data reader must provide exactly size bytes.
// Returns the ETag of the uploaded part.
func (c *Client) UploadPart(bucket, key, uploadID string, partNumber int, data io.Reader, size int64) (string, error) {
	reqMeta := struct {
		Bucket     string `json:"bucket"`
		Key        string `json:"key"`
		UploadID   string `json:"upload_id"`
		PartNumber int    `json:"part_number"`
	}{
		Bucket:     bucket,
		Key:        key,
		UploadID:   uploadID,
		PartNumber: partNumber,
	}

	meta, _ := json.Marshal(reqMeta)
	status, respMeta, err := c.doRequestWithData(proto.OpUploadPart, meta, data, size)
	if err != nil {
		return "", err
	}
	if err := checkError(status, respMeta); err != nil {
		return "", err
	}

	var resp struct {
		ETag string `json:"etag"`
	}
	json.Unmarshal(respMeta, &resp)
	return resp.ETag, nil
}

// CompleteMultipartUpload finalises a multipart upload, assembling all parts
// into the final object.
func (c *Client) CompleteMultipartUpload(bucket, key, uploadID string, parts []CompletePart) (*PutResult, error) {
	partNumbers := make([]int, len(parts))
	for i, p := range parts {
		partNumbers[i] = p.PartNumber
	}

	reqMeta := struct {
		Bucket      string `json:"bucket"`
		Key         string `json:"key"`
		UploadID    string `json:"upload_id"`
		PartNumbers []int  `json:"part_numbers"`
	}{
		Bucket:      bucket,
		Key:         key,
		UploadID:    uploadID,
		PartNumbers: partNumbers,
	}

	meta, _ := json.Marshal(reqMeta)
	status, respMeta, err := c.doRequest(proto.OpCompleteMultipart, meta)
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

// AbortMultipartUpload cancels a multipart upload and cleans up uploaded parts.
func (c *Client) AbortMultipartUpload(bucket, key, uploadID string) error {
	reqMeta := struct {
		Bucket   string `json:"bucket"`
		Key      string `json:"key"`
		UploadID string `json:"upload_id"`
	}{
		Bucket:   bucket,
		Key:      key,
		UploadID: uploadID,
	}

	meta, _ := json.Marshal(reqMeta)
	status, respMeta, err := c.doRequest(proto.OpAbortMultipart, meta)
	if err != nil {
		return err
	}
	return checkError(status, respMeta)
}

// ListParts returns the parts that have been uploaded for a multipart upload.
func (c *Client) ListParts(bucket, key, uploadID string) ([]PartInfo, error) {
	reqMeta := struct {
		Bucket   string `json:"bucket"`
		Key      string `json:"key"`
		UploadID string `json:"upload_id"`
	}{
		Bucket:   bucket,
		Key:      key,
		UploadID: uploadID,
	}

	meta, _ := json.Marshal(reqMeta)
	status, respMeta, err := c.doRequest(proto.OpListParts, meta)
	if err != nil {
		return nil, err
	}
	if err := checkError(status, respMeta); err != nil {
		return nil, err
	}

	var resp struct {
		Parts []PartInfo `json:"parts"`
	}
	json.Unmarshal(respMeta, &resp)
	return resp.Parts, nil
}
