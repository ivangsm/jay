package api

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"time"
)

const s3Namespace = "http://s3.amazonaws.com/doc/2006-03-01/"

// S3 error codes
const (
	S3ErrAccessDenied           = "AccessDenied"
	S3ErrBucketAlreadyExists    = "BucketAlreadyOwnedByYou"
	S3ErrBucketNotEmpty         = "BucketNotEmpty"
	S3ErrInternalError          = "InternalError"
	S3ErrInvalidArgument        = "InvalidArgument"
	S3ErrInvalidBucketName      = "InvalidBucketName"
	S3ErrNoSuchBucket           = "NoSuchBucket"
	S3ErrNoSuchKey              = "NoSuchKey"
	S3ErrMethodNotAllowed       = "MethodNotAllowed"
	S3ErrMissingContentLength   = "MissingContentLength"
)

// S3Error represents an S3 XML error response.
type S3Error struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource"`
	RequestID string   `xml:"RequestId"`
}

// ListAllMyBucketsResult is the XML response for listing buckets.
type ListAllMyBucketsResult struct {
	XMLName xml.Name       `xml:"ListAllMyBucketsResult"`
	XMLNS   string         `xml:"xmlns,attr"`
	Owner   S3Owner        `xml:"Owner"`
	Buckets S3BucketList   `xml:"Buckets"`
}

type S3Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type S3BucketList struct {
	Bucket []S3BucketEntry `xml:"Bucket"`
}

type S3BucketEntry struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

// ListBucketResult is the XML response for ListObjectsV2.
type ListBucketResult struct {
	XMLName        xml.Name       `xml:"ListBucketResult"`
	XMLNS          string         `xml:"xmlns,attr"`
	Name           string         `xml:"Name"`
	Prefix         string         `xml:"Prefix"`
	Delimiter      string         `xml:"Delimiter,omitempty"`
	MaxKeys        int            `xml:"MaxKeys"`
	IsTruncated    bool           `xml:"IsTruncated"`
	Contents       []S3Content    `xml:"Contents"`
	CommonPrefixes []S3CommonPrefix `xml:"CommonPrefixes,omitempty"`
	KeyCount       int            `xml:"KeyCount"`
	StartAfter     string         `xml:"StartAfter,omitempty"`
	ContinuationToken string     `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string `xml:"NextContinuationToken,omitempty"`
}

type S3Content struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type S3CommonPrefix struct {
	Prefix string `xml:"Prefix"`
}

// InitiateMultipartUploadResult is the XML response for CreateMultipartUpload.
type InitiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	XMLNS    string   `xml:"xmlns,attr"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadId string   `xml:"UploadId"`
}

// CompleteMultipartUploadInput is the XML request for CompleteMultipartUpload.
type CompleteMultipartUploadInput struct {
	XMLName xml.Name           `xml:"CompleteMultipartUpload"`
	Parts   []CompletePart     `xml:"Part"`
}

type CompletePart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

// CompleteMultipartUploadResult is the XML response for CompleteMultipartUpload.
type CompleteMultipartUploadResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	XMLNS    string   `xml:"xmlns,attr"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// ListPartsResult is the XML response for ListParts.
type ListPartsResult struct {
	XMLName  xml.Name    `xml:"ListPartsResult"`
	XMLNS    string      `xml:"xmlns,attr"`
	Bucket   string      `xml:"Bucket"`
	Key      string      `xml:"Key"`
	UploadId string      `xml:"UploadId"`
	Parts    []S3Part    `xml:"Part"`
}

type S3Part struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

// CopyObjectResult is the XML response for CopyObject.
type CopyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	LastModified string   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

// writeS3Error writes an S3-compatible XML error response.
func writeS3Error(w http.ResponseWriter, r *http.Request, httpCode int, s3Code, message, resource string) {
	reqID := requestIDFromContext(r.Context())
	errResp := S3Error{
		Code:      s3Code,
		Message:   message,
		Resource:  resource,
		RequestID: reqID,
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-amz-request-id", reqID)
	w.WriteHeader(httpCode)
	w.Write([]byte(xml.Header))
	xml.NewEncoder(w).Encode(errResp)
}

// writeXML writes an XML response with proper headers.
func writeXML(w http.ResponseWriter, r *http.Request, httpCode int, v interface{}) {
	reqID := requestIDFromContext(r.Context())
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-amz-request-id", reqID)
	w.WriteHeader(httpCode)
	w.Write([]byte(xml.Header))
	xml.NewEncoder(w).Encode(v)
}

// formatS3Time formats a time as S3 expects.
func formatS3Time(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// formatETag wraps an ETag in quotes as S3 does.
func formatETag(etag string) string {
	if etag == "" {
		return ""
	}
	if etag[0] == '"' {
		return etag
	}
	return fmt.Sprintf(`"%s"`, etag)
}
