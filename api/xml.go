package api

import (
	"encoding/xml"
	"net/http"
	"time"
)

const s3Namespace = "http://s3.amazonaws.com/doc/2006-03-01/"

// S3 error codes
const (
	S3ErrAccessDenied         = "AccessDenied"
	S3ErrBucketAlreadyExists  = "BucketAlreadyOwnedByYou"
	S3ErrBucketNotEmpty       = "BucketNotEmpty"
	S3ErrInternalError        = "InternalError"
	S3ErrInvalidArgument      = "InvalidArgument"
	S3ErrInvalidBucketName    = "InvalidBucketName"
	S3ErrNoSuchBucket         = "NoSuchBucket"
	S3ErrNoSuchKey            = "NoSuchKey"
	S3ErrMethodNotAllowed     = "MethodNotAllowed"
	S3ErrMissingContentLength = "MissingContentLength"
	S3ErrNotImplemented       = "NotImplemented"
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
	XMLName xml.Name     `xml:"ListAllMyBucketsResult"`
	XMLNS   string       `xml:"xmlns,attr"`
	Owner   S3Owner      `xml:"Owner"`
	Buckets S3BucketList `xml:"Buckets"`
}

// S3Owner is the owner element S3 clients expect in listing responses.
type S3Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

// S3BucketList wraps the bucket entries of a ListBuckets response.
type S3BucketList struct {
	Bucket []S3BucketEntry `xml:"Bucket"`
}

// S3BucketEntry is one bucket in a ListBuckets response.
type S3BucketEntry struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

// ListBucketResult is the XML response for ListObjectsV2.
type ListBucketResult struct {
	XMLName               xml.Name         `xml:"ListBucketResult"`
	XMLNS                 string           `xml:"xmlns,attr"`
	Name                  string           `xml:"Name"`
	Prefix                string           `xml:"Prefix"`
	Delimiter             string           `xml:"Delimiter,omitempty"`
	MaxKeys               int              `xml:"MaxKeys"`
	IsTruncated           bool             `xml:"IsTruncated"`
	Contents              []S3Content      `xml:"Contents"`
	CommonPrefixes        []S3CommonPrefix `xml:"CommonPrefixes,omitempty"`
	KeyCount              int              `xml:"KeyCount"`
	EncodingType          string           `xml:"EncodingType,omitempty"`
	StartAfter            string           `xml:"StartAfter,omitempty"`
	ContinuationToken     string           `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string           `xml:"NextContinuationToken,omitempty"`
}

// S3Content is one object in a ListObjects response.
type S3Content struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

// S3CommonPrefix is a synthesised directory in a delimited listing.
type S3CommonPrefix struct {
	Prefix string `xml:"Prefix"`
}

// InitiateMultipartUploadResult is the XML response for CreateMultipartUpload.
type InitiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	XMLNS    string   `xml:"xmlns,attr"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

// CompleteMultipartUploadInput is the XML request for CompleteMultipartUpload.
type CompleteMultipartUploadInput struct {
	XMLName xml.Name       `xml:"CompleteMultipartUpload"`
	Parts   []CompletePart `xml:"Part"`
}

// CompletePart is one part a client claims to have uploaded, in the
// CompleteMultipartUpload request.
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
	XMLName  xml.Name `xml:"ListPartsResult"`
	XMLNS    string   `xml:"xmlns,attr"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
	Parts    []S3Part `xml:"Part"`
}

// S3Part is one uploaded part in a ListParts response.
type S3Part struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

// CopyObjectResult is the XML response for CopyObject.
type CopyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	XMLNS        string   `xml:"xmlns,attr"`
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
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(errResp)
}

// writeXML writes an XML response with proper headers.
func writeXML(w http.ResponseWriter, r *http.Request, httpCode int, v any) {
	reqID := requestIDFromContext(r.Context())
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-amz-request-id", reqID)
	w.WriteHeader(httpCode)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(v)
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
	return `"` + etag + `"`
}

// ── DeleteObjects (POST /<bucket>?delete) ─────────────────────────────────

// DeleteObjectsInput is the <Delete> request document of DeleteObjects.
//
// The namespace is not matched: encoding/xml resolves element names by local
// name, so a document carrying the S3 namespace and one without it both decode.
type DeleteObjectsInput struct {
	XMLName xml.Name             `xml:"Delete"`
	Quiet   bool                 `xml:"Quiet"`
	Objects []DeleteObjectsEntry `xml:"Object"`
}

// DeleteObjectsEntry is one key of a <Delete> request. VersionID is parsed only
// so a version-scoped delete can be refused explicitly — jay has no versioning,
// and deleting the current object when a specific version was asked for would be
// reporting work that was not done.
type DeleteObjectsEntry struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId"`
}

// DeleteResult is the XML response of DeleteObjects. Every key of the request
// appears exactly once, in Deleted or in Errors: a key that failed is never
// omitted, because a client that sees neither reads the batch as a success.
type DeleteResult struct {
	XMLName xml.Name            `xml:"DeleteResult"`
	XMLNS   string              `xml:"xmlns,attr"`
	Deleted []DeletedObject     `xml:"Deleted"`
	Errors  []DeleteObjectError `xml:"Error"`
}

// DeletedObject reports one key DeleteObjects removed. Suppressed in Quiet mode.
type DeletedObject struct {
	Key string `xml:"Key"`
}

// DeleteObjectError reports one key DeleteObjects did NOT remove, with the same
// code it would have carried as a single-object failure. Reported in Quiet mode
// too — quiet suppresses the successes, never the failures.
type DeleteObjectError struct {
	Key     string `xml:"Key"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// ── GetBucketLocation (GET /<bucket>?location) ────────────────────────────

// LocationConstraint is the XML response of GetBucketLocation. jay has no
// regions, so the value is always empty — which is exactly how S3 spells
// us-east-1 and what SDKs expect from a single-region endpoint.
type LocationConstraint struct {
	XMLName xml.Name `xml:"LocationConstraint"`
	XMLNS   string   `xml:"xmlns,attr"`
	Value   string   `xml:",chardata"`
}

// ── ListMultipartUploads (GET /<bucket>?uploads) ──────────────────────────

// ListMultipartUploadsResult is the XML response of ListMultipartUploads. Field
// order follows the S3 documented response, not Go convention.
type ListMultipartUploadsResult struct {
	XMLName            xml.Name         `xml:"ListMultipartUploadsResult"`
	XMLNS              string           `xml:"xmlns,attr"`
	Bucket             string           `xml:"Bucket"`
	KeyMarker          string           `xml:"KeyMarker"`
	UploadIDMarker     string           `xml:"UploadIdMarker"`
	NextKeyMarker      string           `xml:"NextKeyMarker"`
	Prefix             string           `xml:"Prefix"`
	Delimiter          string           `xml:"Delimiter,omitempty"`
	NextUploadIDMarker string           `xml:"NextUploadIdMarker"`
	MaxUploads         int              `xml:"MaxUploads"`
	IsTruncated        bool             `xml:"IsTruncated"`
	Uploads            []S3Upload       `xml:"Upload"`
	CommonPrefixes     []S3CommonPrefix `xml:"CommonPrefixes,omitempty"`
	EncodingType       string           `xml:"EncodingType,omitempty"`
}

// S3Upload is one in-progress multipart upload in a ListMultipartUploads
// response.
type S3Upload struct {
	Key          string  `xml:"Key"`
	UploadID     string  `xml:"UploadId"`
	Initiator    S3Owner `xml:"Initiator"`
	Owner        S3Owner `xml:"Owner"`
	StorageClass string  `xml:"StorageClass"`
	Initiated    string  `xml:"Initiated"`
}
