package meta

import (
	"encoding/json"
	"time"
)

type Account struct {
	AccountID string    `json:"account_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"` // "active", "suspended"
}

type Bucket struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	OwnerAccountID string          `json:"owner_account_id"`
	CreatedAt      time.Time       `json:"created_at"`
	Visibility     string          `json:"visibility"` // "private", "public-read"
	PolicyJSON     json.RawMessage `json:"policy_json,omitempty"`
	Status         string          `json:"status"` // "active", "deleting"
}

type Object struct {
	BucketID        string            `json:"bucket_id"`
	Key             string            `json:"key"`
	ObjectID        string            `json:"object_id"`
	State           string            `json:"state"` // "active", "deleted", "quarantined"
	SizeBytes       int64             `json:"size_bytes"`
	ContentType     string            `json:"content_type"`
	ETag            string            `json:"etag"`
	ChecksumSHA256  string            `json:"checksum_sha256"`
	LocationRef     string            `json:"location_ref"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	MetadataHeaders map[string]string `json:"metadata_headers,omitempty"`
}

type Token struct {
	TokenID        string     `json:"token_id"`
	AccountID      string     `json:"account_id"`
	Name           string     `json:"name"`
	SecretHash     string     `json:"secret_hash"`
	SecretKey      string     `json:"secret_key,omitempty"` // plaintext secret for SigV4 HMAC computation
	AllowedActions []string   `json:"allowed_actions"`
	BucketScope    []string   `json:"bucket_scope,omitempty"`
	PrefixScope    []string   `json:"prefix_scope,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Status         string     `json:"status"` // "active", "revoked"
}

// MultipartUpload tracks an in-progress multipart upload.
type MultipartUpload struct {
	UploadID    string          `json:"upload_id"`
	BucketID    string          `json:"bucket_id"`
	ObjectKey   string          `json:"object_key"`
	ContentType string          `json:"content_type,omitempty"`
	InitiatedBy string          `json:"initiated_by"`
	CreatedAt   time.Time       `json:"created_at"`
	State       string          `json:"state"` // "initiated", "completed", "aborted"
	Parts       []MultipartPart `json:"parts,omitempty"`
}

// MultipartPart represents a single part in a multipart upload.
type MultipartPart struct {
	PartNumber     int       `json:"part_number"`
	Size           int64     `json:"size"`
	ETag           string    `json:"etag"`
	ChecksumSHA256 string    `json:"checksum_sha256"`
	LocationRef    string    `json:"location_ref"`
	CreatedAt      time.Time `json:"created_at"`
}

// Actions
const (
	ActionBucketList     = "bucket:list"
	ActionBucketReadMeta = "bucket:read-meta"
	ActionBucketWriteMeta = "bucket:write-meta"
	ActionObjectGet      = "object:get"
	ActionObjectPut      = "object:put"
	ActionObjectDelete   = "object:delete"
	ActionObjectList     = "object:list"
	ActionMultipartCreate = "multipart:create"
	ActionMultipartUpload = "multipart:upload-part"
	ActionMultipartComplete = "multipart:complete"
	ActionMultipartAbort = "multipart:abort"
)

// AllActions is the full set of actions for admin/full-access tokens.
var AllActions = []string{
	ActionBucketList, ActionBucketReadMeta, ActionBucketWriteMeta,
	ActionObjectGet, ActionObjectPut, ActionObjectDelete, ActionObjectList,
	ActionMultipartCreate, ActionMultipartUpload, ActionMultipartComplete, ActionMultipartAbort,
}
