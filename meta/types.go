package meta

import (
	"encoding/json/jsontext"
	"time"
)

// Account owns buckets and tokens. It is jay's tenancy boundary: a token can
// only ever reach the buckets of the account that issued it.
type Account struct {
	AccountID string    `json:"account_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"` // "active", "suspended"
}

// Bucket is a named container of objects, owned by exactly one account.
type Bucket struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	OwnerAccountID string    `json:"owner_account_id"`
	CreatedAt      time.Time `json:"created_at"`
	Visibility     string    `json:"visibility"` // "private", "public-read"
	// omitzero, not omitempty: on a raw-JSON field the two diverge. v1 with
	// omitempty omits the empty slice but writes the literal `null`; v2 with
	// omitempty omits the `null` — which would change the bytes on disk. With
	// omitzero the two agree across all four possible states
	// (nil → omitido, `null` → escrito, valor → escrito, vacío-no-nil → error).
	// Lo cubre TestJSONWireCompatV1V2.
	PolicyJSON jsontext.Value `json:"policy_json,omitzero"`
	Status     string         `json:"status"` // "active", "deleting"
}

// Object is one stored blob: where its bytes live, what they hash to, and the
// metadata that came with them.
//
// The checksum is what makes the scrubber possible — it is compared against the
// bytes actually on disk, so silent corruption is detectable rather than served.
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

// Token is a credential issued to an account. SecretKey is never stored in the
// clear: it is encrypted at rest with the signing secret, so a leaked bbolt file
// does not hand over working credentials.
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
	ActionBucketList        = "bucket:list"
	ActionBucketReadMeta    = "bucket:read-meta"
	ActionBucketWriteMeta   = "bucket:write-meta"
	ActionObjectGet         = "object:get"
	ActionObjectPut         = "object:put"
	ActionObjectDelete      = "object:delete"
	ActionObjectList        = "object:list"
	ActionMultipartCreate   = "multipart:create"
	ActionMultipartUpload   = "multipart:upload-part"
	ActionMultipartComplete = "multipart:complete"
	ActionMultipartAbort    = "multipart:abort"
)

// AllActions is the full set of actions for admin/full-access tokens.
var AllActions = []string{
	ActionBucketList, ActionBucketReadMeta, ActionBucketWriteMeta,
	ActionObjectGet, ActionObjectPut, ActionObjectDelete, ActionObjectList,
	ActionMultipartCreate, ActionMultipartUpload, ActionMultipartComplete, ActionMultipartAbort,
}
