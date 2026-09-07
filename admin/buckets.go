package admin

// Bucket policy and visibility (PND-0187).
//
// Both knobs were fully implemented and completely unreachable: the evaluator
// in auth is real and tested, CreateBucket leaves every bucket private, and
// nothing in the tree ever called meta.UpdateBucketPolicy. The only way to
// install a policy was to stop jay and write the bucket record into bbolt with
// a program written for the occasion. The README documented a feature nobody
// could turn on.
//
// The door is here rather than on the S3 port on purpose. Jay's policy dialect
// is its own — `subjects`/`prefixes`/`actions`, not AWS's
// `Principal`/`Resource`/`Action` — so serving S3's PutBucketPolicy would mean
// either translating between two models that do not line up, or answering an
// S3 operation with a document no S3 client can read. And `visibility` has no
// S3 operation at all: the closest is PutBucketAcl, which is a different model
// again and stays in unimplementedBucketSubresources with the rest. The admin
// API already is the operator plane — accounts, tokens, quarantine — already
// carries JAY_ADMIN_TOKEN, and already never faces the internet.

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/internal/jsonx"
	"github.com/ivangsm/jay/meta"
)

// maxBucketPolicyBytes caps the document a caller may PUT. A bucket policy is
// written by hand and read by a human; anything past this is not one, and the
// body is buffered to be parsed.
const maxBucketPolicyBytes = 64 << 10

// bucketRoute splits "/buckets/<name>[/<sub>]" out of an admin path. ok is
// false for anything else. Bucket names cannot contain a slash
// (meta.ValidBucketName), so the split is unambiguous.
func bucketRoute(path string) (name, sub string, ok bool) {
	rest, found := strings.CutPrefix(path, "/buckets/")
	if !found || rest == "" {
		return "", "", false
	}
	name, sub, _ = strings.Cut(rest, "/")
	if name == "" || strings.Contains(sub, "/") {
		return "", "", false
	}
	return name, sub, true
}

// bucketResponse is what GET /_jay/buckets/{name} answers.
//
// It reports the policy and the visibility together because they are the two
// halves of one question — "who can reach this bucket?" — and reading one
// without the other has already been enough to mislead someone.
type bucketResponse struct {
	Name           string         `json:"name"`
	OwnerAccountID string         `json:"owner_account_id"`
	CreatedAt      time.Time      `json:"created_at"`
	Visibility     string         `json:"visibility"`
	Status         string         `json:"status"`
	Policy         jsontext.Value `json:"policy"`
}

// putPolicyResponse confirms what was installed rather than just that something
// was. `{"ok":true}` on an access-control change is a confirmation with nothing
// behind it; the statement count is the cheapest fact that proves the document
// was parsed and not merely stored.
type putPolicyResponse struct {
	Bucket     string `json:"bucket"`
	Statements int    `json:"statements"`
}

type visibilityRequest struct {
	Visibility string `json:"visibility"`
}

// handleGetBucket answers GET /_jay/buckets/{name}.
func (h *Handler) handleGetBucket(w http.ResponseWriter, _ *http.Request, name string) {
	bucket, ok := h.loadBucket(w, name)
	if !ok {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := jsonv2.MarshalWrite(w, bucketResponse{
		Name:           bucket.Name,
		OwnerAccountID: bucket.OwnerAccountID,
		CreatedAt:      bucket.CreatedAt,
		Visibility:     bucket.Visibility,
		Status:         bucket.Status,
		Policy:         bucket.PolicyJSON,
	}); err != nil {
		h.log.Error("encode get-bucket response", "err", err)
	}
}

// handlePutBucketPolicy answers PUT /_jay/buckets/{name}/policy. The request
// body IS the policy document — there is no envelope, so the file an operator
// edits is the file they send.
func (h *Handler) handlePutBucketPolicy(w http.ResponseWriter, r *http.Request, name string) {
	if _, ok := h.loadBucket(w, name); !ok {
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBucketPolicyBytes+1))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "could not read the policy document: "+err.Error())
		return
	}
	if len(raw) > maxBucketPolicyBytes {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "policy document is larger than 64 KiB")
		return
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		writeJSONError(w, http.StatusBadRequest,
			"empty body: to remove a policy use DELETE, which says so")
		return
	}

	// Decoded with auth.ParsePolicy, the single unmarshalling of a bucket policy
	// in the tree. Validating through a second decoder would mean accepting a
	// document under one dialect and evaluating it under another.
	policy, err := auth.ParsePolicy(jsontext.Value(raw))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "policy is not valid JSON: "+err.Error())
		return
	}
	if err := auth.ValidatePolicy(policy); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.db.UpdateBucketPolicy(name, jsontext.Value(raw)); err != nil {
		h.writeBucketUpdateError(w, "update bucket policy", name, err)
		return
	}
	h.log.Info("bucket policy installed", "bucket", name, "statements", len(policy.Statements))

	w.Header().Set("Content-Type", "application/json")
	if err := jsonv2.MarshalWrite(w, putPolicyResponse{
		Bucket:     name,
		Statements: len(policy.Statements),
	}); err != nil {
		h.log.Error("encode put-bucket-policy response", "err", err)
	}
}

// handleDeleteBucketPolicy answers DELETE /_jay/buckets/{name}/policy.
//
// Removing a policy closes a bucket rather than opening one: with no policy,
// AuthorizeBucketAccess has nothing to grant on and the default is deny. That
// is why it is a plain delete and not a quarantine — nothing is lost that was
// protecting anything.
func (h *Handler) handleDeleteBucketPolicy(w http.ResponseWriter, _ *http.Request, name string) {
	if _, ok := h.loadBucket(w, name); !ok {
		return
	}
	if err := h.db.UpdateBucketPolicy(name, nil); err != nil {
		h.writeBucketUpdateError(w, "delete bucket policy", name, err)
		return
	}
	h.log.Info("bucket policy removed", "bucket", name)
	w.WriteHeader(http.StatusNoContent)
}

// handlePutBucketVisibility answers PUT /_jay/buckets/{name}/visibility.
func (h *Handler) handlePutBucketVisibility(w http.ResponseWriter, r *http.Request, name string) {
	if _, ok := h.loadBucket(w, name); !ok {
		return
	}

	var req visibilityRequest
	if err := jsonv2.UnmarshalRead(r.Body, &req, jsonx.Strict); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Checked here as well as in meta so the caller gets the list of accepted
	// values instead of a bare 500 from a layer it cannot see.
	if !meta.ValidVisibility(req.Visibility) {
		writeJSONError(w, http.StatusBadRequest,
			"visibility must be \""+meta.VisibilityPrivate+"\" or \""+meta.VisibilityPublicRead+"\"")
		return
	}

	if err := h.db.UpdateBucketVisibility(name, req.Visibility); err != nil {
		h.writeBucketUpdateError(w, "update bucket visibility", name, err)
		return
	}
	h.log.Info("bucket visibility changed", "bucket", name, "visibility", req.Visibility)

	w.Header().Set("Content-Type", "application/json")
	if err := jsonv2.MarshalWrite(w, map[string]string{
		"bucket":     name,
		"visibility": req.Visibility,
	}); err != nil {
		h.log.Error("encode put-bucket-visibility response", "err", err)
	}
}

// loadBucket resolves the named bucket, answering 404 when it does not exist.
// Every handler above starts here so a policy is never accepted for a name that
// holds nothing — which would look like a configured bucket and be a typo.
func (h *Handler) loadBucket(w http.ResponseWriter, name string) (*meta.Bucket, bool) {
	bucket, err := h.db.GetBucket(name)
	if err != nil {
		if errors.Is(err, meta.ErrBucketNotFound) {
			writeJSONError(w, http.StatusNotFound, "bucket not found")
			return nil, false
		}
		h.log.Error("get bucket", "err", err, "bucket", name)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return nil, false
	}
	return bucket, true
}

// writeBucketUpdateError maps a write failure. A bucket that vanished between
// the load above and the update is a 404, not a 500: it is the caller's answer
// that changed, not jay that broke.
func (h *Handler) writeBucketUpdateError(w http.ResponseWriter, what, name string, err error) {
	if errors.Is(err, meta.ErrBucketNotFound) {
		writeJSONError(w, http.StatusNotFound, "bucket not found")
		return
	}
	h.log.Error(what, "err", err, "bucket", name)
	writeJSONError(w, http.StatusInternalServerError, "internal error")
}
