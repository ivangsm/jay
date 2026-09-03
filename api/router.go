package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/internal/objops"
	"github.com/ivangsm/jay/internal/ratelimit"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

// S3 sub-resource handling.
//
// dispatch routes on method, so a sub-resource it does not recognise used to
// fall through to the handler for that method and do something entirely
// different from what was asked: `PUT /bucket/key?tagging` reached
// handlePutObject and overwrote the object with the `<Tagging>` XML, answering
// 200 and a fresh ETag; `DELETE /bucket/key?tagging` deleted the object and
// answered 204. The hourly bbolt backup only holds metadata, so the bytes were
// gone for good.
//
// The rule below is deliberately asymmetric, and the asymmetry is the whole
// point:
//
//   - On PUT/POST/DELETE the cost of guessing wrong is a destroyed object, so
//     anything not positively recognised is refused (allowlist). A sub-resource
//     S3 adds tomorrow fails on its own.
//   - On GET/HEAD the cost of guessing wrong is answering with object bytes
//     instead of an XML document — wrong, but nothing is lost. There a denylist
//     of the sub-resources S3 defines and jay does not implement is enough, and
//     it keeps an innocuous `?v=<hash>` cache-buster from turning into a 501.

// unimplementedObjectSubresources are object-level S3 sub-resources jay does not
// implement. Only consulted for reads; writes use the allowlist instead.
var unimplementedObjectSubresources = map[string]struct{}{
	"acl":        {},
	"attributes": {}, // GetObjectAttributes
	"legal-hold": {},
	"restore":    {},
	"retention":  {},
	"select":     {}, // SelectObjectContent
	"tagging":    {},
	"torrent":    {},
	"versionId":  {}, // jay has no versioning: a version-scoped read is not the same read
	"versions":   {},
}

// unimplementedBucketSubresources are bucket-level S3 sub-resources jay does not
// implement. Same read/write split as the object-level list above.
var unimplementedBucketSubresources = map[string]struct{}{
	"accelerate":          {},
	"acl":                 {},
	"analytics":           {},
	"cors":                {},
	"encryption":          {},
	"intelligent-tiering": {},
	"inventory":           {},
	"lifecycle":           {},
	"logging":             {},
	"metrics":             {},
	"notification":        {},
	"object-lock":         {},
	"ownershipControls":   {},
	"policy":              {},
	"policyStatus":        {},
	"publicAccessBlock":   {},
	"replication":         {},
	"requestPayment":      {},
	"tagging":             {},
	"versioning":          {},
	"versions":            {},
	"website":             {},
}

// neutralQueryParam reports whether a param does not select an operation.
// `X-Jay-*` and `X-Amz-*` authenticate a presigned URL and `response-*` overrides
// response headers on GET; none of them changes which operation is being asked
// for, so they are safe to ignore on any method.
func neutralQueryParam(key string) bool {
	switch key {
	case "X-Jay-Token", "X-Jay-Expires", "X-Jay-Signature":
		return true
	}
	lower := strings.ToLower(key)
	return strings.HasPrefix(lower, "x-amz-") || strings.HasPrefix(lower, "response-")
}

// mutatingMethod reports whether the handler reached by this method can
// overwrite or delete. These are the ones held to the allowlist.
func mutatingMethod(method string) bool {
	switch method {
	case http.MethodPut, http.MethodPost, http.MethodDelete:
		return true
	}
	return false
}

// unsupportedSubresource returns the first query param that must fail the
// request, or "" if it can be dispatched.
//
// Callers must have already handled every operation the params can legitimately
// select (multipart, listing): by the time this runs, a supported sub-resource
// arriving on a mutating method is a method/sub-resource mismatch, not a valid
// request — `PUT /bucket/key?uploads` is not CreateMultipartUpload, it is a PUT
// that would overwrite the object.
func unsupportedSubresource(q url.Values, method string, unimplemented map[string]struct{}) string {
	mutating := mutatingMethod(method)
	for key := range q {
		if neutralQueryParam(key) {
			continue
		}
		if mutating {
			return key
		}
		if _, ok := unimplemented[key]; ok {
			return key
		}
	}
	return ""
}

// writeUnsupportedSubresource answers the honest status: the operation exists in
// S3 and jay does not implement it.
func writeUnsupportedSubresource(w http.ResponseWriter, r *http.Request, sub, resource string) {
	writeS3Error(w, r, http.StatusNotImplemented, S3ErrNotImplemented,
		"The '"+sub+"' sub-resource is not implemented", resource)
}

// Handler is the S3-compatible HTTP handler.
type Handler struct {
	db                *meta.DB
	store             *store.Store
	auth              *auth.Auth
	log               *slog.Logger
	metrics           *maintenance.Metrics
	signingSecret     string
	rateLimiter       *ratelimit.Limiter // per-token, post-auth
	ipRateLimiter     *ratelimit.Limiter // per-source-IP, pre-auth (see withIPRateLimit)
	objops            *objops.Service
	trustProxyHeaders bool
}

// NewHandler creates a new S3 API handler.
//
// trustProxyHeaders defaults to false (the safe option). Callers that sit
// behind a trusted reverse proxy should call SetTrustProxyHeaders(true) after
// construction — typically wired from cfg.TrustProxyHeaders in main.go. This
// is kept as a setter (not an extra NewHandler arg) so main.go's existing
// NewHandler call site does not need to be modified by this refactor agent.
func NewHandler(db *meta.DB, st *store.Store, au *auth.Auth, log *slog.Logger, metrics *maintenance.Metrics, signingSecret string, rlCfg *RateLimiterConfig) *Handler {
	var rl, ipRL *ratelimit.Limiter
	if rlCfg != nil && rlCfg.Rate > 0 {
		rl = newRateLimiter(*rlCfg)
		// Separate bucket set, same configured rate/burst. Keeping them
		// separate is what lets the IP limiter run before authentication
		// without stealing tokens from the per-token quota.
		ipRL = newRateLimiter(*rlCfg)
	}
	return &Handler{
		db:            db,
		store:         st,
		auth:          au,
		log:           log,
		metrics:       metrics,
		signingSecret: signingSecret,
		rateLimiter:   rl,
		ipRateLimiter: ipRL,
		objops:        objops.New(db, st, log),
	}
}

// SetTrustProxyHeaders enables or disables trust in X-Forwarded-For for
// client-IP derivation. Must be called before the server begins accepting
// requests — there is no locking around the flag. When false (the default),
// X-Forwarded-For is ignored entirely. When true, X-Forwarded-For is honoured
// only if the direct TCP peer is loopback or RFC1918 private.
func (h *Handler) SetTrustProxyHeaders(v bool) {
	h.trustProxyHeaders = v
}

// SetMaxObjectSize caps the size of a single PUT body (and of each multipart
// part). 0 means unlimited. Wired from cfg.MaxObjectSize in main.go; the
// native proto server owns a separate objops.Service and must be configured
// through its own setter.
func (h *Handler) SetMaxObjectSize(n int64) {
	h.objops.SetMaxObjectSize(n)
}

// ServeHTTP dispatches S3 requests based on path and method.
//
// Middleware order matters, outermost first:
//
//   - withRequestID mints the ID before anything can answer, so the header the
//     client gets, the access log line and the <RequestId> of any error
//     document are the same string on EVERY path — including the ones that
//     never reach the credential middleware (429, aws-chunked 501, presigned
//     rejection). It used to be minted in the middle of the chain and the
//     logger, sitting outside it, logged request_id="" on every request.
//   - withIPRateLimit runs BEFORE any authentication so that bcrypt/SigV4
//     verification is never reached by a source that is already over its
//     budget (see withIPRateLimit). withRateLimit then applies the per-token
//     quota once the caller is known.
//   - withUnframedBody sits between the two rate limiters and withPresigned: an
//     aws-chunked body cannot be served by any handler, so it is refused before
//     a signature is verified and before a single byte is read — but still
//     inside the IP limiter, so refusing it is not free for the sender.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler := h.withRequestID(h.withLogging(h.withIPRateLimit(h.withUnframedBody(h.withPresigned(h.withAuth(h.withRateLimit(h.dispatch)))))))
	handler(w, r)
}

// withPresigned checks for presigned URL query params before falling through
// to the normal auth middleware.
//
// Two forms are accepted and they do not overlap:
//
//   - SigV4 in its query-string form (X-Amz-Signature and friends), which is
//     what every AWS SDK, boto3, minio-go and `aws s3 presign` produce. It is
//     verified against the signing token's own secret, so it works whether or
//     not the server has a JAY_SIGNING_SECRET-derived presign secret wired.
//   - jay's own X-Jay-* form, HMAC'd with the server signing secret. falco and
//     `jay-admin presign` emit it, so it stays.
//
// The SigV4 branch is tried first and IsPresignedSigV4 already refuses a
// request that also carries an Authorization header, so there is no way to
// attach two credentials and have jay shop for the one that verifies.
func (h *Handler) withPresigned(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if auth.IsPresignedSigV4(r) {
			token, err := h.auth.AuthenticatePresignedSigV4(r)
			if err != nil {
				h.rejectPresigned(w, r)
				return
			}
			h.servePresigned(w, r, token)
			return
		}
		if h.signingSecret != "" && r.URL.Query().Get("X-Jay-Token") != "" {
			token, err := validatePresignedRequest(r, h.signingSecret, h.db)
			if err != nil {
				h.rejectPresigned(w, r)
				return
			}
			h.servePresigned(w, r, token)
			return
		}
		next(w, r)
	}
}

// servePresigned hands an authenticated presigned request straight to the rate
// limiter and dispatcher, skipping the credential middleware it has no
// credentials for. Authorization still runs: every handler calls requireAuth,
// so the token's actions, bucket scope and prefix scope apply exactly as they
// would to a Bearer or SigV4-header request.
//
// It does NOT mint a request ID. This branch skips withAuth, and back when the
// ID was minted there it had to mint its own — which is exactly how a request
// could log one ID and answer with another. withRequestID now owns the single
// generator and this path inherits its value like every other.
func (h *Handler) servePresigned(w http.ResponseWriter, r *http.Request, token *meta.Token) {
	ctx := context.WithValue(r.Context(), ctxKeyToken, token)
	h.withRateLimit(h.dispatch)(w, r.WithContext(ctx))
}

// rejectPresigned answers a presigned URL that did not verify. The reason is
// deliberately not reported: which of "expired", "no such token" and "bad
// signature" it was is an oracle, the same reasoning as auth's sentinel errors.
func (h *Handler) rejectPresigned(w http.ResponseWriter, r *http.Request) {
	if h.metrics != nil {
		h.metrics.AuthFailures.Add(1)
	}
	writeS3Error(w, r, http.StatusForbidden, S3ErrAccessDenied, "Invalid presigned URL", r.URL.Path)
}

func (h *Handler) dispatch(w http.ResponseWriter, r *http.Request) {
	// Custom JSON endpoint: GET /_stats/{name}
	// This is NOT an S3 API path; it returns JSON and is auth'd by bucket:read-meta.
	// The "/_stats/" prefix cannot collide with S3 bucket routes because Jay bucket
	// names must match `^[a-z0-9]...[a-z0-9]$` (see api/bucket_handlers.go), so no
	// valid bucket name starts with an underscore.
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/_stats/") {
		name := strings.TrimPrefix(r.URL.Path, "/_stats/")
		if name != "" && !strings.Contains(name, "/") {
			h.handleBucketStats(w, r, name)
			return
		}
	}

	// Parse path: /<bucket> or /<bucket>/<key...>
	path := strings.TrimPrefix(r.URL.Path, "/")

	// Root: list buckets
	if path == "" {
		if r.Method == http.MethodGet {
			h.handleListBuckets(w, r)
			return
		}
		writeS3Error(w, r, http.StatusMethodNotAllowed, S3ErrMethodNotAllowed, "Method not allowed", "/")
		return
	}

	// Split into bucket and key
	bucketName, objectKey, _ := strings.Cut(path, "/")

	if objectKey == "" {
		bq := r.URL.Query()

		// Bucket sub-resources jay does implement. They are claimed here, ahead
		// of the filter below, for the same reason the multipart params are
		// claimed ahead of it at object level: on a mutating method the filter
		// is an allowlist, so an operation it does not claim first can never be
		// reached. Each one is pinned to its own method — `PUT /bucket?delete`
		// is not DeleteObjects, it is a PUT carrying a name we recognise, and
		// the allowlist still refuses it.
		switch {
		case r.Method == http.MethodPost && bq.Has("delete"):
			h.handleDeleteObjects(w, r, bucketName)
			return
		case r.Method == http.MethodGet && bq.Has("location"):
			h.handleGetBucketLocation(w, r, bucketName)
			return
		case r.Method == http.MethodGet && bq.Has("uploads"):
			h.handleListMultipartUploads(w, r, bucketName)
			return
		}

		// Same reasoning as at object level (see unsupportedSubresource): an
		// unimplemented sub-resource must not reach the switch. `DELETE
		// /bucket?tagging` used to reach handleDeleteBucket and delete the
		// bucket itself.
		if sub := unsupportedSubresource(bq, r.Method, unimplementedBucketSubresources); sub != "" {
			writeUnsupportedSubresource(w, r, sub, "/"+bucketName)
			return
		}

		// Bucket-level operation
		switch r.Method {
		case http.MethodPut:
			h.handleCreateBucket(w, r, bucketName)
		case http.MethodDelete:
			h.handleDeleteBucket(w, r, bucketName)
		case http.MethodHead:
			h.handleHeadBucket(w, r, bucketName)
		case http.MethodGet:
			h.handleListObjectsV2(w, r, bucketName)
		default:
			writeS3Error(w, r, http.StatusMethodNotAllowed, S3ErrMethodNotAllowed, "Method not allowed", "/"+bucketName)
		}
		return
	}

	q := r.URL.Query()

	// Multipart operations (detected by query params)
	if q.Get("uploads") != "" || q.Has("uploads") {
		// POST /<bucket>/<key>?uploads → CreateMultipartUpload
		if r.Method == http.MethodPost {
			h.handleCreateMultipartUpload(w, r, bucketName, objectKey)
			return
		}
	}
	if uploadID := q.Get("uploadId"); uploadID != "" {
		switch r.Method {
		case http.MethodPut:
			// PUT /<bucket>/<key>?uploadId=X&partNumber=N → UploadPart
			h.handleUploadPart(w, r, bucketName, objectKey, uploadID)
		case http.MethodPost:
			// POST /<bucket>/<key>?uploadId=X → CompleteMultipartUpload
			h.handleCompleteMultipartUpload(w, r, bucketName, objectKey, uploadID)
		case http.MethodDelete:
			// DELETE /<bucket>/<key>?uploadId=X → AbortMultipartUpload
			h.handleAbortMultipartUpload(w, r, bucketName, objectKey, uploadID)
		case http.MethodGet:
			// GET /<bucket>/<key>?uploadId=X → ListParts
			h.handleListParts(w, r, bucketName, objectKey, uploadID)
		default:
			writeS3Error(w, r, http.StatusMethodNotAllowed, S3ErrMethodNotAllowed, "Method not allowed", "/"+bucketName+"/"+objectKey)
		}
		return
	}

	// Every legitimate multipart operation has returned by now, so a sub-resource
	// reaching this point must not fall through to the switch below. See
	// unsupportedSubresource for why writes are held to an allowlist and reads
	// only to a denylist.
	if sub := unsupportedSubresource(q, r.Method, unimplementedObjectSubresources); sub != "" {
		writeUnsupportedSubresource(w, r, sub, "/"+bucketName+"/"+objectKey)
		return
	}

	// Object-level operation
	switch r.Method {
	case http.MethodPut:
		if r.Header.Get("x-amz-copy-source") != "" {
			h.handleCopyObject(w, r, bucketName, objectKey)
		} else {
			h.handlePutObject(w, r, bucketName, objectKey)
		}
	case http.MethodGet:
		h.handleGetObject(w, r, bucketName, objectKey)
	case http.MethodHead:
		h.handleHeadObject(w, r, bucketName, objectKey)
	case http.MethodDelete:
		h.handleDeleteObject(w, r, bucketName, objectKey)
	case http.MethodPost:
		// POST without uploadId query is invalid for objects
		writeS3Error(w, r, http.StatusBadRequest, S3ErrInvalidArgument, "Invalid request", "/"+bucketName+"/"+objectKey)
	default:
		writeS3Error(w, r, http.StatusMethodNotAllowed, S3ErrMethodNotAllowed, "Method not allowed", "/"+bucketName+"/"+objectKey)
	}
}
