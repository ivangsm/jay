// Package auth validates jay's credentials: bearer tokens and real SigV4
// signatures, plus per-action, per-bucket and per-prefix scoping.
//
// SigV4 verification recomputes the body hash rather than trusting the one the
// client declared, so an altered body does not pass. That is why signed requests
// carrying a payload hash are size-capped: the body has to be buffered to be
// hashed.
package auth

import (
	"crypto/sha256"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ivangsm/jay/internal/jsonx"
	"github.com/ivangsm/jay/meta"
	"golang.org/x/crypto/bcrypt"
)

// Sentinel errors for authentication.
//
// They are deliberately NOT distinguished in the HTTP response: telling a caller
// whether a token exists, is expired or was revoked is itself an oracle.
var (
	ErrNoCredentials      = errors.New("no credentials provided")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenRevoked       = errors.New("token revoked")
	ErrAccessDenied       = errors.New("access denied")
)

const authCacheTTL = 5 * time.Minute

// authFailCacheTTL is how long a failed bcrypt comparison is remembered.
//
// bcrypt costs ~60-100ms of CPU per attempt, so replaying the same bad
// credentials is a cheap way to burn the whole CPU budget. Caching the
// *failure* for a few seconds makes identical retries free. The TTL is kept
// deliberately short so a secret rotation (or a token being re-created with a
// new secret) is never blocked for more than a few seconds.
const authFailCacheTTL = 5 * time.Second

// authFailCacheMax caps the negative cache so an attacker cycling through
// random secrets cannot grow it without bound. When exceeded, expired entries
// are swept and — if that is not enough — the map is dropped entirely.
const authFailCacheMax = 4096

// authCacheEntry stores a validated token with an expiry time.
type authCacheEntry struct {
	token     *meta.Token
	expiresAt time.Time
}

// authFailEntry remembers a rejected credential pair until deadline.
type authFailEntry struct {
	err      error
	deadline time.Time
}

// Auth handles authentication and authorization.
type Auth struct {
	db        *meta.DB
	mu        sync.RWMutex
	cache     map[[32]byte]authCacheEntry
	failCache map[[32]byte]authFailEntry
	tokenKeys map[string]map[[32]byte]struct{} // tokenID → set of cache keys (positive + negative)
}

// New creates an Auth instance.
func New(db *meta.DB) *Auth {
	return &Auth{
		db:        db,
		cache:     make(map[[32]byte]authCacheEntry),
		failCache: make(map[[32]byte]authFailEntry),
		tokenKeys: make(map[string]map[[32]byte]struct{}),
	}
}

// cacheKey produces a SHA-256 hash of tokenID:secret for cache lookup.
func cacheKey(tokenID, secret string) [32]byte {
	return sha256.Sum256([]byte(tokenID + ":" + secret))
}

// InvalidateToken removes all cache entries (positive and negative) for a
// given token ID. Call this when a token is revoked or modified.
func (a *Auth) InvalidateToken(tokenID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if keys, ok := a.tokenKeys[tokenID]; ok {
		for k := range keys {
			delete(a.cache, k)
			delete(a.failCache, k)
		}
		delete(a.tokenKeys, tokenID)
	}
}

// rememberKey associates a cache key with its token ID so InvalidateToken can
// evict it later. Caller must hold a.mu.
func (a *Auth) rememberKey(tokenID string, key [32]byte) {
	if a.tokenKeys[tokenID] == nil {
		a.tokenKeys[tokenID] = make(map[[32]byte]struct{})
	}
	a.tokenKeys[tokenID][key] = struct{}{}
}

// cacheAuthFailure records a rejected credential pair so identical retries do
// not pay for bcrypt again within authFailCacheTTL.
func (a *Auth) cacheAuthFailure(tokenID string, key [32]byte, failErr error, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.failCache) >= authFailCacheMax {
		for k, e := range a.failCache {
			if now.After(e.deadline) {
				delete(a.failCache, k)
			}
		}
		// Still full of live entries: drop everything rather than grow without
		// bound. Worst case a handful of attackers pay for bcrypt again.
		if len(a.failCache) >= authFailCacheMax {
			a.failCache = make(map[[32]byte]authFailEntry)
		}
	}

	a.failCache[key] = authFailEntry{err: failErr, deadline: now.Add(authFailCacheTTL)}
	a.rememberKey(tokenID, key)
}

// Authenticate extracts and validates credentials from the request.
// Supports: Authorization: Bearer <token_id>:<secret>
func (a *Auth) Authenticate(r *http.Request) (*meta.Token, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, ErrNoCredentials
	}

	// Bearer <token_id>:<secret>
	if after, ok := strings.CutPrefix(authHeader, "Bearer "); ok {
		parts := strings.SplitN(after, ":", 2)
		if len(parts) != 2 {
			return nil, ErrInvalidCredentials
		}
		tokenID, secret := parts[0], parts[1]
		return a.validateToken(tokenID, secret)
	}

	// AWS Signature V4
	if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		return a.AuthenticateSigV4(r)
	}

	return nil, ErrInvalidCredentials
}

// AuthenticateCredentials validates a token_id and secret pair directly,
// without requiring an HTTP request. Used by the native protocol.
func (a *Auth) AuthenticateCredentials(tokenID, secret string) (*meta.Token, error) {
	return a.validateToken(tokenID, secret)
}

func (a *Auth) validateToken(tokenID, secret string) (*meta.Token, error) {
	// Fast path: check cache with a read lock.
	key := cacheKey(tokenID, secret)
	now := time.Now()

	a.mu.RLock()
	entry, hit := a.cache[key]
	hit = hit && now.Before(entry.expiresAt)
	failEntry, failHit := a.failCache[key]
	failHit = failHit && now.Before(failEntry.deadline)
	a.mu.RUnlock()

	// Negative cache: identical bad credentials are rejected without bcrypt.
	if failHit {
		return nil, failEntry.err
	}

	if hit {
		// Re-check revocation/expiry on the cached token without bcrypt.
		if entry.token.Status == "revoked" {
			return nil, ErrTokenRevoked
		}
		if entry.token.ExpiresAt != nil && now.After(*entry.token.ExpiresAt) {
			return nil, ErrTokenExpired
		}
		// Account status must be re-checked on every request: suspending an
		// account has to take effect immediately, not after authCacheTTL. This
		// is an O(1) bbolt View, orders of magnitude cheaper than bcrypt.
		if err := a.checkAccountActive(entry.token.AccountID); err != nil {
			return nil, err
		}
		return entry.token, nil
	}

	// Slow path: full validation with bcrypt.
	token, err := a.db.GetToken(tokenID)
	if err != nil {
		if errors.Is(err, meta.ErrTokenNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if token.Status == "revoked" {
		return nil, ErrTokenRevoked
	}

	if token.ExpiresAt != nil && now.After(*token.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	if err := bcrypt.CompareHashAndPassword([]byte(token.SecretHash), []byte(secret)); err != nil {
		// Remember the failure briefly so a replay of the same wrong secret
		// does not cost another bcrypt round.
		a.cacheAuthFailure(tokenID, key, ErrInvalidCredentials, now)
		return nil, ErrInvalidCredentials
	}

	// Verify account exists and is active
	if err := a.checkAccountActive(token.AccountID); err != nil {
		return nil, err
	}

	// Store in cache — clone the token and strip SecretKey so the cache
	// never holds the plaintext secret (Bearer auth only needs bcrypt).
	cached := *token
	cached.SecretKey = ""
	a.mu.Lock()
	a.cache[key] = authCacheEntry{token: &cached, expiresAt: now.Add(authCacheTTL)}
	a.rememberKey(token.TokenID, key)
	a.mu.Unlock()

	return token, nil
}

// checkAccountActive verifies the owning account still exists and is active.
// Returns ErrInvalidCredentials when the account is gone and ErrAccessDenied
// when it is suspended.
func (a *Auth) checkAccountActive(accountID string) error {
	account, err := a.db.GetAccount(accountID)
	if err != nil {
		return ErrInvalidCredentials
	}
	if account.Status != "active" {
		return ErrAccessDenied
	}
	return nil
}

// Authorize checks if the token has permission for the given action on the bucket/key.
func (a *Auth) Authorize(token *meta.Token, action, bucketName, objectKey string) error {
	// Check action is allowed
	if !containsAction(token.AllowedActions, action) {
		return ErrAccessDenied
	}

	// Check bucket scope (empty means all buckets)
	if len(token.BucketScope) > 0 && !contains(token.BucketScope, bucketName) {
		return ErrAccessDenied
	}

	// Check prefix scope (empty means all prefixes)
	if len(token.PrefixScope) > 0 && objectKey != "" {
		if !hasMatchingPrefix(token.PrefixScope, objectKey) {
			return ErrAccessDenied
		}
	}

	return nil
}

// AuthorizeBucketOwnership checks that the token is entitled to operate on an
// EXISTING bucket's metadata (delete, head, and any other cross-account
// sensitive bucket operation).
//
// Authorize alone is not enough: a token with "bucket:write-meta" and no
// BucketScope is allowed to act on *every* bucket name, including buckets
// owned by a different account. This is the tenant-isolation check that must
// run in addition to Authorize, after the bucket has been loaded from meta.
//
// Access is granted when any of the following holds:
//   - the token's account owns the bucket;
//   - the bucket has no owner (legacy buckets created before ownership was
//     recorded — refusing these would break existing deployments);
//   - the token's BucketScope explicitly names the bucket, which is how an
//     operator delegates cross-account access via the admin API.
func (a *Auth) AuthorizeBucketOwnership(token *meta.Token, bucket *meta.Bucket) error {
	return authorizeBucketOwnership(token, bucket)
}

// authorizeBucketOwnership is the ownership half of AuthorizeBucketAccess. It
// needs no Auth state, so it is reachable from packages that hold a bucket but
// not an *Auth.
func authorizeBucketOwnership(token *meta.Token, bucket *meta.Bucket) error {
	if token == nil || bucket == nil {
		return ErrAccessDenied
	}
	if bucket.OwnerAccountID == "" {
		return nil
	}
	if token.AccountID == bucket.OwnerAccountID {
		return nil
	}
	// Explicit delegation: the operator scoped this token to this bucket.
	if contains(token.BucketScope, bucket.Name) {
		return nil
	}
	return ErrAccessDenied
}

// AuthorizeBucketAccess is the cross-account gate for an EXISTING bucket, and
// the single place where "may this token touch this bucket at all?" is decided.
//
// Authorize answers a different question: what the token is scoped to. A token
// with "*" actions and no BucketScope passes it for every bucket name in the
// store, including buckets of other accounts — which is exactly how object
// operations ended up reachable across accounts while the bucket operations
// were safe (PND-0185). Every path that has resolved a bucket calls this, so a
// handler added tomorrow inherits the check instead of having to remember it.
//
// Access is granted when, in this order:
//
//  1. the token's account owns the bucket, the bucket has no recorded owner
//     (legacy), or the token's BucketScope names it explicitly — see
//     AuthorizeBucketOwnership;
//  2. the bucket is public-read and the action is a read of object data. This
//     mirrors the anonymous rule the HTTP layer already applies: it would be
//     absurd for a bucket that answers strangers with no credentials at all to
//     refuse the same read to an authenticated token of another account;
//  3. a bucket policy carries an explicit allow that matches the subject, the
//     action, the prefix and the IP conditions.
//
// Otherwise: denied. The default is deny and a missing or malformed policy
// never opens anything — a policy that cannot be parsed is refused, not
// ignored.
//
// Order matters and is deliberate. Running the account check BEFORE the policy
// would make a cross-account allow statement unreachable, and the policy is the
// only mechanism the README offers for sharing a bucket. Running the policy
// FIRST would mean a bucket without a policy has nothing to say about a
// stranger, and "nothing to say" must never read as yes. So: ownership, then
// the documented public-read door, then an explicit grant — and deny statements
// are still evaluated afterwards by the caller, so a deny always wins.
//
// This is a package-level function, not a method, because the decision needs no
// database: everything it reads is already in the token and the bucket the
// caller resolved. That is what lets objops and both transports share it.
func AuthorizeBucketAccess(token *meta.Token, bucket *meta.Bucket, action, objectKey, sourceIP string) error {
	if bucket == nil {
		return ErrAccessDenied
	}
	if authorizeBucketOwnership(token, bucket) == nil {
		return nil
	}
	if bucket.Visibility == "public-read" &&
		(action == meta.ActionObjectGet || action == meta.ActionObjectList) {
		return nil
	}

	policy, err := ParsePolicy(bucket.PolicyJSON)
	if err != nil || policy == nil {
		return ErrAccessDenied
	}
	tokenID := ""
	if token != nil {
		tokenID = token.TokenID
	}
	if EvaluatePolicyAllow(policy, tokenID, action, objectKey, sourceIP) {
		return nil
	}
	return ErrAccessDenied
}

// ParsePolicy decodes a bucket policy and compiles its conditions. A bucket
// with no policy returns (nil, nil) — the caller decides what that means, and
// for AuthorizeBucketAccess it means deny.
//
// Lenient rather than v2's defaults: bucket policies are written by hand, and
// v1 matched field names case-insensitively. Under v2's case-sensitive defaults
// an AWS-style policy ("Effect"/"Statements") would stop parsing and its Deny
// statement would vanish silently — opening access where it used to be refused.
// Lenient preserves v1's matching.
//
// This is the only unmarshalling of a bucket policy in the tree: two of them
// would be two dialects.
func ParsePolicy(policyJSON jsontext.Value) (*BucketPolicy, error) {
	if len(policyJSON) == 0 {
		return nil, nil
	}
	var policy BucketPolicy
	if err := jsonv2.Unmarshal(policyJSON, &policy, jsonx.Lenient); err != nil {
		return nil, err
	}
	policy.Compile()
	return &policy, nil
}

// IsPublicRead checks if a bucket is publicly readable.
func (a *Auth) IsPublicRead(bucketName string) bool {
	b, err := a.db.GetBucket(bucketName)
	if err != nil {
		return false
	}
	return b.Visibility == "public-read"
}

// HashSecret hashes a secret for storage using bcrypt.
func HashSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func containsAction(actions []string, action string) bool {
	for _, a := range actions {
		if a == action || a == "*" {
			return true
		}
	}
	return false
}

func contains(slice []string, item string) bool {
	return slices.Contains(slice, item)
}

// AuthorizeWithPolicy performs all existing Authorize checks and additionally
// evaluates a bucket policy (if provided) against the request context.
// Deny in the policy always takes precedence.
func (a *Auth) AuthorizeWithPolicy(token *meta.Token, action, bucketName, objectKey, clientIP string, policyJSON jsontext.Value) error {
	// Run existing token-level authorization first.
	if err := a.Authorize(token, action, bucketName, objectKey); err != nil {
		return err
	}

	// If no policy is attached, token authorization alone is sufficient.
	if len(policyJSON) == 0 {
		return nil
	}

	policy, err := ParsePolicy(policyJSON)
	if err != nil {
		// Malformed policy should not silently grant access.
		return ErrAccessDenied
	}

	if EvaluatePolicyDeny(policy, token.TokenID, action, objectKey, clientIP) {
		return ErrAccessDenied
	}

	return nil
}

func hasMatchingPrefix(prefixes []string, key string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}
