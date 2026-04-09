package auth

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ivangsm/jay/meta"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrNoCredentials      = errors.New("no credentials provided")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenRevoked       = errors.New("token revoked")
	ErrAccessDenied       = errors.New("access denied")
)

const authCacheTTL = 5 * time.Minute

// authCacheEntry stores a validated token with an expiry time.
type authCacheEntry struct {
	token     *meta.Token
	expiresAt time.Time
}

// Auth handles authentication and authorization.
type Auth struct {
	db        *meta.DB
	mu        sync.RWMutex
	cache     map[[32]byte]authCacheEntry
	tokenKeys map[string]map[[32]byte]struct{} // tokenID → set of cache keys
}

// New creates an Auth instance.
func New(db *meta.DB) *Auth {
	return &Auth{
		db:        db,
		cache:     make(map[[32]byte]authCacheEntry),
		tokenKeys: make(map[string]map[[32]byte]struct{}),
	}
}

// cacheKey produces a SHA-256 hash of tokenID:secret for cache lookup.
func cacheKey(tokenID, secret string) [32]byte {
	return sha256.Sum256([]byte(tokenID + ":" + secret))
}

// InvalidateToken removes all cache entries for a given token ID.
// Call this when a token is revoked or modified.
func (a *Auth) InvalidateToken(tokenID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if keys, ok := a.tokenKeys[tokenID]; ok {
		for k := range keys {
			delete(a.cache, k)
		}
		delete(a.tokenKeys, tokenID)
	}
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
	if entry, ok := a.cache[key]; ok && now.Before(entry.expiresAt) {
		a.mu.RUnlock()
		// Re-check revocation/expiry on the cached token without bcrypt.
		if entry.token.Status == "revoked" {
			return nil, ErrTokenRevoked
		}
		if entry.token.ExpiresAt != nil && now.After(*entry.token.ExpiresAt) {
			return nil, ErrTokenExpired
		}
		return entry.token, nil
	}
	a.mu.RUnlock()

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
		return nil, ErrInvalidCredentials
	}

	// Verify account exists and is active
	account, err := a.db.GetAccount(token.AccountID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if account.Status != "active" {
		return nil, ErrAccessDenied
	}

	// Store in cache — clone the token and strip SecretKey so the cache
	// never holds the plaintext secret (Bearer auth only needs bcrypt).
	cached := *token
	cached.SecretKey = ""
	a.mu.Lock()
	a.cache[key] = authCacheEntry{token: &cached, expiresAt: now.Add(authCacheTTL)}
	if a.tokenKeys[token.TokenID] == nil {
		a.tokenKeys[token.TokenID] = make(map[[32]byte]struct{})
	}
	a.tokenKeys[token.TokenID][key] = struct{}{}
	a.mu.Unlock()

	return token, nil
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
func (a *Auth) AuthorizeWithPolicy(token *meta.Token, action, bucketName, objectKey, clientIP string, policyJSON json.RawMessage) error {
	// Run existing token-level authorization first.
	if err := a.Authorize(token, action, bucketName, objectKey); err != nil {
		return err
	}

	// If no policy is attached, token authorization alone is sufficient.
	if len(policyJSON) == 0 {
		return nil
	}

	var policy BucketPolicy
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		// Malformed policy should not silently grant access.
		return ErrAccessDenied
	}
	policy.Compile()

	if EvaluatePolicyDeny(&policy, token.TokenID, action, objectKey, clientIP) {
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
