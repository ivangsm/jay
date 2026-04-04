package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ivangsm/jay/meta"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrNoCredentials    = errors.New("no credentials provided")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenRevoked     = errors.New("token revoked")
	ErrAccessDenied     = errors.New("access denied")
)

// Auth handles authentication and authorization.
type Auth struct {
	db *meta.DB
}

// New creates an Auth instance.
func New(db *meta.DB) *Auth {
	return &Auth{db: db}
}

// Authenticate extracts and validates credentials from the request.
// Supports: Authorization: Bearer <token_id>:<secret>
func (a *Auth) Authenticate(r *http.Request) (*meta.Token, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, ErrNoCredentials
	}

	// Bearer <token_id>:<secret>
	if strings.HasPrefix(authHeader, "Bearer ") {
		parts := strings.SplitN(strings.TrimPrefix(authHeader, "Bearer "), ":", 2)
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

	if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
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
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func hasMatchingPrefix(prefixes []string, key string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}
