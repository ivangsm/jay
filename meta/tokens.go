package meta

import (
	"errors"
	"fmt"
	"time"
	"uuid"

	"golang.org/x/crypto/bcrypt"
)

// Sentinel errors for token and account lookups. Distinguishing them from a
// read failure is what lets the API answer 404 rather than 500.
var (
	ErrTokenNotFound   = errors.New("token not found")
	ErrAccountNotFound = errors.New("account not found")
)

// CreateAccount creates a new account.
func (db *DB) CreateAccount(a *Account) error {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	if a.Status == "" {
		a.Status = "active"
	}
	return db.putRecord(bucketAccounts, a.AccountID, a)
}

// GetAccount retrieves an account by ID.
func (db *DB) GetAccount(id string) (*Account, error) {
	return db.getRecord[Account](bucketAccounts, id, ErrAccountNotFound)
}

// CreateToken stores a new token in bbolt. The caller passes a Token with
// a plaintext SecretKey; it is encrypted before being persisted.
func (db *DB) CreateToken(t *Token) error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	if t.Status == "" {
		t.Status = "active"
	}
	enc, err := db.encryptSecret(t.SecretKey)
	if err != nil {
		return fmt.Errorf("meta: encrypt secret key: %w", err)
	}
	// Store encrypted version on disk, leave caller's struct untouched.
	stored := *t
	stored.SecretKey = enc
	return db.putRecord(bucketTokens, t.TokenID, &stored)
}

// GetToken retrieves a token by ID and transparently decrypts SecretKey.
// A thin wrapper over getRecord: decrypting the secret is the only thing it
// adds.
func (db *DB) GetToken(tokenID string) (*Token, error) {
	t, err := db.getRecord[Token](bucketTokens, tokenID, ErrTokenNotFound)
	if err != nil {
		return nil, err
	}
	plain, err := db.decryptSecret(t.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("meta: decrypt token %s: %w", tokenID, err)
	}
	t.SecretKey = plain
	return t, nil
}

// ListTokens returns all tokens, optionally filtered by account.
// SecretHash and SecretKey are zeroed in the response.
func (db *DB) ListTokens(accountID string) ([]Token, error) {
	tokens, err := db.listRecords(bucketTokens, func(t *Token) bool {
		return accountID == "" || t.AccountID == accountID
	})
	if err != nil {
		return nil, err
	}
	// Zeroing the secrets is the only thing this listing adds over the core.
	for i := range tokens {
		tokens[i].SecretHash = ""
		tokens[i].SecretKey = ""
	}
	return tokens, nil
}

// TokenSeedStatus describes the outcome of CreateTokenIfNotExists.
type TokenSeedStatus int

// The three outcomes of seeding a token. Mismatch is the one that matters: it
// means the id exists with a DIFFERENT secret, so booting would silently leave
// the operator with credentials that do not work.
const (
	TokenSeedCreated  TokenSeedStatus = iota // brand new token persisted
	TokenSeedReused                          // token existed with matching secret hash
	TokenSeedMismatch                        // token existed but secret hash didn't match
)

// CreateAccountIfNotExists looks up an account by Name. If found, returns it
// with created=false. If not found, creates a new one with a uuid ID.
func (db *DB) CreateAccountIfNotExists(name string) (*Account, bool, error) {
	matches, err := db.listRecords(bucketAccounts, func(a *Account) bool {
		return a.Name == name
	})
	if err != nil {
		return nil, false, err
	}
	if len(matches) > 0 {
		// Same rule as before: with several of the same name, the last one
		// bbolt's key-ordered walk returns wins.
		return &matches[len(matches)-1], false, nil
	}

	acc := &Account{
		AccountID: uuid.New().String(),
		Name:      name,
		Status:    "active",
		CreatedAt: time.Now().UTC(),
	}
	if err := db.CreateAccount(acc); err != nil {
		return nil, false, err
	}
	return acc, true, nil
}

// CreateTokenIfNotExists creates a token with a caller-provided ID. If a token
// with the same ID already exists, it compares the plaintext secret against
// the stored bcrypt hash:
//   - match    -> returns TokenSeedReused (no write)
//   - mismatch -> returns TokenSeedMismatch (no write)
//
// Otherwise creates a new token with the supplied hash and returns TokenSeedCreated.
func (db *DB) CreateTokenIfNotExists(tokenID, accountID, name, secretHash, plaintextSecret string, allowedActions []string) (*Token, TokenSeedStatus, error) {
	existing, err := db.GetToken(tokenID)
	if err != nil && !errors.Is(err, ErrTokenNotFound) {
		return nil, 0, err
	}
	if existing != nil {
		if bcrypt.CompareHashAndPassword([]byte(existing.SecretHash), []byte(plaintextSecret)) == nil {
			return existing, TokenSeedReused, nil
		}
		return existing, TokenSeedMismatch, nil
	}

	tok := &Token{
		TokenID:        tokenID,
		AccountID:      accountID,
		Name:           name,
		SecretHash:     secretHash,
		SecretKey:      plaintextSecret,
		AllowedActions: allowedActions,
		Status:         "active",
		CreatedAt:      time.Now().UTC(),
	}
	if err := db.CreateToken(tok); err != nil {
		return nil, 0, err
	}
	return tok, TokenSeedCreated, nil
}

// SetTokenInvalidateHook registers a callback invoked after a token is
// persisted with a mutated state (revoke/update/delete). The auth layer
// wires its cache invalidator here so stale cache entries are purged
// immediately instead of waiting for TTL expiration.
//
// Passing nil clears the hook. Safe to call at any time; invocations are
// serialized via hookMu.
func (db *DB) SetTokenInvalidateHook(fn func(tokenID string)) {
	db.hookMu.Lock()
	db.tokenInvalidateHook = fn
	db.hookMu.Unlock()
}

// fireTokenInvalidate invokes the registered hook (if any) for tokenID.
// Callers MUST only call this after a successful bbolt commit.
func (db *DB) fireTokenInvalidate(tokenID string) {
	db.hookMu.RLock()
	fn := db.tokenInvalidateHook
	db.hookMu.RUnlock()
	if fn != nil {
		fn(tokenID)
	}
}

// RevokeToken marks a token as revoked.
func (db *DB) RevokeToken(tokenID string) error {
	err := db.updateRecord(bucketTokens, tokenID, ErrTokenNotFound, func(t *Token) error {
		t.Status = "revoked"
		return nil
	})
	if err != nil {
		return err
	}
	db.fireTokenInvalidate(tokenID)
	return nil
}
