package meta

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrTokenNotFound = errors.New("token not found")
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
	data, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("meta: marshal account: %w", err)
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAccounts).Put([]byte(a.AccountID), data)
	})
}

// GetAccount retrieves an account by ID.
func (db *DB) GetAccount(id string) (*Account, error) {
	var a Account
	err := db.bolt.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketAccounts).Get([]byte(id))
		if data == nil {
			return ErrAccountNotFound
		}
		return json.Unmarshal(data, &a)
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// CreateToken stores a new token in bbolt.
func (db *DB) CreateToken(t *Token) error {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	if t.Status == "" {
		t.Status = "active"
	}
	data, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("meta: marshal token: %w", err)
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).Put([]byte(t.TokenID), data)
	})
}

// GetToken retrieves a token by ID.
func (db *DB) GetToken(tokenID string) (*Token, error) {
	var t Token
	err := db.bolt.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketTokens).Get([]byte(tokenID))
		if data == nil {
			return ErrTokenNotFound
		}
		return json.Unmarshal(data, &t)
	})
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ListTokens returns all tokens, optionally filtered by account.
func (db *DB) ListTokens(accountID string) ([]Token, error) {
	var tokens []Token
	err := db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).ForEach(func(k, v []byte) error {
			var t Token
			if err := json.Unmarshal(v, &t); err != nil {
				return nil
			}
			if accountID == "" || t.AccountID == accountID {
				// Don't expose secrets in listings
				t.SecretHash = ""
				t.SecretKey = ""
				tokens = append(tokens, t)
			}
			return nil
		})
	})
	return tokens, err
}

// TokenSeedStatus describes the outcome of CreateTokenIfNotExists.
type TokenSeedStatus int

const (
	TokenSeedCreated  TokenSeedStatus = iota // brand new token persisted
	TokenSeedReused                          // token existed with matching secret hash
	TokenSeedMismatch                        // token existed but secret hash didn't match
)

// CreateAccountIfNotExists looks up an account by Name. If found, returns it
// with created=false. If not found, creates a new one with a uuid ID.
func (db *DB) CreateAccountIfNotExists(name string) (*Account, bool, error) {
	// Search existing accounts by Name (linear — OK for O(10) accounts)
	var found *Account
	err := db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAccounts).ForEach(func(k, v []byte) error {
			var a Account
			if err := json.Unmarshal(v, &a); err != nil {
				return nil
			}
			if a.Name == name {
				copy := a
				found = &copy
			}
			return nil
		})
	})
	if err != nil {
		return nil, false, err
	}
	if found != nil {
		return found, false, nil
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
//   - match    → returns TokenSeedReused (no write)
//   - mismatch → returns TokenSeedMismatch (no write)
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

// RevokeToken marks a token as revoked.
func (db *DB) RevokeToken(tokenID string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketTokens)
		data := bk.Get([]byte(tokenID))
		if data == nil {
			return ErrTokenNotFound
		}
		var t Token
		if err := json.Unmarshal(data, &t); err != nil {
			return err
		}
		t.Status = "revoked"
		updated, err := json.Marshal(&t)
		if err != nil {
			return err
		}
		return bk.Put([]byte(tokenID), updated)
	})
}
