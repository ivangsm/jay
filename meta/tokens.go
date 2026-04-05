package meta

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
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
