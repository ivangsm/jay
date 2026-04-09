package meta

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/hkdf"
	"io"

	bolt "go.etcd.io/bbolt"
)

const (
	encryptedPrefix = "enc:v1:"
	hkdfSalt        = "jay-token-secret-v1"
	hkdfInfo        = "token-secretkey-aead"
)

// DeriveKEK derives a 32-byte AES-256 key from signingSecret using HKDF-SHA256.
func DeriveKEK(signingSecret string) [32]byte {
	r := hkdf.New(sha256.New, []byte(signingSecret), []byte(hkdfSalt), []byte(hkdfInfo))
	var key [32]byte
	if _, err := io.ReadFull(r, key[:]); err != nil {
		panic("meta: HKDF read failed: " + err.Error())
	}
	return key
}

// SetSigningSecret derives and caches the KEK used to encrypt/decrypt
// Token.SecretKey at rest. Must be called before any token read/write.
func (db *DB) SetSigningSecret(s string) {
	k := DeriveKEK(s)
	db.kekMu.Lock()
	db.kek = k
	db.kekSet = true
	db.kekMu.Unlock()
}

func (db *DB) aead() (cipher.AEAD, error) {
	db.kekMu.RLock()
	defer db.kekMu.RUnlock()
	if !db.kekSet {
		return nil, fmt.Errorf("meta: signing secret not set — cannot decrypt token.SecretKey")
	}
	block, err := aes.NewCipher(db.kek[:])
	if err != nil {
		return nil, fmt.Errorf("meta: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("meta: cipher.NewGCM: %w", err)
	}
	return gcm, nil
}

// encryptSecret encrypts a plaintext secret and returns the "enc:v1:" prefixed
// representation for on-disk storage.
func (db *DB) encryptSecret(plain string) (string, error) {
	gcm, err := db.aead()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("meta: generate nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil) // nonce || ciphertext || tag
	return encryptedPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// decryptSecret takes a stored value and returns the plaintext secret.
// Unencrypted (legacy) values are returned as-is.
func (db *DB) decryptSecret(stored string) (string, error) {
	if !strings.HasPrefix(stored, encryptedPrefix) {
		return stored, nil
	}
	gcm, err := db.aead()
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, encryptedPrefix))
	if err != nil {
		return "", fmt.Errorf("meta: base64 decode secret: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", fmt.Errorf("meta: encrypted secret too short")
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("meta: decrypt secret: %w", err)
	}
	return string(plain), nil
}

// MigrateTokenSecrets scans the tokens bucket and re-encrypts any token where
// SecretKey is stored as plaintext (no "enc:v1:" prefix). Returns the number
// of tokens migrated. Idempotent — already-encrypted entries are skipped.
func (db *DB) MigrateTokenSecrets() (migrated int, err error) {
	type pending struct {
		id   string
		data []byte
	}
	var toUpdate []pending

	err = db.bolt.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).ForEach(func(k, v []byte) error {
			var t Token
			if err := json.Unmarshal(v, &t); err != nil {
				return nil
			}
			if t.SecretKey == "" || strings.HasPrefix(t.SecretKey, encryptedPrefix) {
				return nil
			}
			enc, err := db.encryptSecret(t.SecretKey)
			if err != nil {
				return err
			}
			t.SecretKey = enc
			updated, err := json.Marshal(&t)
			if err != nil {
				return err
			}
			toUpdate = append(toUpdate, pending{id: t.TokenID, data: updated})
			return nil
		})
	})
	if err != nil {
		return 0, fmt.Errorf("meta: scan tokens for migration: %w", err)
	}

	if len(toUpdate) == 0 {
		return 0, nil
	}

	err = db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketTokens)
		for _, p := range toUpdate {
			if err := bk.Put([]byte(p.id), p.data); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("meta: write migrated tokens: %w", err)
	}
	return len(toUpdate), nil
}
