package meta

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/hkdf"
	"io"

	"github.com/ivangsm/jay/internal/jsonx"
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

// aesGCMEncrypt encrypts plain with kek, returning an "enc:v1:" prefixed value.
func aesGCMEncrypt(kek [32]byte, plain string) (string, error) {
	block, err := aes.NewCipher(kek[:])
	if err != nil {
		return "", fmt.Errorf("meta: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("meta: cipher.NewGCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("meta: generate nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil) // nonce || ciphertext || tag
	return encryptedPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// aesGCMDecrypt decrypts a stored "enc:v1:" value with kek.
// Values without the prefix are returned as-is (legacy plaintext).
func aesGCMDecrypt(kek [32]byte, stored string) (string, error) {
	if !strings.HasPrefix(stored, encryptedPrefix) {
		return stored, nil
	}
	block, err := aes.NewCipher(kek[:])
	if err != nil {
		return "", fmt.Errorf("meta: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("meta: cipher.NewGCM: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, encryptedPrefix))
	if err != nil {
		return "", fmt.Errorf("meta: base64 decode secret: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("meta: encrypted secret too short")
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("meta: decrypt secret: %w", err)
	}
	return string(plain), nil
}

func (db *DB) encryptSecret(plain string) (string, error) {
	db.kekMu.RLock()
	defer db.kekMu.RUnlock()
	if !db.kekSet {
		return "", errors.New("meta: signing secret not set — cannot encrypt token.SecretKey")
	}
	return aesGCMEncrypt(db.kek, plain)
}

func (db *DB) decryptSecret(stored string) (string, error) {
	db.kekMu.RLock()
	defer db.kekMu.RUnlock()
	if !db.kekSet {
		return "", errors.New("meta: signing secret not set — cannot decrypt token.SecretKey")
	}
	return aesGCMDecrypt(db.kek, stored)
}

// minSigningSecretLen is the server's floor for JAY_SIGNING_SECRET
// (minSecretLen in cmd/jay/main.go, which refuses to start below it).
// cmd/jay-rekey's tests read the server's constant and check this refusal
// against it, so the two cannot drift apart silently.
const minSigningSecretLen = 32

// RekeyTokens decrypts every token secret with oldSecret and re-encrypts it
// with newSecret. Jay must be stopped before calling this — bbolt enforces an
// exclusive file lock that will block if another process has the DB open.
// Returns the number of tokens rekeyed.
//
// A token that already decrypts under newSecret is left as it is. That is what
// makes a second run with the same arguments a no-op rather than a decrypt
// error, and — more to the point — what makes a database holding tokens under
// BOTH secrets recoverable: the state a server leaves when it is restarted
// with the new secret before the rekey runs and mints a token in between.
// Refusing that database left the operator with no way back, since no endpoint
// deletes a token record.
//
// A token that decrypts under neither secret aborts the run before anything is
// written. So does a newSecret shorter than the server accepts: rekeying to it
// would report success and leave a database jay refuses to start against.
func (db *DB) RekeyTokens(oldSecret, newSecret string) (int, error) {
	if len(newSecret) < minSigningSecretLen {
		return 0, fmt.Errorf("rekey: the new signing secret is %d bytes and jay refuses to start "+
			"with fewer than %d; nothing was rekeyed", len(newSecret), minSigningSecretLen)
	}
	oldKEK := DeriveKEK(oldSecret)
	newKEK := DeriveKEK(newSecret)

	n, err := db.resecretTokens(func(t *Token) (bool, error) {
		if !strings.HasPrefix(t.SecretKey, encryptedPrefix) {
			return false, nil // plaintext legacy entry — MigrateTokenSecrets handles these
		}
		plain, err := aesGCMDecrypt(oldKEK, t.SecretKey)
		if err != nil {
			if _, errNew := aesGCMDecrypt(newKEK, t.SecretKey); errNew == nil {
				return false, nil // already under the new secret
			}
			return false, fmt.Errorf("rekey: token %s decrypts under neither the old nor the new "+
				"secret; nothing was rekeyed: %w", t.TokenID, err)
		}
		enc, err := aesGCMEncrypt(newKEK, plain)
		if err != nil {
			return false, fmt.Errorf("rekey: encrypt token %s: %w", t.TokenID, err)
		}
		t.SecretKey = enc
		return true, nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// MigrateTokenSecrets scans the tokens bucket and re-encrypts any token where
// SecretKey is stored as plaintext (no "enc:v1:" prefix). Returns the number
// of tokens migrated. Idempotent — already-encrypted entries are skipped.
func (db *DB) MigrateTokenSecrets() (migrated int, err error) {
	return db.resecretTokens(func(t *Token) (bool, error) {
		if t.SecretKey == "" || strings.HasPrefix(t.SecretKey, encryptedPrefix) {
			return false, nil
		}
		enc, err := db.encryptSecret(t.SecretKey)
		if err != nil {
			return false, err
		}
		t.SecretKey = enc
		return true, nil
	})
}

// resecretTokens is the shared core of RekeyTokens and MigrateTokenSecrets: it
// scans the token bucket in a read transaction, lets rewrite decide which ones
// to touch and how, and writes every affected one back in a SINGLE write
// transaction (all or nothing).
//
// The scan gets its own transaction: re-encrypting is AES-GCM per token, and
// bbolt has one writer, so that CPU work must not run under the write lock.
func (db *DB) resecretTokens(rewrite func(*Token) (bool, error)) (int, error) {
	type pending struct {
		id   string
		data []byte
	}
	var toUpdate []pending

	err := db.bolt.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketTokens)
		if bk == nil {
			return nil
		}
		return bk.ForEach(func(k, v []byte) error {
			var t Token
			if err := jsonv2.Unmarshal(v, &t, jsonx.Wire); err != nil {
				db.reportDecodeFailure(bucketTokens, string(k), err)
				return nil
			}
			changed, err := rewrite(&t)
			if err != nil {
				return err
			}
			if !changed {
				return nil
			}
			data, err := jsonv2.Marshal(&t, jsonx.Wire)
			if err != nil {
				return fmt.Errorf("meta: encode token %s: %w", t.TokenID, err)
			}
			toUpdate = append(toUpdate, pending{id: t.TokenID, data: data})
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	if len(toUpdate) == 0 {
		return 0, nil
	}

	err = db.bolt.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketTokens)
		if bk == nil {
			return fmt.Errorf("meta: bbolt bucket %s missing", bucketTokens)
		}
		for _, p := range toUpdate {
			if err := bk.Put([]byte(p.id), p.data); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("meta: write re-encrypted tokens: %w", err)
	}
	return len(toUpdate), nil
}
