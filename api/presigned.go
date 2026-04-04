package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ivangsm/jay/meta"
)

// Presigned URL query params:
// X-Jay-Token=<token_id>
// X-Jay-Expires=<unix_timestamp>
// X-Jay-Signature=HMAC-SHA256(signing_secret, token_id + "\n" + method + "\n" + path + "\n" + expires)

func computeSignature(signingSecret, tokenID, method, path, expires string) string {
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte(tokenID + "\n" + method + "\n" + path + "\n" + expires))
	return hex.EncodeToString(mac.Sum(nil))
}

func generatePresignedURL(signingSecret, scheme, host, tokenID, method, path string, expires time.Duration) (string, error) {
	if signingSecret == "" {
		return "", fmt.Errorf("signing secret not configured")
	}
	if tokenID == "" {
		return "", fmt.Errorf("token_id is required")
	}
	if path == "" || path[0] != '/' {
		return "", fmt.Errorf("path must start with /")
	}

	expiresAt := time.Now().Add(expires).Unix()
	expiresStr := strconv.FormatInt(expiresAt, 10)

	sig := computeSignature(signingSecret, tokenID, method, path, expiresStr)

	u := url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   path,
	}
	q := u.Query()
	q.Set("X-Jay-Token", tokenID)
	q.Set("X-Jay-Expires", expiresStr)
	q.Set("X-Jay-Signature", sig)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func validatePresignedRequest(r *http.Request, signingSecret string, db *meta.DB) (*meta.Token, error) {
	q := r.URL.Query()
	tokenID := q.Get("X-Jay-Token")
	expiresStr := q.Get("X-Jay-Expires")
	signature := q.Get("X-Jay-Signature")

	if tokenID == "" || expiresStr == "" || signature == "" {
		return nil, fmt.Errorf("missing presigned URL parameters")
	}

	// Check expiry
	expiresUnix, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid expires value")
	}
	if time.Now().Unix() > expiresUnix {
		return nil, fmt.Errorf("presigned URL has expired")
	}

	// Verify HMAC
	expected := computeSignature(signingSecret, tokenID, r.Method, r.URL.Path, expiresStr)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Load token from db
	token, err := db.GetToken(tokenID)
	if err != nil {
		return nil, fmt.Errorf("token not found")
	}
	if token.Status != "active" {
		return nil, fmt.Errorf("token is not active")
	}

	return token, nil
}
