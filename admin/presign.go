package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// maxPresignExpiry is the maximum allowed expiration duration for presigned URLs (7 days).
const maxPresignExpiry = 7 * 24 * time.Hour

func generateAdminPresignedURL(signingSecret, host, tokenID, method, path string, expires time.Duration, tlsEnabled bool) (string, error) {
	if signingSecret == "" {
		return "", fmt.Errorf("signing secret not configured")
	}
	if tokenID == "" {
		return "", fmt.Errorf("token_id is required")
	}
	if path == "" || path[0] != '/' {
		return "", fmt.Errorf("path must start with /")
	}
	if expires > maxPresignExpiry {
		return "", fmt.Errorf("expiration exceeds maximum of %d seconds", int(maxPresignExpiry.Seconds()))
	}

	expiresAt := time.Now().Add(expires).Unix()
	expiresStr := strconv.FormatInt(expiresAt, 10)

	// Admin-generated URLs have no extra query params; canonical query is empty.
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte(tokenID + "\n" + method + "\n" + path + "\n" + "\n" + expiresStr))
	sig := hex.EncodeToString(mac.Sum(nil))

	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
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
