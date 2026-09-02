package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivangsm/jay/meta"
)

// jay's own presigned URL form, HMAC'd with the server signing secret.
//
// It predates SigV4 query-string support (auth/presign_sigv4.go) and is kept
// because falco and `jay-admin presign` emit it. The two live side by side:
// withPresigned dispatches on which parameters are present, and no request can
// carry both without the SigV4 branch claiming it.

// presignedMetaParams are query parameters used by the presigned URL mechanism
// and excluded from the canonical query string that is signed.
var presignedMetaParams = map[string]bool{
	"X-Jay-Token":     true,
	"X-Jay-Expires":   true,
	"X-Jay-Signature": true,
}

// Presigned URL query params:
// X-Jay-Token=<token_id>
// X-Jay-Expires=<unix_timestamp>
// X-Jay-Signature=HMAC-SHA256(signing_secret, token_id + "\n" + method + "\n" + path + "\n" + query + "\n" + expires)

func computeSignature(signingSecret, tokenID, method, path, query, expires string) string {
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte(tokenID + "\n" + method + "\n" + path + "\n" + query + "\n" + expires))
	return hex.EncodeToString(mac.Sum(nil))
}

// canonicalQuery builds a sorted query string from the given url.Values,
// excluding presigned-URL meta parameters (token, expires, signature).
func canonicalQuery(q url.Values) string {
	var keys []string
	for k := range q {
		if !presignedMetaParams[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func validatePresignedRequest(r *http.Request, signingSecret string, db *meta.DB) (*meta.Token, error) {
	q := r.URL.Query()
	tokenID := q.Get("X-Jay-Token")
	expiresStr := q.Get("X-Jay-Expires")
	signature := q.Get("X-Jay-Signature")

	if tokenID == "" || expiresStr == "" || signature == "" {
		return nil, errors.New("missing presigned URL parameters")
	}

	// Check expiry
	expiresUnix, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil {
		return nil, errors.New("invalid expires value")
	}
	if time.Now().Unix() > expiresUnix {
		return nil, errors.New("presigned URL has expired")
	}
	maxExpiry := time.Now().Unix() + int64((7 * 24 * time.Hour).Seconds())
	if expiresUnix > maxExpiry {
		return nil, errors.New("presigned URL expiry exceeds maximum of 7 days")
	}

	// Verify HMAC — include canonical query (excluding meta params) in signature
	cq := canonicalQuery(q)
	expected := computeSignature(signingSecret, tokenID, r.Method, r.URL.Path, cq, expiresStr)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return nil, errors.New("invalid signature")
	}

	// Load token from db
	token, err := db.GetToken(tokenID)
	if err != nil {
		return nil, errors.New("token not found")
	}
	if token.Status != "active" {
		return nil, errors.New("token is not active")
	}

	// Check token expiry
	if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
		return nil, errors.New("token has expired")
	}

	// Check account status
	account, err := db.GetAccount(token.AccountID)
	if err != nil {
		return nil, errors.New("account not found")
	}
	if account.Status != "active" {
		return nil, errors.New("account is not active")
	}

	return token, nil
}
