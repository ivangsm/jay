package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ivangsm/jay/meta"
)

// maxClockSkew is the maximum allowed time difference between client and server.
const maxClockSkew = 15 * time.Minute

// AuthenticateSigV4 validates AWS Signature V4 auth from an HTTP request.
// Format: AWS4-HMAC-SHA256 Credential=<access-key>/<date>/<region>/s3/aws4_request,
//
//	SignedHeaders=<headers>, Signature=<signature>
func (a *Auth) AuthenticateSigV4(r *http.Request) (*meta.Token, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		return nil, ErrInvalidCredentials
	}

	parts := parseSigV4Header(authHeader)
	if parts == nil {
		return nil, ErrInvalidCredentials
	}

	accessKey := parts["credential_key"]
	dateStr := parts["credential_date"]
	region := parts["credential_region"]
	signedHeadersStr := parts["signed_headers"]
	providedSig := parts["signature"]

	if accessKey == "" || providedSig == "" {
		return nil, ErrInvalidCredentials
	}

	// Look up token by ID (access key = token ID)
	token, err := a.db.GetToken(accessKey)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if token.Status == "revoked" {
		return nil, ErrTokenRevoked
	}
	if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Validate request timestamp to prevent replay attacks.
	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		amzDate = r.Header.Get("Date")
	}
	if err := validateTimestamp(amzDate, dateStr); err != nil {
		return nil, err
	}

	// SigV4 requires the plaintext secret for HMAC computation.
	if token.SecretKey == "" {
		return nil, ErrInvalidCredentials
	}

	// Compute the expected SigV4 signature using the plaintext secret.
	signingKey := deriveSigningKey(token.SecretKey, dateStr, region, "s3")
	canonicalRequest := buildCanonicalRequest(r, signedHeadersStr)
	stringToSign := buildStringToSign(dateStr, amzDate, region, canonicalRequest)
	expectedSig := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// Constant-time comparison to prevent timing attacks.
	if subtle.ConstantTimeCompare([]byte(expectedSig), []byte(providedSig)) != 1 {
		return nil, ErrInvalidCredentials
	}

	// Verify account
	account, err := a.db.GetAccount(token.AccountID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if account.Status != "active" {
		return nil, ErrAccessDenied
	}

	return token, nil
}

func parseSigV4Header(header string) map[string]string {
	header = strings.TrimPrefix(header, "AWS4-HMAC-SHA256 ")
	result := make(map[string]string)

	for part := range strings.SplitSeq(header, ",") {
		part = strings.TrimSpace(part)
		key, value, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		switch key {
		case "Credential":
			// Format: access-key/date/region/service/aws4_request
			credParts := strings.SplitN(value, "/", 5)
			if len(credParts) >= 4 {
				result["credential_key"] = credParts[0]
				result["credential_date"] = credParts[1]
				result["credential_region"] = credParts[2]
			}
		case "SignedHeaders":
			result["signed_headers"] = value
		case "Signature":
			result["signature"] = value
		}
	}
	return result
}

func buildCanonicalRequest(r *http.Request, signedHeaders string) string {
	// HTTP method
	method := r.Method

	// Canonical URI — use EscapedPath per the AWS SigV4 spec so that
	// keys with special characters (spaces, unicode) are percent-encoded.
	uri := r.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}

	// Canonical query string
	queryString := r.URL.RawQuery

	// Canonical headers — header names must be lowercased per SigV4 spec.
	headerNames := strings.Split(signedHeaders, ";")
	for i, h := range headerNames {
		headerNames[i] = strings.ToLower(strings.TrimSpace(h))
	}
	sort.Strings(headerNames)
	var canonHeaders strings.Builder
	for _, h := range headerNames {
		val := strings.TrimSpace(r.Header.Get(h))
		if h == "host" && val == "" {
			val = r.Host
		}
		canonHeaders.WriteString(h)
		canonHeaders.WriteString(":")
		canonHeaders.WriteString(val)
		canonHeaders.WriteString("\n")
	}

	// Signed headers list must also be lowercased.
	signedHeadersLower := strings.Join(headerNames, ";")

	// Payload hash
	payloadHash := r.Header.Get("x-amz-content-sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method, uri, queryString, canonHeaders.String(), signedHeadersLower, payloadHash)
}

func buildStringToSign(dateStr, amzDate, region, canonicalRequest string) string {
	hash := sha256.Sum256([]byte(canonicalRequest))
	return fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s/%s/s3/aws4_request\n%s",
		amzDate, dateStr, region, hex.EncodeToString(hash[:]))
}

func deriveSigningKey(secret, dateStr, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStr))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// validateTimestamp checks that the request timestamp is within ±15 minutes of
// current server time, preventing replay attacks.
func validateTimestamp(amzDate, credentialDate string) error {
	if amzDate == "" {
		return ErrInvalidCredentials
	}

	var reqTime time.Time
	var err error

	// Try ISO 8601 basic format (X-Amz-Date: 20130524T000000Z)
	reqTime, err = time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		// Try RFC 2616 / HTTP-date formats
		reqTime, err = time.Parse(time.RFC1123, amzDate)
		if err != nil {
			reqTime, err = time.Parse(time.RFC1123Z, amzDate)
			if err != nil {
				return ErrInvalidCredentials
			}
		}
	}

	// Also validate that the credential date matches the request date.
	if credentialDate != "" {
		expectedDate := reqTime.UTC().Format("20060102")
		if credentialDate != expectedDate {
			return ErrInvalidCredentials
		}
	}

	skew := time.Duration(math.Abs(float64(time.Since(reqTime))))
	if skew > maxClockSkew {
		return fmt.Errorf("%w: request timestamp is too far from server time", ErrInvalidCredentials)
	}

	return nil
}
