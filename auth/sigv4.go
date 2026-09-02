package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ivangsm/jay/meta"
)

// maxClockSkew is the maximum allowed time difference between client and server.
const maxClockSkew = 15 * time.Minute

// unsignedPayload is the placeholder S3 clients put in the canonical request
// when the body is not covered by the signature. It is the default for
// presigned URLs, where there is no opportunity to hash the body up front.
const unsignedPayload = "UNSIGNED-PAYLOAD"

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

	// The signature only covers the *declared* payload hash. Without checking
	// that the body actually hashes to it, anyone replaying a captured request
	// (or a MITM) could swap the body and keep the signature valid. Done after
	// the signature check so an unauthenticated caller can never make us buffer
	// a body.
	if err := verifyPayloadHash(r, r.Header.Get("x-amz-content-sha256")); err != nil {
		return nil, err
	}

	// Verify account
	if err := a.checkAccountActive(token.AccountID); err != nil {
		return nil, err
	}

	return token, nil
}

// maxSignedPayloadSize bounds how much request body we are willing to buffer in
// order to verify x-amz-content-sha256. Signing a payload requires hashing it
// end-to-end anyway, so real S3 clients switch to UNSIGNED-PAYLOAD or multipart
// well below this. A request that declares a signed payload larger than this is
// rejected rather than buffered.
const maxSignedPayloadSize = 32 << 20 // 32 MiB

// verifyPayloadHash checks that the request body actually hashes to the value
// declared in x-amz-content-sha256, and leaves the body readable by handlers.
//
// An aws-chunked body is refused outright, whatever the declared hash says:
// jay cannot decode the framing, so there is nothing here that could verify it.
// This used to be a *skip* — STREAMING-* returned nil "because chunk signatures
// carry their own integrity" — and since nothing downstream decoded the framing
// either, the framing itself was stored as the object body under a 200.
//
// Verification is skipped, honestly, for UNSIGNED-PAYLOAD and for an absent
// header, which the canonical request already treats as UNSIGNED-PAYLOAD.
func verifyPayloadHash(r *http.Request, declared string) error {
	if hdr := ChunkedBodyIndicator(r); hdr != "" {
		return fmt.Errorf("%w: announced by %s", ErrChunkedBodyUnsupported, hdr)
	}

	if declared == "" || declared == unsignedPayload {
		return nil
	}

	if r.ContentLength > maxSignedPayloadSize {
		return fmt.Errorf("%w: signed payload exceeds %d bytes, use UNSIGNED-PAYLOAD or multipart",
			ErrInvalidCredentials, maxSignedPayloadSize)
	}

	var body []byte
	if r.Body != nil {
		var err error
		// +1 so an over-sized body with an unknown/lying Content-Length is
		// detected instead of being silently truncated (and hashed wrong).
		body, err = io.ReadAll(io.LimitReader(r.Body, maxSignedPayloadSize+1))
		if err != nil {
			return ErrInvalidCredentials
		}
		if len(body) > maxSignedPayloadSize {
			return fmt.Errorf("%w: signed payload exceeds %d bytes, use UNSIGNED-PAYLOAD or multipart",
				ErrInvalidCredentials, maxSignedPayloadSize)
		}
	}

	// Hand the buffered body back to the handler chain.
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	sum := sha256.Sum256(body)
	actual := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(strings.ToLower(declared))) != 1 {
		return fmt.Errorf("%w: payload hash mismatch", ErrInvalidCredentials)
	}
	return nil
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

// buildCanonicalRequest derives the canonical request for the header form of
// SigV4, where the whole query string is signed and the payload hash comes from
// x-amz-content-sha256.
func buildCanonicalRequest(r *http.Request, signedHeaders string) string {
	payloadHash := r.Header.Get("x-amz-content-sha256")
	if payloadHash == "" {
		payloadHash = unsignedPayload
	}
	return buildCanonicalRequestFrom(r, signedHeaders, r.URL.RawQuery, payloadHash)
}

// buildCanonicalRequestFrom is the single implementation of the SigV4 canonical
// request, shared by the header form and the query-string (presigned) form.
//
// The two forms differ only in their inputs — a presigned URL excludes
// X-Amz-Signature from the query it signs and defaults to UNSIGNED-PAYLOAD — so
// they are passed in rather than recomputed. Two copies of this function is how
// the two forms start disagreeing about what a signature covers.
func buildCanonicalRequestFrom(r *http.Request, signedHeaders, rawQuery, payloadHash string) string {
	// HTTP method
	method := r.Method

	// Canonical URI — use EscapedPath per the AWS SigV4 spec so that
	// keys with special characters (spaces, unicode) are percent-encoded.
	uri := r.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}

	// Canonical query string — SigV4 requires it normalised (sorted, RFC 3986
	// percent-encoded), not the raw string as it arrived on the wire.
	queryString := canonicalQueryString(rawQuery)

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

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method, uri, queryString, canonHeaders.String(), signedHeadersLower, payloadHash)
}

// canonicalQueryString normalises a raw query string per the SigV4 spec:
// each parameter name and value is percent-encoded with RFC 3986 rules
// (unreserved characters kept, everything else %XX, uppercase hex), the pairs
// are sorted by encoded name and then by encoded value, and joined with "&".
// Parameters with no value are signed as "name=".
func canonicalQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}

	type pair struct{ key, val string }
	var pairs []pair

	for part := range strings.SplitSeq(rawQuery, "&") {
		if part == "" {
			continue
		}
		rawKey, rawVal, _ := strings.Cut(part, "=")
		// Decode first: the client may have used a different (but equivalent)
		// encoding than the one SigV4 mandates.
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			key = rawKey
		}
		val, err := url.QueryUnescape(rawVal)
		if err != nil {
			val = rawVal
		}
		pairs = append(pairs, pair{key: rfc3986Escape(key), val: rfc3986Escape(val)})
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key != pairs[j].key {
			return pairs[i].key < pairs[j].key
		}
		return pairs[i].val < pairs[j].val
	})

	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.key)
		b.WriteByte('=')
		b.WriteString(p.val)
	}
	return b.String()
}

// rfc3986Escape percent-encodes s per RFC 3986: A-Z a-z 0-9 - _ . ~ are left
// as-is, every other byte becomes %XX with uppercase hex. Unlike
// url.QueryEscape it does NOT encode spaces as "+".
func rfc3986Escape(s string) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&0x0f])
		}
	}
	return b.String()
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
