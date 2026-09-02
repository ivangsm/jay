package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ivangsm/jay/auth"
)

// maxPresignExpiry is the maximum allowed expiration duration for presigned
// URLs (7 days). It is auth's ceiling, not a second one: the verifier and the
// issuer disagreeing about the limit would mean minting URLs jay refuses.
const maxPresignExpiry = auth.MaxPresignExpiry

// The two forms /_jay/presign can emit.
const (
	// presignStyleJay is jay's own X-Jay-* form, signed with the server
	// signing secret.
	presignStyleJay = "jay"
	// presignStyleAWS is SigV4 in its query-string form, signed with the
	// token's own secret — what boto3, the AWS SDKs, minio-go and
	// `aws s3 presign` produce and consume.
	presignStyleAWS = "aws"
)

// defaultPresignRegion is the credential-scope region used when the caller does
// not name one.
//
// jay has no notion of regions: the region is an input to the signing-key
// derivation and nothing else, so any value works as long as the URL and the
// verifier agree — and they do, because the verifier reads it back out of
// X-Amz-Credential. us-east-1 is what S3 clients default to.
const defaultPresignRegion = "us-east-1"

// generateAWSPresignedURL builds a SigV4 query-string presigned URL for one S3
// operation, signed with the token's own secret key.
//
// Unlike the jay form, the signature covers the host, so host must be the one
// the client will actually send. A URL signed against ":9000" can never verify,
// which is why the caller has to run it through requirePresignHostname first.
func generateAWSPresignedURL(secretKey, scheme, host, tokenID, region, method, path string, expires time.Duration) (string, error) {
	query, err := auth.PresignQuery(auth.PresignInput{
		AccessKeyID: tokenID,
		SecretKey:   secretKey,
		Region:      region,
		Method:      method,
		Host:        host,
		Path:        path,
		Expires:     expires,
	})
	if err != nil {
		return "", err
	}

	u := url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     path,
		RawQuery: query,
	}
	return u.String(), nil
}

// resolvePresignHost picks the host that goes into a presigned URL: the one the
// caller asked for, falling back to the server's own listen address.
func resolvePresignHost(requested, listenAddr string) string {
	if host := strings.TrimSpace(requested); host != "" {
		return host
	}
	return strings.TrimSpace(listenAddr)
}

// requirePresignHostname refuses a host the SigV4 form cannot be signed
// against.
//
// The AWS form covers the host in its signature, and a listen address like
// ":9000" has no hostname: signing against it produces a URL that verifies
// nowhere. An error naming the missing piece is the honest answer, not a URL
// that looks fine and 403s forever. The jay form does not sign the host, so it
// never calls this.
func requirePresignHostname(host string) error {
	if host == "" {
		return errors.New(`"host" is required: the server has no listen address to derive one from`)
	}
	if h, _, err := net.SplitHostPort(host); err == nil && h == "" {
		return fmt.Errorf(`"host" is required: %q has no hostname and the SigV4 signature covers it`, host)
	}
	return nil
}

// generateAdminPresignedURL builds a signed URL for one admin operation in
// jay's own X-Jay-* form.
//
// scheme is deployment configuration ("http" or "https"), threaded through
// rather than guessed: a URL handed out with the wrong scheme is a URL nobody
// can fetch.
func generateAdminPresignedURL(signingSecret, scheme, host, tokenID, method, path string, expires time.Duration) (string, error) {
	if signingSecret == "" {
		return "", errors.New("signing secret not configured")
	}
	if tokenID == "" {
		return "", errors.New("token_id is required")
	}
	if path == "" || path[0] != '/' {
		return "", errors.New("path must start with /")
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
