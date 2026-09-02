package auth

// AWS Signature Version 4 in its query-string form — what every S3 client calls
// a "presigned URL": boto3's generate_presigned_url, `aws s3 presign`,
// minio-go's PresignedGetObject, the AWS SDKs' request presigners.
//
// It is the same algorithm as the Authorization-header form in sigv4.go. The
// only differences are where the inputs come from (query parameters instead of
// a header) and two rules of the canonical request:
//
//   - X-Amz-Signature is excluded from the signed query string. It is the
//     output of the calculation, so it cannot be an input to it.
//   - The payload hash is UNSIGNED-PAYLOAD, because whoever mints the URL does
//     not have the body. It is only the declared x-amz-content-sha256 when the
//     signer explicitly listed that header in X-Amz-SignedHeaders.
//
// Everything else — canonical URI, canonical query normalisation, canonical
// headers, string-to-sign, signing key derivation — is shared with the header
// form on purpose. A second copy would drift.

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ivangsm/jay/meta"
)

const (
	// sigV4Algorithm is the only algorithm jay signs and verifies.
	sigV4Algorithm = "AWS4-HMAC-SHA256"
	// sigV4Service is the service name baked into the credential scope. jay is
	// an S3 endpoint, so a credential scoped to anything else is not for us.
	sigV4Service = "s3"
	// sigV4Terminator closes the credential scope.
	sigV4Terminator = "aws4_request"
	// amzDateFormat is the ISO 8601 basic format X-Amz-Date uses.
	amzDateFormat = "20060102T150405Z"
	// amzDateStampFormat is the date portion of the credential scope.
	amzDateStampFormat = "20060102"
)

// MaxPresignExpiry is the ceiling for X-Amz-Expires, matching AWS's own limit
// of seven days.
//
// It is not decoration: a presigned URL carries its own authority, so a URL
// whose expiry never arrives is a permanent credential that no token
// revocation was asked about. Every URL jay accepts has a deadline, and every
// URL jay mints has one too.
const MaxPresignExpiry = 7 * 24 * time.Hour

// presignParamNames are the six query parameters that carry a query-string
// signature, in the order presignParams stores them.
var presignParamNames = [...]string{
	"X-Amz-Algorithm",
	"X-Amz-Credential",
	"X-Amz-Date",
	"X-Amz-Expires",
	"X-Amz-SignedHeaders",
	"X-Amz-Signature",
}

// presignParams holds the six parameters after extraction.
type presignParams struct {
	algorithm     string
	credential    string
	date          string
	expires       string
	signedHeaders string
	signature     string
}

// IsPresignedSigV4 reports whether r carries a SigV4 query-string signature and
// should be authenticated as a presigned URL.
//
// A request that also carries an Authorization header is deliberately NOT one:
// the header form takes precedence in S3, and accepting either would let a
// caller attach two credentials and have jay pick whichever one verifies.
func IsPresignedSigV4(r *http.Request) bool {
	if r.Header.Get("Authorization") != "" {
		return false
	}
	for key := range r.URL.Query() {
		if strings.EqualFold(key, "X-Amz-Signature") {
			return true
		}
	}
	return false
}

// AuthenticatePresignedSigV4 validates a SigV4 presigned URL and returns the
// token it was signed with.
//
// The returned token is the one whose secret produced the signature, so the
// caller's normal Authorize/AuthorizeWithPolicy checks still decide what the
// request may do: a presigned URL can never reach past the scope (actions,
// buckets, prefixes) of the token that signed it.
func (a *Auth) AuthenticatePresignedSigV4(r *http.Request) (*meta.Token, error) {
	q := r.URL.Query()

	p, err := extractPresignParams(q)
	if err != nil {
		return nil, err
	}
	if p.algorithm != sigV4Algorithm {
		return nil, fmt.Errorf("%w: unsupported presign algorithm", ErrInvalidCredentials)
	}

	accessKey, dateStamp, region, err := parsePresignCredential(p.credential)
	if err != nil {
		return nil, err
	}

	signedAt, err := time.Parse(amzDateFormat, p.date)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed X-Amz-Date", ErrInvalidCredentials)
	}
	if dateStamp != signedAt.UTC().Format(amzDateStampFormat) {
		return nil, fmt.Errorf("%w: credential scope date does not match X-Amz-Date", ErrInvalidCredentials)
	}

	// The expiry is checked before anything touches the database: an expired
	// URL is not a reason to do work.
	if err := checkPresignWindow(signedAt, p.expires, time.Now()); err != nil {
		return nil, err
	}

	signed := parseSignedHeaders(p.signedHeaders)
	// host must be signed. Without it a URL minted for one endpoint replays
	// against any other endpoint that shares the token — including one an
	// attacker controls the DNS for.
	if !slices.Contains(signed, "host") {
		return nil, fmt.Errorf("%w: X-Amz-SignedHeaders must cover host", ErrInvalidCredentials)
	}
	// Every declared header has to actually be on the request. A header that is
	// declared but absent signs as empty, which would let a signature made over
	// "no such header" pass for a request that was supposed to carry one.
	for _, h := range signed {
		if h == "host" {
			continue
		}
		if _, ok := r.Header[http.CanonicalHeaderKey(h)]; !ok {
			return nil, fmt.Errorf("%w: signed header %q is missing from the request", ErrInvalidCredentials, h)
		}
	}

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
	// SigV4 needs the plaintext secret to recompute the HMAC. Without it the
	// signature cannot be verified, and "cannot verify" is a rejection.
	if token.SecretKey == "" {
		return nil, ErrInvalidCredentials
	}

	// UNSIGNED-PAYLOAD unless the signer said otherwise by listing
	// x-amz-content-sha256 among the signed headers.
	payloadHash := unsignedPayload
	if slices.Contains(signed, "x-amz-content-sha256") {
		payloadHash = r.Header.Get("x-amz-content-sha256")
	}

	canonicalRequest := buildCanonicalRequestFrom(r, p.signedHeaders, stripSignatureParam(r.URL.RawQuery), payloadHash)
	stringToSign := buildStringToSign(dateStamp, p.date, region, canonicalRequest)
	signingKey := deriveSigningKey(token.SecretKey, dateStamp, region, sigV4Service)
	expectedSig := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	// Constant-time comparison to prevent timing attacks.
	if !hmac.Equal([]byte(expectedSig), []byte(p.signature)) {
		return nil, ErrInvalidCredentials
	}

	// A signed payload hash is a promise about the body; check it, same as the
	// header form does. Only reached after the signature verified, so an
	// unauthenticated caller can never make jay buffer a body.
	//
	// Called unconditionally: verifyPayloadHash skips UNSIGNED-PAYLOAD on its
	// own, and it is also where an aws-chunked body is refused — a presigned
	// PUT can carry the framing just as a header-signed one can, and guarding
	// the call with `payloadHash != unsignedPayload` left that door open.
	if err := verifyPayloadHash(r, payloadHash); err != nil {
		return nil, err
	}

	if err := a.checkAccountActive(token.AccountID); err != nil {
		return nil, err
	}

	return token, nil
}

// checkPresignWindow enforces the two halves of a presigned URL's lifetime: the
// signing time must not be in the future beyond the tolerated clock skew, and
// now must fall before signing time + X-Amz-Expires.
func checkPresignWindow(signedAt time.Time, expiresParam string, now time.Time) error {
	expiresSecs, err := strconv.ParseInt(expiresParam, 10, 64)
	if err != nil || expiresSecs <= 0 {
		return fmt.Errorf("%w: invalid X-Amz-Expires", ErrInvalidCredentials)
	}
	expires := time.Duration(expiresSecs) * time.Second
	if expires > MaxPresignExpiry {
		return fmt.Errorf("%w: X-Amz-Expires exceeds the maximum of %d seconds",
			ErrInvalidCredentials, int64(MaxPresignExpiry.Seconds()))
	}
	if signedAt.After(now.Add(maxClockSkew)) {
		return fmt.Errorf("%w: presigned URL is dated in the future", ErrInvalidCredentials)
	}
	if now.After(signedAt.Add(expires)) {
		return fmt.Errorf("%w: presigned URL has expired", ErrInvalidCredentials)
	}
	return nil
}

// parseSignedHeaders splits X-Amz-SignedHeaders into lowercased names.
func parseSignedHeaders(list string) []string {
	if list == "" {
		return nil
	}
	names := strings.Split(list, ";")
	for i, n := range names {
		names[i] = strings.ToLower(strings.TrimSpace(n))
	}
	return names
}

// extractPresignParams pulls the six presign parameters out of the query.
func extractPresignParams(q url.Values) (presignParams, error) {
	var p presignParams
	dst := [...]*string{&p.algorithm, &p.credential, &p.date, &p.expires, &p.signedHeaders, &p.signature}
	for i, name := range presignParamNames {
		v, err := lookupPresignParam(q, name)
		if err != nil {
			return p, err
		}
		if v == "" {
			return p, fmt.Errorf("%w: missing %s", ErrInvalidCredentials, name)
		}
		*dst[i] = v
	}
	return p, nil
}

// lookupPresignParam finds one presign parameter case-insensitively and refuses
// to guess when it appears more than once.
//
// Two spellings of X-Amz-Expires (or two values of it) would let a URL show one
// deadline to whoever reads it and hand a different one to the verifier, so a
// duplicate is a rejection rather than a first-one-wins.
func lookupPresignParam(q url.Values, name string) (string, error) {
	found := ""
	seen := 0
	for key, values := range q {
		if !strings.EqualFold(key, name) {
			continue
		}
		seen += len(values)
		if len(values) > 0 && found == "" {
			found = values[0]
		}
	}
	if seen > 1 {
		return "", fmt.Errorf("%w: %s appears more than once", ErrInvalidCredentials, name)
	}
	return found, nil
}

// parsePresignCredential splits X-Amz-Credential into access key and scope.
// Format: <access-key>/<yyyymmdd>/<region>/s3/aws4_request
func parsePresignCredential(credential string) (accessKey, dateStamp, region string, err error) {
	parts := strings.Split(credential, "/")
	if len(parts) != 5 {
		return "", "", "", fmt.Errorf("%w: malformed X-Amz-Credential", ErrInvalidCredentials)
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", fmt.Errorf("%w: malformed X-Amz-Credential", ErrInvalidCredentials)
	}
	if parts[3] != sigV4Service || parts[4] != sigV4Terminator {
		return "", "", "", fmt.Errorf("%w: credential scope is not %s/%s", ErrInvalidCredentials, sigV4Service, sigV4Terminator)
	}
	return parts[0], parts[1], parts[2], nil
}

// stripSignatureParam removes X-Amz-Signature from a raw query string, leaving
// every other parameter byte-for-byte as it arrived. It works on the raw string
// rather than on url.Values so that no re-encoding step can change what gets
// canonicalised.
func stripSignatureParam(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	var kept []string
	for part := range strings.SplitSeq(rawQuery, "&") {
		if part == "" {
			continue
		}
		rawKey, _, _ := strings.Cut(part, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			key = rawKey
		}
		if strings.EqualFold(key, "X-Amz-Signature") {
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "&")
}

// PresignInput describes one query-string signature to mint.
//
// Host is not cosmetic: the signature covers it, so a URL signed for a host the
// client will not send is a URL that can never verify.
type PresignInput struct {
	AccessKeyID string        // token id, used as the SigV4 access key
	SecretKey   string        // token secret in the clear, used for the HMAC
	Region      string        // any value, as long as it is the one in the URL
	Method      string        // GET, PUT, HEAD, DELETE…
	Host        string        // the Host header the client will send
	Path        string        // "/bucket/key", unescaped
	Expires     time.Duration // how long the URL stays valid
	Now         time.Time     // signing time; zero means time.Now()
}

// PresignQuery returns the signed query string for a SigV4 presigned URL,
// without the leading "?".
//
// The returned string is already in canonical order and RFC 3986 encoded, so a
// caller can hand it to url.URL.RawQuery verbatim and the URL it prints is the
// URL that was signed.
func PresignQuery(in PresignInput) (string, error) {
	switch {
	case in.AccessKeyID == "":
		return "", errors.New("auth: presign requires an access key id")
	case in.SecretKey == "":
		// Never emit a URL that cannot have been signed. A token whose secret
		// is unreadable produces no presigned URL, not an unsigned one.
		return "", errors.New("auth: presign requires the token secret in the clear")
	case in.Region == "":
		return "", errors.New("auth: presign requires a region")
	case in.Method == "":
		return "", errors.New("auth: presign requires an HTTP method")
	case in.Host == "":
		return "", errors.New("auth: presign requires a host, because the signature covers it")
	case in.Path == "" || in.Path[0] != '/':
		return "", errors.New("auth: presign path must start with /")
	case in.Expires <= 0:
		return "", errors.New("auth: presign expiry must be positive")
	case in.Expires > MaxPresignExpiry:
		return "", fmt.Errorf("auth: presign expiry exceeds the maximum of %d seconds",
			int64(MaxPresignExpiry.Seconds()))
	}

	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	amzDate := now.Format(amzDateFormat)
	dateStamp := now.Format(amzDateStampFormat)

	values := url.Values{}
	values.Set("X-Amz-Algorithm", sigV4Algorithm)
	values.Set("X-Amz-Credential", strings.Join([]string{
		in.AccessKeyID, dateStamp, in.Region, sigV4Service, sigV4Terminator,
	}, "/"))
	values.Set("X-Amz-Date", amzDate)
	values.Set("X-Amz-Expires", strconv.FormatInt(int64(in.Expires.Seconds()), 10))
	values.Set("X-Amz-SignedHeaders", "host")

	// Emit exactly the canonical form, so the query in the URL and the query in
	// the canonical request are the same bytes.
	rawQuery := canonicalQueryString(values.Encode())

	method := strings.ToUpper(in.Method)
	req := &http.Request{
		Method: method,
		URL:    &url.URL{Path: in.Path, RawQuery: rawQuery},
		Host:   in.Host,
		Header: make(http.Header),
	}
	canonicalRequest := buildCanonicalRequestFrom(req, "host", rawQuery, unsignedPayload)
	stringToSign := buildStringToSign(dateStamp, amzDate, in.Region, canonicalRequest)
	signingKey := deriveSigningKey(in.SecretKey, dateStamp, in.Region, sigV4Service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	return rawQuery + "&X-Amz-Signature=" + signature, nil
}
