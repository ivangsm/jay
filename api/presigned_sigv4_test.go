package api

// End-to-end tests for SigV4 presigned URLs, signed by a signer that is NOT
// jay's.
//
// The signer below is written from the AWS Signature Version 4 specification —
// the URI-encoding rules, the canonical request layout, the string to sign and
// the four-round key derivation — and lives in package api, which cannot reach
// auth's unexported canonicalisation even by accident. Signing with the code
// under test would prove only that the code agrees with itself; a URL minted
// here is the same shape a third-party client (boto3, minio-go, the AWS SDKs,
// `aws s3 presign`) puts on the wire.
//
// jay pins itself to AWS's own published vectors separately, in
// auth/presign_sigv4_test.go.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/meta"
)

// ── An independent SigV4 query-string signer ───────────────────────────────

// awsURIEncode implements the URI-encode() the SigV4 spec defines: every byte
// except A-Z a-z 0-9 - . _ ~ becomes %XX with uppercase hex; a space is %20 and
// never "+"; the forward slash is left alone only inside an object key.
func awsURIEncode(s string, encodeSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte('/')
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
		}
	}
	return b.String()
}

func awsHMAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func awsSHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// presignSpec is one URL to mint.
type presignSpec struct {
	accessKey string
	secret    string
	region    string
	service   string
	method    string
	host      string
	path      string // unescaped, "/bucket/key"
	now       time.Time
	expires   time.Duration

	// extraQuery are non-presign parameters that are part of the signature,
	// like a ListObjectsV2 "prefix".
	extraQuery map[string]string
	// signedHeaders beyond host, lowercase.
	extraSignedHeaders []string
	// headerValues supplies the values of extraSignedHeaders on the request.
	headerValues map[string]string
	// omitHost drops host from SignedHeaders, which jay must refuse.
	omitHost bool
	// payloadHash overrides UNSIGNED-PAYLOAD.
	payloadHash string
}

func (s presignSpec) withDefaults() presignSpec {
	if s.region == "" {
		s.region = "us-east-1"
	}
	if s.service == "" {
		s.service = "s3"
	}
	if s.method == "" {
		s.method = http.MethodGet
	}
	if s.host == "" {
		s.host = "jay.test"
	}
	if s.now.IsZero() {
		s.now = time.Now().UTC()
	}
	if s.expires == 0 {
		s.expires = time.Hour
	}
	if s.payloadHash == "" {
		s.payloadHash = "UNSIGNED-PAYLOAD"
	}
	return s
}

// presignedTarget mints a presigned URL and returns it as an absolute URL.
func presignedTarget(t *testing.T, spec presignSpec) string {
	t.Helper()
	s := spec.withDefaults()

	amzDate := s.now.UTC().Format("20060102T150405Z")
	dateStamp := s.now.UTC().Format("20060102")
	scope := strings.Join([]string{dateStamp, s.region, s.service, "aws4_request"}, "/")

	signedHeaders := append([]string{}, s.extraSignedHeaders...)
	if !s.omitHost {
		signedHeaders = append(signedHeaders, "host")
	}
	sort.Strings(signedHeaders)

	query := map[string]string{
		"X-Amz-Algorithm":     "AWS4-HMAC-SHA256",
		"X-Amz-Credential":    s.accessKey + "/" + scope,
		"X-Amz-Date":          amzDate,
		"X-Amz-Expires":       strconv.FormatInt(int64(s.expires.Seconds()), 10),
		"X-Amz-SignedHeaders": strings.Join(signedHeaders, ";"),
	}
	for k, v := range s.extraQuery {
		query[k] = v
	}

	// Canonical query string: encode both halves, sort by encoded name.
	encoded := make([]string, 0, len(query))
	for k, v := range query {
		encoded = append(encoded, awsURIEncode(k, true)+"="+awsURIEncode(v, true))
	}
	sort.Strings(encoded)
	canonicalQuery := strings.Join(encoded, "&")

	// Canonical headers: lowercase name, trimmed value, one per line, sorted.
	var canonicalHeaders strings.Builder
	for _, h := range signedHeaders {
		value := s.host
		if h != "host" {
			value = s.headerValues[h]
		}
		canonicalHeaders.WriteString(h + ":" + strings.TrimSpace(value) + "\n")
	}

	canonicalURI := awsURIEncode(s.path, false)
	canonicalRequest := strings.Join([]string{
		s.method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders.String(),
		strings.Join(signedHeaders, ";"),
		s.payloadHash,
	}, "\n")

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		awsSHA256Hex(canonicalRequest),
	}, "\n")

	key := awsHMAC([]byte("AWS4"+s.secret), []byte(dateStamp))
	key = awsHMAC(key, []byte(s.region))
	key = awsHMAC(key, []byte(s.service))
	key = awsHMAC(key, []byte("aws4_request"))
	signature := hex.EncodeToString(awsHMAC(key, []byte(stringToSign)))

	return "http://" + s.host + canonicalURI + "?" + canonicalQuery + "&X-Amz-Signature=" + signature
}

// presignedRequest turns a minted URL into a server request, with no
// Authorization header — the whole point of a presigned URL.
func presignedRequest(t *testing.T, method, target string, body string, spec presignSpec) *http.Request {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	for h, v := range spec.headerValues {
		req.Header.Set(h, v)
	}
	return req
}

// ── Fixtures ───────────────────────────────────────────────────────────────

// presignSetup returns a handler with a bucket, an object, and a full-access
// token whose secret can sign.
func presignSetup(t *testing.T) (*Handler, *meta.DB, *meta.Token, string) {
	t.Helper()
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "presign-bucket")
	putObjectForTest(t, h, tok, secret, "presign-bucket", "hello.txt", "hola")
	return h, db, tok, secret
}

// putObjectEscaped stores an object whose key needs percent-encoding to travel
// in a request line. The shared putObjectForTest concatenates the key raw,
// which is fine for the keys it is used with and panics on a space.
func putObjectEscaped(t *testing.T, h *Handler, tok *meta.Token, secret, bucket, key, body string) {
	t.Helper()
	target := "http://jay.test/" + bucket + "/" + awsURIEncode(key, false)
	req := httptest.NewRequest(http.MethodPut, target, strings.NewReader(body))
	req.Header.Set("Authorization", authHeader(tok, secret))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("put %s/%s: want 200, got %d: %s", bucket, key, w.Code, w.Body.String())
	}
}

func scopedToken(t *testing.T, db *meta.DB, accountID, id string, actions, bucketScope, prefixScope []string) (*meta.Token, string) {
	t.Helper()
	secret := "scoped-secret-" + id
	hash, err := auth.HashSecret(secret)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	tok := &meta.Token{
		TokenID:        id,
		AccountID:      accountID,
		Name:           id,
		SecretHash:     hash,
		SecretKey:      secret,
		AllowedActions: actions,
		BucketScope:    bucketScope,
		PrefixScope:    prefixScope,
		Status:         "active",
	}
	if err := db.CreateToken(tok); err != nil {
		t.Fatalf("create token: %v", err)
	}
	return tok, secret
}

// ── Accepted ───────────────────────────────────────────────────────────────

func TestPresignedSigV4_GetObject_Accepted(t *testing.T) {
	h, _, tok, secret := presignSetup(t)

	spec := presignSpec{accessKey: tok.TokenID, secret: secret, path: "/presign-bucket/hello.txt"}
	target := presignedTarget(t, spec)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, presignedRequest(t, http.MethodGet, target, "", spec))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "hola" {
		t.Fatalf("body = %q, want %q", got, "hola")
	}
}

func TestPresignedSigV4_PutObject_StoresTheBytes(t *testing.T) {
	h, db, tok, secret := presignSetup(t)

	spec := presignSpec{
		accessKey: tok.TokenID, secret: secret,
		method: http.MethodPut, path: "/presign-bucket/uploaded.txt",
	}
	target := presignedTarget(t, spec)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, presignedRequest(t, http.MethodPut, target, "subido por URL firmada", spec))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	// The assertion is the object on disk, not the status line: a PUT that
	// answers 200 without storing anything is exactly the failure this repo
	// forbids.
	_, obj, err := db.GetBucketAndObject("presign-bucket", "uploaded.txt")
	if err != nil {
		t.Fatalf("object was not stored: %v", err)
	}
	if obj.SizeBytes != int64(len("subido por URL firmada")) {
		t.Fatalf("stored size = %d, want %d", obj.SizeBytes, len("subido por URL firmada"))
	}
}

func TestPresignedSigV4_HeadObject_Accepted(t *testing.T) {
	h, _, tok, secret := presignSetup(t)

	spec := presignSpec{
		accessKey: tok.TokenID, secret: secret,
		method: http.MethodHead, path: "/presign-bucket/hello.txt",
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, presignedRequest(t, http.MethodHead, presignedTarget(t, spec), "", spec))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPresignedSigV4_KeyWithSpecialCharacters_Accepted(t *testing.T) {
	h, db, tok, secret := presignSetup(t)

	// Every one of these is encoded differently by SigV4's URI-encode and by
	// Go's default path escaping, so they are where a canonical-URI bug shows.
	keys := []string{
		"carpeta/archivo con espacios.txt",
		"a+b.txt",
		"precio=100&x.txt",
		"acentuado-ñá.txt",
		"tilde~y.punto.txt",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			putObjectEscaped(t, h, tok, secret, "presign-bucket", key, "contenido")

			spec := presignSpec{accessKey: tok.TokenID, secret: secret, path: "/presign-bucket/" + key}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, presignedRequest(t, http.MethodGet, presignedTarget(t, spec), "", spec))

			if w.Code != http.StatusOK {
				t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
			}
			if w.Body.String() != "contenido" {
				t.Fatalf("body = %q", w.Body.String())
			}
			_ = db
		})
	}
}

func TestPresignedSigV4_ListObjects_WithSignedQueryParams_Accepted(t *testing.T) {
	h, _, tok, secret := presignSetup(t)
	putObjectForTest(t, h, tok, secret, "presign-bucket", "fotos/a.txt", "a")

	spec := presignSpec{
		accessKey: tok.TokenID, secret: secret,
		path:       "/presign-bucket",
		extraQuery: map[string]string{"list-type": "2", "prefix": "fotos/"},
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, presignedRequest(t, http.MethodGet, presignedTarget(t, spec), "", spec))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "fotos/a.txt") {
		t.Fatalf("listing did not include the object: %s", w.Body.String())
	}
}

func TestPresignedSigV4_SignedContentHash_Accepted(t *testing.T) {
	h, _, tok, secret := presignSetup(t)

	body := "cuerpo firmado"
	spec := presignSpec{
		accessKey: tok.TokenID, secret: secret,
		method: http.MethodPut, path: "/presign-bucket/signed-body.txt",
		extraSignedHeaders: []string{"x-amz-content-sha256"},
		headerValues:       map[string]string{"x-amz-content-sha256": awsSHA256Hex(body)},
		payloadHash:        awsSHA256Hex(body),
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, presignedRequest(t, http.MethodPut, presignedTarget(t, spec), body, spec))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ── Rejected ───────────────────────────────────────────────────────────────

func TestPresignedSigV4_SignedContentHash_BodySwapped_Rejected(t *testing.T) {
	h, _, tok, secret := presignSetup(t)

	spec := presignSpec{
		accessKey: tok.TokenID, secret: secret,
		method: http.MethodPut, path: "/presign-bucket/swapped.txt",
		extraSignedHeaders: []string{"x-amz-content-sha256"},
		headerValues:       map[string]string{"x-amz-content-sha256": awsSHA256Hex("lo prometido")},
		payloadHash:        awsSHA256Hex("lo prometido"),
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, presignedRequest(t, http.MethodPut, presignedTarget(t, spec), "otra cosa", spec))

	if w.Code != http.StatusForbidden {
		t.Fatalf("a body that does not match the signed hash must be refused, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPresignedSigV4_Rejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(spec *presignSpec)
		// tamper rewrites the minted URL after signing.
		tamper func(target string) string
	}{
		{
			name:   "expired",
			mutate: func(s *presignSpec) { s.now = time.Now().Add(-2 * time.Hour); s.expires = time.Hour },
		},
		{
			name:   "expiry beyond seven days",
			mutate: func(s *presignSpec) { s.expires = 8 * 24 * time.Hour },
		},
		{
			name:   "dated past the clock skew",
			mutate: func(s *presignSpec) { s.now = time.Now().Add(time.Hour) },
		},
		{
			name:   "host not among the signed headers",
			mutate: func(s *presignSpec) { s.omitHost = true },
		},
		{
			name:   "signed with the wrong secret",
			mutate: func(s *presignSpec) { s.secret = "not-the-token-secret" },
		},
		{
			name:   "unknown access key",
			mutate: func(s *presignSpec) { s.accessKey = "no-such-token" },
		},
		{
			name:   "credential scoped to another service",
			mutate: func(s *presignSpec) { s.service = "iam" },
		},
		{
			name:   "signature altered",
			tamper: func(target string) string { return flipLastHexDigit(target) },
		},
		{
			name: "path swapped after signing",
			tamper: func(target string) string {
				return strings.Replace(target, "/hello.txt?", "/otro.txt?", 1)
			},
		},
		{
			name: "query parameter appended after signing",
			tamper: func(target string) string {
				return target + "&response-content-type=text%2Fhtml"
			},
		},
		{
			name: "expiry stretched after signing",
			tamper: func(target string) string {
				return strings.Replace(target, "X-Amz-Expires=3600", "X-Amz-Expires=604800", 1)
			},
		},
		{
			name: "signature parameter duplicated",
			tamper: func(target string) string {
				return target + "&X-Amz-Signature=" + strings.Repeat("0", 64)
			},
		},
		{
			name: "algorithm downgraded",
			tamper: func(target string) string {
				return strings.Replace(target, "X-Amz-Algorithm=AWS4-HMAC-SHA256", "X-Amz-Algorithm=AWS4-HMAC-SHA1", 1)
			},
		},
		{
			name: "signature dropped",
			tamper: func(target string) string {
				i := strings.Index(target, "&X-Amz-Signature=")
				return target[:i]
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, _, tok, secret := presignSetup(t)

			spec := presignSpec{accessKey: tok.TokenID, secret: secret, path: "/presign-bucket/hello.txt"}
			if c.mutate != nil {
				c.mutate(&spec)
			}
			target := presignedTarget(t, spec)
			if c.tamper != nil {
				target = c.tamper(target)
			}

			w := httptest.NewRecorder()
			h.ServeHTTP(w, presignedRequest(t, http.MethodGet, target, "", spec))

			if w.Code != http.StatusForbidden {
				t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
			}
			// The object's bytes must not leak in the error body.
			if strings.Contains(w.Body.String(), "hola") {
				t.Fatalf("rejected request answered with object content: %s", w.Body.String())
			}
		})
	}
}

func flipLastHexDigit(target string) string {
	runes := []byte(target)
	last := runes[len(runes)-1]
	if last == '0' {
		last = '1'
	} else {
		last = '0'
	}
	runes[len(runes)-1] = last
	return string(runes)
}

// TestPresignedSigV4_HostNotCovered_Rejected is the case the table above cannot
// isolate: there, dropping host also empties SignedHeaders, so the signature
// fails for a second reason. Here the signer covers a real header and simply
// leaves host out, so both sides agree on the canonical request and the only
// thing left to refuse it is the rule that host must be signed. Without that
// rule a URL minted for one endpoint replays against any other.
func TestPresignedSigV4_HostNotCovered_Rejected(t *testing.T) {
	h, _, tok, secret := presignSetup(t)

	spec := presignSpec{
		accessKey: tok.TokenID, secret: secret, path: "/presign-bucket/hello.txt",
		omitHost:           true,
		extraSignedHeaders: []string{"x-amz-meta-marker"},
		headerValues:       map[string]string{"x-amz-meta-marker": "v"},
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, presignedRequest(t, http.MethodGet, presignedTarget(t, spec), "", spec))

	if w.Code != http.StatusForbidden {
		t.Fatalf("a signature that does not cover host must be refused, got %d: %s", w.Code, w.Body.String())
	}
}

// TestPresignedSigV4_DeclaredHeaderMissing_Rejected covers the mirror rule: a
// header named in SignedHeaders but absent from the request canonicalises as
// empty, so a signature made over "no such header" would pass for a request
// that was supposed to carry one.
func TestPresignedSigV4_DeclaredHeaderMissing_Rejected(t *testing.T) {
	h, _, tok, secret := presignSetup(t)

	spec := presignSpec{
		accessKey: tok.TokenID, secret: secret, path: "/presign-bucket/hello.txt",
		extraSignedHeaders: []string{"x-amz-meta-marker"},
		headerValues:       map[string]string{"x-amz-meta-marker": ""},
	}
	target := presignedTarget(t, spec)

	// Build the request WITHOUT the declared header.
	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("a declared-but-absent signed header must be refused, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPresignedSigV4_RevokedToken_Rejected(t *testing.T) {
	h, db, tok, secret := presignSetup(t)

	spec := presignSpec{accessKey: tok.TokenID, secret: secret, path: "/presign-bucket/hello.txt"}
	target := presignedTarget(t, spec)

	if err := db.RevokeToken(tok.TokenID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, presignedRequest(t, http.MethodGet, target, "", spec))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a URL signed before revocation must stop working, got %d", w.Code)
	}
}

// ── A presign cannot exceed the scope of the token that signed it ──────────

func TestPresignedSigV4_ActionOutsideTokenScope_Rejected(t *testing.T) {
	h, db, tok, _ := presignSetup(t)

	// This token may write but not read.
	writer, writerSecret := scopedToken(t, db, tok.AccountID, "writer-only",
		[]string{meta.ActionObjectPut}, nil, nil)

	spec := presignSpec{accessKey: writer.TokenID, secret: writerSecret, path: "/presign-bucket/hello.txt"}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, presignedRequest(t, http.MethodGet, presignedTarget(t, spec), "", spec))

	if w.Code != http.StatusForbidden {
		t.Fatalf("a presigned GET signed by a write-only token must be refused, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPresignedSigV4_BucketOutsideTokenScope_Rejected(t *testing.T) {
	h, db, tok, _ := presignSetup(t)
	createBucketForTest(t, db, tok.AccountID, "otro-bucket")

	scoped, scopedSecret := scopedToken(t, db, tok.AccountID, "bucket-scoped",
		meta.AllActions, []string{"otro-bucket"}, nil)

	spec := presignSpec{accessKey: scoped.TokenID, secret: scopedSecret, path: "/presign-bucket/hello.txt"}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, presignedRequest(t, http.MethodGet, presignedTarget(t, spec), "", spec))

	if w.Code != http.StatusForbidden {
		t.Fatalf("a presigned URL must not reach outside the token's bucket scope, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPresignedSigV4_PrefixOutsideTokenScope_Rejected(t *testing.T) {
	h, db, tok, secret := presignSetup(t)
	putObjectForTest(t, h, tok, secret, "presign-bucket", "privado/secreto.txt", "no")

	scoped, scopedSecret := scopedToken(t, db, tok.AccountID, "prefix-scoped",
		meta.AllActions, nil, []string{"publico/"})

	spec := presignSpec{accessKey: scoped.TokenID, secret: scopedSecret, path: "/presign-bucket/privado/secreto.txt"}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, presignedRequest(t, http.MethodGet, presignedTarget(t, spec), "", spec))

	if w.Code != http.StatusForbidden {
		t.Fatalf("a presigned URL must not reach outside the token's prefix scope, got %d: %s", w.Code, w.Body.String())
	}
}

// ── Coexistence with the other two credential forms ────────────────────────

func TestPresignedSigV4_AuthorizationHeaderWins(t *testing.T) {
	h, _, tok, secret := presignSetup(t)

	// A valid presigned URL, but the caller also attaches a bad bearer. The
	// header form takes precedence, so the request must be refused rather than
	// fall back to whichever credential happens to verify.
	spec := presignSpec{accessKey: tok.TokenID, secret: secret, path: "/presign-bucket/hello.txt"}
	req := presignedRequest(t, http.MethodGet, presignedTarget(t, spec), "", spec)
	req.Header.Set("Authorization", "Bearer "+tok.TokenID+":wrong-secret")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPresignedJay_StillWorksAlongsideSigV4(t *testing.T) {
	h, db, tok, secret := presignSetup(t)
	h.signingSecret = "server-signing-secret-at-least-32-chars"

	// jay's own form, built the way admin/presign.go builds it.
	expires := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	sig := computeSignature(h.signingSecret, tok.TokenID, http.MethodGet, "/presign-bucket/hello.txt", "", expires)
	target := fmt.Sprintf("http://jay.test/presign-bucket/hello.txt?X-Jay-Token=%s&X-Jay-Expires=%s&X-Jay-Signature=%s",
		tok.TokenID, expires, sig)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("the X-Jay-* form must keep working: got %d: %s", w.Code, w.Body.String())
	}
	_ = db
	_ = secret
}

// ── The URLs jay itself mints ──────────────────────────────────────────────

func TestPresignQuery_MintedByJay_IsAcceptedByJay(t *testing.T) {
	h, _, tok, secret := presignSetup(t)

	query, err := auth.PresignQuery(auth.PresignInput{
		AccessKeyID: tok.TokenID,
		SecretKey:   secret,
		Region:      "us-east-1",
		Method:      http.MethodGet,
		Host:        "jay.test",
		Path:        "/presign-bucket/hello.txt",
		Expires:     time.Hour,
	})
	if err != nil {
		t.Fatalf("PresignQuery: %v", err)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://jay.test/presign-bucket/hello.txt?"+query, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "hola" {
		t.Fatalf("body = %q", w.Body.String())
	}
}
