package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivangsm/jay/meta"
	"golang.org/x/crypto/bcrypt"
)

// ---- helpers ---------------------------------------------------------------

func openTestDB(t *testing.T) *meta.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := meta.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetSigningSecret("test-signing-secret-at-least-32-chars!!")
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedToken creates an account + token and returns both along with the plaintext secret.
func seedToken(t *testing.T, db *meta.DB, tokenID, secret string, actions []string) (*meta.Account, *meta.Token) {
	t.Helper()
	acc, _, err := db.CreateAccountIfNotExists("testaccount")
	if err != nil {
		t.Fatalf("CreateAccountIfNotExists: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	tok, _, err := db.CreateTokenIfNotExists(tokenID, acc.AccountID, "testtoken", string(hash), secret, actions)
	if err != nil {
		t.Fatalf("CreateTokenIfNotExists: %v", err)
	}
	return acc, tok
}

// newBearerRequest builds a GET request with a Bearer Authorization header.
func newBearerRequest(tokenID, secret string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tokenID+":"+secret)
	return r
}

// ---- Authenticate ----------------------------------------------------------

func TestAuthenticate_NoHeader(t *testing.T) {
	db := openTestDB(t)
	a := New(db)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrNoCredentials) {
		t.Errorf("want ErrNoCredentials, got %v", err)
	}
}

func TestAuthenticate_BearerNoColon(t *testing.T) {
	db := openTestDB(t)
	a := New(db)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer notokenidsecret")
	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthenticate_BearerValid(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "tok1", "s3cr3t", []string{"*"})
	a := New(db)
	tok, err := a.Authenticate(newBearerRequest("tok1", "s3cr3t"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.TokenID != "tok1" {
		t.Errorf("wrong token id: %s", tok.TokenID)
	}
}

func TestAuthenticate_BearerWrongSecret(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "tok2", "s3cr3t", []string{"*"})
	a := New(db)
	_, err := a.Authenticate(newBearerRequest("tok2", "wrong"))
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthenticate_BearerNonexistentToken(t *testing.T) {
	db := openTestDB(t)
	a := New(db)
	_, err := a.Authenticate(newBearerRequest("ghost", "anything"))
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthenticate_BearerRevokedToken(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "revoked-tok", "s3cr3t", []string{"*"})
	if err := db.RevokeToken("revoked-tok"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	a := New(db)
	_, err := a.Authenticate(newBearerRequest("revoked-tok", "s3cr3t"))
	if !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("want ErrTokenRevoked, got %v", err)
	}
}

func TestAuthenticate_BearerExpiredToken(t *testing.T) {
	db := openTestDB(t)
	acc, _, _ := db.CreateAccountIfNotExists("expiry-acct")
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cr3t"), bcrypt.DefaultCost)
	past := time.Now().Add(-time.Hour)
	tok := &meta.Token{
		TokenID:        "expired-tok",
		AccountID:      acc.AccountID,
		Name:           "expired",
		SecretHash:     string(hash),
		SecretKey:      "s3cr3t",
		AllowedActions: []string{"*"},
		ExpiresAt:      &past,
	}
	if err := db.CreateToken(tok); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	a := New(db)
	_, err := a.Authenticate(newBearerRequest("expired-tok", "s3cr3t"))
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("want ErrTokenExpired, got %v", err)
	}
}

func TestAuthenticate_UnknownScheme(t *testing.T) {
	db := openTestDB(t)
	a := New(db)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	_, err := a.Authenticate(r)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials, got %v", err)
	}
}

// Confirm that a second call for the same credentials hits the in-memory cache
// (fast path) and still succeeds.
func TestAuthenticate_CacheHit(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "cache-tok", "s3cr3t", []string{"*"})
	a := New(db)

	r1 := newBearerRequest("cache-tok", "s3cr3t")
	if _, err := a.Authenticate(r1); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Prime the cache, then check the cache size.
	a.mu.RLock()
	cached := len(a.cache)
	a.mu.RUnlock()
	if cached != 1 {
		t.Errorf("expected 1 cache entry, got %d", cached)
	}

	r2 := newBearerRequest("cache-tok", "s3cr3t")
	if _, err := a.Authenticate(r2); err != nil {
		t.Fatalf("second call (cache path): %v", err)
	}
}

// ---- AuthenticateCredentials -----------------------------------------------

func TestAuthenticateCredentials_Valid(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "cred-tok", "mypass", []string{"*"})
	a := New(db)
	tok, err := a.AuthenticateCredentials("cred-tok", "mypass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.TokenID != "cred-tok" {
		t.Errorf("wrong token: %s", tok.TokenID)
	}
}

func TestAuthenticateCredentials_Invalid(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "cred-tok2", "mypass", []string{"*"})
	a := New(db)
	_, err := a.AuthenticateCredentials("cred-tok2", "badpass")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials, got %v", err)
	}
}

// ---- InvalidateToken -------------------------------------------------------

func TestInvalidateToken_ClearsCache(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "inv-tok", "pass", []string{"*"})
	a := New(db)

	// Populate the cache.
	if _, err := a.AuthenticateCredentials("inv-tok", "pass"); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	a.mu.RLock()
	before := len(a.cache)
	a.mu.RUnlock()
	if before == 0 {
		t.Fatal("cache should be non-empty before invalidation")
	}

	a.InvalidateToken("inv-tok")

	a.mu.RLock()
	after := len(a.cache)
	a.mu.RUnlock()
	if after != 0 {
		t.Errorf("expected empty cache after invalidation, got %d entries", after)
	}
}

func TestInvalidateToken_NoopForUnknown(t *testing.T) {
	db := openTestDB(t)
	a := New(db)
	// Must not panic for a token that was never cached.
	a.InvalidateToken("never-existed")
}

// ---- Authorize -------------------------------------------------------------

func TestAuthorize_ActionAllowed(t *testing.T) {
	tok := &meta.Token{AllowedActions: []string{"object:get"}}
	a := New(nil)
	if err := a.Authorize(tok, "object:get", "bucket", "key"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestAuthorize_ActionDenied(t *testing.T) {
	tok := &meta.Token{AllowedActions: []string{"object:get"}}
	a := New(nil)
	if err := a.Authorize(tok, "object:put", "bucket", "key"); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("want ErrAccessDenied, got %v", err)
	}
}

func TestAuthorize_WildcardAction(t *testing.T) {
	tok := &meta.Token{AllowedActions: []string{"*"}}
	a := New(nil)
	for _, action := range []string{"object:get", "object:put", "bucket:list"} {
		if err := a.Authorize(tok, action, "bucket", "key"); err != nil {
			t.Errorf("action %q: expected nil, got %v", action, err)
		}
	}
}

func TestAuthorize_BucketScopeAllowed(t *testing.T) {
	tok := &meta.Token{AllowedActions: []string{"*"}, BucketScope: []string{"allowed-bucket"}}
	a := New(nil)
	if err := a.Authorize(tok, "object:get", "allowed-bucket", "key"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestAuthorize_BucketScopeDenied(t *testing.T) {
	tok := &meta.Token{AllowedActions: []string{"*"}, BucketScope: []string{"allowed-bucket"}}
	a := New(nil)
	if err := a.Authorize(tok, "object:get", "other-bucket", "key"); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("want ErrAccessDenied, got %v", err)
	}
}

func TestAuthorize_EmptyBucketScope_AllBuckets(t *testing.T) {
	tok := &meta.Token{AllowedActions: []string{"*"}, BucketScope: nil}
	a := New(nil)
	if err := a.Authorize(tok, "object:get", "any-bucket", "key"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestAuthorize_PrefixScopeAllowed(t *testing.T) {
	tok := &meta.Token{AllowedActions: []string{"*"}, PrefixScope: []string{"public/"}}
	a := New(nil)
	if err := a.Authorize(tok, "object:get", "b", "public/img.png"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestAuthorize_PrefixScopeDenied(t *testing.T) {
	tok := &meta.Token{AllowedActions: []string{"*"}, PrefixScope: []string{"public/"}}
	a := New(nil)
	if err := a.Authorize(tok, "object:get", "b", "private/secret.txt"); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("want ErrAccessDenied, got %v", err)
	}
}

func TestAuthorize_PrefixScopeEmptyKey_NotDenied(t *testing.T) {
	// Prefix scope only applies when objectKey is non-empty.
	tok := &meta.Token{AllowedActions: []string{"*"}, PrefixScope: []string{"public/"}}
	a := New(nil)
	if err := a.Authorize(tok, "bucket:list", "b", ""); err != nil {
		t.Errorf("expected nil for empty key, got %v", err)
	}
}

// ---- IsPublicRead ----------------------------------------------------------

func TestIsPublicRead_PublicBucket(t *testing.T) {
	db := openTestDB(t)
	acc, _, _ := db.CreateAccountIfNotExists("pub-acct")
	bkt := &meta.Bucket{
		ID:             "bucket-pub-1",
		Name:           "public-bucket",
		OwnerAccountID: acc.AccountID,
		Visibility:     "public-read",
	}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	a := New(db)
	if !a.IsPublicRead("public-bucket") {
		t.Error("expected true for public-read bucket")
	}
}

func TestIsPublicRead_PrivateBucket(t *testing.T) {
	db := openTestDB(t)
	acc, _, _ := db.CreateAccountIfNotExists("priv-acct")
	bkt := &meta.Bucket{
		ID:             "bucket-priv-1",
		Name:           "private-bucket",
		OwnerAccountID: acc.AccountID,
		Visibility:     "private",
	}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	a := New(db)
	if a.IsPublicRead("private-bucket") {
		t.Error("expected false for private bucket")
	}
}

func TestIsPublicRead_NonexistentBucket(t *testing.T) {
	db := openTestDB(t)
	a := New(db)
	if a.IsPublicRead("does-not-exist") {
		t.Error("expected false for nonexistent bucket")
	}
}

// ---- HashSecret ------------------------------------------------------------

func TestHashSecret_VerifiesCorrectly(t *testing.T) {
	hash, err := HashSecret("my-secret-pass")
	if err != nil {
		t.Fatalf("HashSecret: %v", err)
	}
	if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") {
		t.Errorf("unexpected hash format: %s", hash[:10])
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("my-secret-pass")); err != nil {
		t.Errorf("hash does not verify against original secret: %v", err)
	}
}

func TestHashSecret_DifferentEachTime(t *testing.T) {
	h1, _ := HashSecret("pass")
	h2, _ := HashSecret("pass")
	if h1 == h2 {
		t.Error("bcrypt hashes should differ due to random salt")
	}
}

// ---- AuthorizeWithPolicy ---------------------------------------------------

func TestAuthorizeWithPolicy_NilPolicy(t *testing.T) {
	tok := &meta.Token{TokenID: "t", AllowedActions: []string{"*"}}
	a := New(nil)
	if err := a.AuthorizeWithPolicy(tok, "object:get", "b", "k", "1.2.3.4", nil); err != nil {
		t.Errorf("nil policy: expected nil error, got %v", err)
	}
}

func TestAuthorizeWithPolicy_EmptyPolicy(t *testing.T) {
	tok := &meta.Token{TokenID: "t", AllowedActions: []string{"*"}}
	a := New(nil)
	if err := a.AuthorizeWithPolicy(tok, "object:get", "b", "k", "1.2.3.4", json.RawMessage{}); err != nil {
		t.Errorf("empty policy: expected nil error, got %v", err)
	}
}

func TestAuthorizeWithPolicy_MalformedJSON(t *testing.T) {
	tok := &meta.Token{TokenID: "t", AllowedActions: []string{"*"}}
	a := New(nil)
	err := a.AuthorizeWithPolicy(tok, "object:get", "b", "k", "1.2.3.4", json.RawMessage(`{bad json`))
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("want ErrAccessDenied for malformed JSON, got %v", err)
	}
}

func TestAuthorizeWithPolicy_DenyMatchingToken(t *testing.T) {
	tok := &meta.Token{TokenID: "blocked-tok", AllowedActions: []string{"*"}}
	a := New(nil)
	policy := `{"version":"1","statements":[{"effect":"deny","actions":["*"],"subjects":["blocked-tok"],"prefixes":[]}]}`
	err := a.AuthorizeWithPolicy(tok, "object:get", "b", "docs/secret", "1.2.3.4", json.RawMessage(policy))
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("want ErrAccessDenied, got %v", err)
	}
}

func TestAuthorizeWithPolicy_DenyNotMatchingToken(t *testing.T) {
	tok := &meta.Token{TokenID: "other-tok", AllowedActions: []string{"*"}}
	a := New(nil)
	policy := `{"version":"1","statements":[{"effect":"deny","actions":["*"],"subjects":["blocked-tok"],"prefixes":[]}]}`
	err := a.AuthorizeWithPolicy(tok, "object:get", "b", "k", "1.2.3.4", json.RawMessage(policy))
	if err != nil {
		t.Errorf("expected nil for non-matching deny, got %v", err)
	}
}

func TestAuthorizeWithPolicy_DenyWithIPCondition_Matching(t *testing.T) {
	tok := &meta.Token{TokenID: "t", AllowedActions: []string{"*"}}
	a := New(nil)
	policy := `{
		"version":"1",
		"statements":[{
			"effect":"deny",
			"actions":["*"],
			"subjects":["*"],
			"prefixes":[],
			"conditions":{"ip_whitelist":["10.0.0.0/8"]}
		}]
	}`
	// IP within the CIDR → deny matches → access denied.
	err := a.AuthorizeWithPolicy(tok, "object:get", "b", "k", "10.1.2.3", json.RawMessage(policy))
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("want ErrAccessDenied for IP in deny CIDR, got %v", err)
	}
}

func TestAuthorizeWithPolicy_DenyWithIPCondition_NotMatching(t *testing.T) {
	tok := &meta.Token{TokenID: "t", AllowedActions: []string{"*"}}
	a := New(nil)
	policy := `{
		"version":"1",
		"statements":[{
			"effect":"deny",
			"actions":["*"],
			"subjects":["*"],
			"prefixes":[],
			"conditions":{"ip_whitelist":["10.0.0.0/8"]}
		}]
	}`
	// IP outside the CIDR → deny condition not satisfied → access allowed.
	err := a.AuthorizeWithPolicy(tok, "object:get", "b", "k", "192.168.1.1", json.RawMessage(policy))
	if err != nil {
		t.Errorf("expected nil for IP outside deny CIDR, got %v", err)
	}
}

func TestAuthorizeWithPolicy_TokenAuthFailsFirst(t *testing.T) {
	// Even with a permissive policy, token-level Authorize runs first.
	tok := &meta.Token{TokenID: "t", AllowedActions: []string{"object:get"}}
	a := New(nil)
	policy := `{"version":"1","statements":[]}`
	err := a.AuthorizeWithPolicy(tok, "object:put", "b", "k", "1.2.3.4", json.RawMessage(policy))
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("want ErrAccessDenied from token-level check, got %v", err)
	}
}

// ---- parseSigV4Header ------------------------------------------------------

func TestParseSigV4Header_Valid(t *testing.T) {
	header := "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123"
	parts := parseSigV4Header(header)
	if parts == nil {
		t.Fatal("expected non-nil result")
	}
	if parts["credential_key"] != "AKID" {
		t.Errorf("credential_key: got %q", parts["credential_key"])
	}
	if parts["credential_date"] != "20130524" {
		t.Errorf("credential_date: got %q", parts["credential_date"])
	}
	if parts["credential_region"] != "us-east-1" {
		t.Errorf("credential_region: got %q", parts["credential_region"])
	}
	if parts["signed_headers"] != "host;x-amz-date" {
		t.Errorf("signed_headers: got %q", parts["signed_headers"])
	}
	if parts["signature"] != "abc123" {
		t.Errorf("signature: got %q", parts["signature"])
	}
}

func TestParseSigV4Header_MissingParts(t *testing.T) {
	// No Credential field — key should be empty.
	header := "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=abc"
	parts := parseSigV4Header(header)
	if parts["credential_key"] != "" {
		t.Errorf("expected empty credential_key, got %q", parts["credential_key"])
	}
}

// ---- validateTimestamp -----------------------------------------------------

func TestValidateTimestamp_ValidISO8601(t *testing.T) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	credDate := now.Format("20060102")
	if err := validateTimestamp(amzDate, credDate); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestValidateTimestamp_TooOld(t *testing.T) {
	old := time.Now().UTC().Add(-20 * time.Minute)
	amzDate := old.Format("20060102T150405Z")
	credDate := old.Format("20060102")
	err := validateTimestamp(amzDate, credDate)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials for old timestamp, got %v", err)
	}
}

func TestValidateTimestamp_TooFarInFuture(t *testing.T) {
	future := time.Now().UTC().Add(20 * time.Minute)
	amzDate := future.Format("20060102T150405Z")
	credDate := future.Format("20060102")
	err := validateTimestamp(amzDate, credDate)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials for future timestamp, got %v", err)
	}
}

func TestValidateTimestamp_InvalidFormat(t *testing.T) {
	err := validateTimestamp("not-a-date", "20130524")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials for invalid format, got %v", err)
	}
}

func TestValidateTimestamp_Empty(t *testing.T) {
	err := validateTimestamp("", "")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials for empty timestamp, got %v", err)
	}
}

func TestValidateTimestamp_CredDateMismatch(t *testing.T) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	// Pass yesterday as the credential date.
	credDate := now.Add(-24 * time.Hour).Format("20060102")
	err := validateTimestamp(amzDate, credDate)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials for credential date mismatch, got %v", err)
	}
}

// ---- buildCanonicalRequest -------------------------------------------------

func TestBuildCanonicalRequest_KnownInputs(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/bucket/key?prefix=foo", nil)
	r.Header.Set("host", "s3.example.com")
	r.Header.Set("x-amz-date", "20130524T000000Z")
	r.Header.Set("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canon := buildCanonicalRequest(r, signedHeaders)

	lines := strings.Split(canon, "\n")
	if len(lines) < 6 {
		t.Fatalf("canonical request has %d lines, want >= 6: %q", len(lines), canon)
	}
	if lines[0] != "GET" {
		t.Errorf("method line: got %q", lines[0])
	}
	if lines[1] != "/bucket/key" {
		t.Errorf("URI line: got %q", lines[1])
	}
	if lines[2] != "prefix=foo" {
		t.Errorf("query line: got %q", lines[2])
	}
}

// ---- deriveSigningKey ------------------------------------------------------

func TestDeriveSigningKey_Deterministic(t *testing.T) {
	k1 := deriveSigningKey("secretABC", "20130524", "us-east-1", "s3")
	k2 := deriveSigningKey("secretABC", "20130524", "us-east-1", "s3")
	if string(k1) != string(k2) {
		t.Error("deriveSigningKey must be deterministic for identical inputs")
	}
}

func TestDeriveSigningKey_DifferentInputs(t *testing.T) {
	k1 := deriveSigningKey("secretABC", "20130524", "us-east-1", "s3")
	k2 := deriveSigningKey("secretABC", "20130524", "eu-west-1", "s3")
	if string(k1) == string(k2) {
		t.Error("different regions must produce different signing keys")
	}
}

// ---- AuthenticateSigV4 end-to-end ------------------------------------------

// signRequest adds a complete AWS SigV4 Authorization header to r.
func signRequest(r *http.Request, tokenID, secretKey, region, dateStr, amzDate string) {
	r.Header.Set("x-amz-date", amzDate)
	r.Header.Set("host", r.Host)
	r.Header.Set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")

	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := buildCanonicalRequest(r, signedHeaders)
	signingKey := deriveSigningKey(secretKey, dateStr, region, "s3")
	stringToSign := buildStringToSign(dateStr, amzDate, region, canonicalRequest)
	h := hmac.New(sha256.New, signingKey)
	h.Write([]byte(stringToSign))
	sig := hex.EncodeToString(h.Sum(nil))

	r.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s/%s/s3/aws4_request, SignedHeaders=%s, Signature=%s",
		tokenID, dateStr, region, signedHeaders, sig,
	))
}

func TestAuthenticateSigV4_Valid(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "sigv4-tok", "sigv4-secret-key", []string{"*"})
	a := New(db)

	now := time.Now().UTC()
	dateStr := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	r.Host = "s3.example.com"
	signRequest(r, "sigv4-tok", "sigv4-secret-key", "us-east-1", dateStr, amzDate)

	tok, err := a.AuthenticateSigV4(r)
	if err != nil {
		t.Fatalf("AuthenticateSigV4: %v", err)
	}
	if tok.TokenID != "sigv4-tok" {
		t.Errorf("wrong token: %s", tok.TokenID)
	}
}

func TestAuthenticateSigV4_WrongSignature(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "sigv4-bad", "sigv4-secret-key", []string{"*"})
	a := New(db)

	now := time.Now().UTC()
	dateStr := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	r.Host = "s3.example.com"
	signRequest(r, "sigv4-bad", "sigv4-secret-key", "us-east-1", dateStr, amzDate)
	// Overwrite the signature with garbage.
	r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "Signature=", "Signature=AAABBB", 1))

	_, err := a.AuthenticateSigV4(r)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthenticateSigV4_NonexistentToken(t *testing.T) {
	db := openTestDB(t)
	a := New(db)

	now := time.Now().UTC()
	dateStr := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "s3.example.com"
	signRequest(r, "ghost-token", "any-secret", "us-east-1", dateStr, amzDate)

	_, err := a.AuthenticateSigV4(r)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthenticateSigV4_MissingAuthHeader(t *testing.T) {
	db := openTestDB(t)
	a := New(db)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := a.AuthenticateSigV4(r)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthenticateSigV4_RevokedToken(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "sigv4-rev", "sigv4-secret-rev", []string{"*"})
	if err := db.RevokeToken("sigv4-rev"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	a := New(db)

	now := time.Now().UTC()
	dateStr := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "s3.example.com"
	signRequest(r, "sigv4-rev", "sigv4-secret-rev", "us-east-1", dateStr, amzDate)

	_, err := a.AuthenticateSigV4(r)
	if !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("want ErrTokenRevoked, got %v", err)
	}
}

// ---- BucketPolicy.Compile --------------------------------------------------

func TestCompile_ParsesCIDRs(t *testing.T) {
	p := &BucketPolicy{
		Statements: []PolicyStatement{
			{
				Effect:  "deny",
				Actions: []string{"*"},
				Conditions: &PolicyConditions{
					IPWhitelist: []string{"192.168.1.0/24", "10.0.0.0/8"},
				},
			},
		},
	}
	p.Compile()
	conds := p.Statements[0].Conditions
	if len(conds.parsedCIDRs) != 2 {
		t.Errorf("expected 2 parsed CIDRs, got %d", len(conds.parsedCIDRs))
	}
}

func TestCompile_InvalidCIDRSkipped(t *testing.T) {
	p := &BucketPolicy{
		Statements: []PolicyStatement{
			{
				Effect:  "deny",
				Actions: []string{"*"},
				Conditions: &PolicyConditions{
					IPWhitelist: []string{"not-a-cidr", "10.0.0.0/8"},
				},
			},
		},
	}
	p.Compile()
	conds := p.Statements[0].Conditions
	if len(conds.parsedCIDRs) != 1 {
		t.Errorf("expected 1 valid parsed CIDR (invalid skipped), got %d", len(conds.parsedCIDRs))
	}
}

func TestCompile_NilPolicy(t *testing.T) {
	var p *BucketPolicy
	// Must not panic.
	p.Compile()
}

// ---- EvaluatePolicyDeny ----------------------------------------------------

func TestEvaluatePolicyDeny_NilPolicy(t *testing.T) {
	if EvaluatePolicyDeny(nil, "tok", "object:get", "key", "1.2.3.4") {
		t.Error("nil policy must not deny")
	}
}

func TestEvaluatePolicyDeny_AllowEffect_Ignored(t *testing.T) {
	p := &BucketPolicy{
		Statements: []PolicyStatement{
			{Effect: "allow", Actions: []string{"*"}, Subjects: []string{"*"}},
		},
	}
	p.Compile()
	if EvaluatePolicyDeny(p, "tok", "object:get", "key", "1.2.3.4") {
		t.Error("allow effect must not trigger deny")
	}
}

func TestEvaluatePolicyDeny_DenyMatchingAll(t *testing.T) {
	p := &BucketPolicy{
		Statements: []PolicyStatement{
			{Effect: "deny", Actions: []string{"*"}, Subjects: []string{"*"}},
		},
	}
	p.Compile()
	if !EvaluatePolicyDeny(p, "any-tok", "object:get", "key", "1.2.3.4") {
		t.Error("wildcard deny must match")
	}
}

func TestEvaluatePolicyDeny_DenySubjectMismatch(t *testing.T) {
	p := &BucketPolicy{
		Statements: []PolicyStatement{
			{Effect: "deny", Actions: []string{"*"}, Subjects: []string{"specific-tok"}},
		},
	}
	p.Compile()
	if EvaluatePolicyDeny(p, "other-tok", "object:get", "key", "1.2.3.4") {
		t.Error("subject mismatch must not deny")
	}
}

func TestEvaluatePolicyDeny_DenyActionMismatch(t *testing.T) {
	p := &BucketPolicy{
		Statements: []PolicyStatement{
			{Effect: "deny", Actions: []string{"object:delete"}, Subjects: []string{"*"}},
		},
	}
	p.Compile()
	if EvaluatePolicyDeny(p, "tok", "object:get", "key", "1.2.3.4") {
		t.Error("action mismatch must not deny")
	}
}

func TestEvaluatePolicyDeny_DenyPrefixMismatch(t *testing.T) {
	p := &BucketPolicy{
		Statements: []PolicyStatement{
			{Effect: "deny", Actions: []string{"*"}, Subjects: []string{"*"}, Prefixes: []string{"restricted/"}},
		},
	}
	p.Compile()
	if EvaluatePolicyDeny(p, "tok", "object:get", "public/img.png", "1.2.3.4") {
		t.Error("prefix mismatch must not deny")
	}
}

func TestEvaluatePolicyDeny_DenyPrefixMatch(t *testing.T) {
	p := &BucketPolicy{
		Statements: []PolicyStatement{
			{Effect: "deny", Actions: []string{"*"}, Subjects: []string{"*"}, Prefixes: []string{"restricted/"}},
		},
	}
	p.Compile()
	if !EvaluatePolicyDeny(p, "tok", "object:get", "restricted/doc.pdf", "1.2.3.4") {
		t.Error("prefix match must deny")
	}
}

func TestEvaluatePolicyDeny_IPConditionMatch(t *testing.T) {
	p := &BucketPolicy{
		Statements: []PolicyStatement{
			{
				Effect:     "deny",
				Actions:    []string{"*"},
				Subjects:   []string{"*"},
				Conditions: &PolicyConditions{IPWhitelist: []string{"192.168.1.0/24"}},
			},
		},
	}
	p.Compile()
	if !EvaluatePolicyDeny(p, "tok", "object:get", "key", "192.168.1.50") {
		t.Error("IP in deny CIDR must deny")
	}
}

func TestEvaluatePolicyDeny_IPConditionNoMatch(t *testing.T) {
	p := &BucketPolicy{
		Statements: []PolicyStatement{
			{
				Effect:     "deny",
				Actions:    []string{"*"},
				Subjects:   []string{"*"},
				Conditions: &PolicyConditions{IPWhitelist: []string{"192.168.1.0/24"}},
			},
		},
	}
	p.Compile()
	if EvaluatePolicyDeny(p, "tok", "object:get", "key", "10.0.0.1") {
		t.Error("IP outside deny CIDR must not deny")
	}
}

// ---- AuthorizeBucketOwnership ----------------------------------------------

func TestAuthorizeBucketOwnership_Owner(t *testing.T) {
	a := New(openTestDB(t))
	tok := &meta.Token{TokenID: "t", AccountID: "acct-a"}
	b := &meta.Bucket{Name: "photos", OwnerAccountID: "acct-a"}
	if err := a.AuthorizeBucketOwnership(tok, b); err != nil {
		t.Errorf("owner should be allowed, got %v", err)
	}
}

func TestAuthorizeBucketOwnership_OtherAccountDenied(t *testing.T) {
	a := New(openTestDB(t))
	// Full permissions, no bucket scope — exactly the token that used to be
	// able to delete another tenant's bucket.
	tok := &meta.Token{TokenID: "t", AccountID: "acct-a", AllowedActions: []string{"*"}}
	b := &meta.Bucket{Name: "photos", OwnerAccountID: "acct-b"}
	if err := a.AuthorizeBucketOwnership(tok, b); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("want ErrAccessDenied, got %v", err)
	}
}

func TestAuthorizeBucketOwnership_LegacyBucketWithoutOwner(t *testing.T) {
	a := New(openTestDB(t))
	tok := &meta.Token{TokenID: "t", AccountID: "acct-a"}
	b := &meta.Bucket{Name: "legacy", OwnerAccountID: ""}
	if err := a.AuthorizeBucketOwnership(tok, b); err != nil {
		t.Errorf("ownerless bucket should be allowed, got %v", err)
	}
}

func TestAuthorizeBucketOwnership_ExplicitBucketScopeDelegation(t *testing.T) {
	a := New(openTestDB(t))
	tok := &meta.Token{TokenID: "t", AccountID: "acct-a", BucketScope: []string{"shared", "photos"}}
	b := &meta.Bucket{Name: "shared", OwnerAccountID: "acct-b"}
	if err := a.AuthorizeBucketOwnership(tok, b); err != nil {
		t.Errorf("explicit bucket scope should delegate access, got %v", err)
	}
}

func TestAuthorizeBucketOwnership_ScopeForOtherBucketDenied(t *testing.T) {
	a := New(openTestDB(t))
	tok := &meta.Token{TokenID: "t", AccountID: "acct-a", BucketScope: []string{"other"}}
	b := &meta.Bucket{Name: "shared", OwnerAccountID: "acct-b"}
	if err := a.AuthorizeBucketOwnership(tok, b); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("want ErrAccessDenied, got %v", err)
	}
}

func TestAuthorizeBucketOwnership_NilArgs(t *testing.T) {
	a := New(openTestDB(t))
	if err := a.AuthorizeBucketOwnership(nil, &meta.Bucket{}); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("nil token: want ErrAccessDenied, got %v", err)
	}
	if err := a.AuthorizeBucketOwnership(&meta.Token{}, nil); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("nil bucket: want ErrAccessDenied, got %v", err)
	}
}

// ---- account status revalidation -------------------------------------------

// A suspended account must be rejected immediately, even though the token is
// still in the positive auth cache (which is what used to keep a suspended
// account working for up to authCacheTTL).
func TestValidateToken_SuspendedAccountRejectedOnCachedPath(t *testing.T) {
	db := openTestDB(t)
	acc, _ := seedToken(t, db, "susp-tok", "pass", []string{"*"})
	a := New(db)

	if _, err := a.AuthenticateCredentials("susp-tok", "pass"); err != nil {
		t.Fatalf("first authenticate: %v", err)
	}

	// Suspend the account (CreateAccount is an upsert).
	acc.Status = "suspended"
	if err := db.CreateAccount(acc); err != nil {
		t.Fatalf("suspend account: %v", err)
	}

	// Cache is still warm; the fast path must revalidate the account status.
	if _, err := a.AuthenticateCredentials("susp-tok", "pass"); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("want ErrAccessDenied for suspended account, got %v", err)
	}
}

// ---- negative auth cache ----------------------------------------------------

func TestValidateToken_FailureIsCached(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "neg-tok", "goodpass", []string{"*"})
	a := New(db)

	if _, err := a.AuthenticateCredentials("neg-tok", "badpass"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("want ErrInvalidCredentials, got %v", err)
	}

	a.mu.RLock()
	n := len(a.failCache)
	a.mu.RUnlock()
	if n != 1 {
		t.Fatalf("expected 1 negative cache entry, got %d", n)
	}

	// Replay: must still fail, now without touching bcrypt.
	if _, err := a.AuthenticateCredentials("neg-tok", "badpass"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("cached failure: want ErrInvalidCredentials, got %v", err)
	}

	// The correct secret must never be blocked by the negative cache.
	if _, err := a.AuthenticateCredentials("neg-tok", "goodpass"); err != nil {
		t.Errorf("valid credentials must still authenticate: %v", err)
	}
}

func TestValidateToken_FailureCacheExpires(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "exp-tok", "goodpass", []string{"*"})
	a := New(db)

	if _, err := a.AuthenticateCredentials("exp-tok", "nope"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("want ErrInvalidCredentials, got %v", err)
	}

	// Force the entry to be stale and confirm the slow path runs again.
	key := cacheKey("exp-tok", "nope")
	a.mu.Lock()
	a.failCache[key] = authFailEntry{err: ErrInvalidCredentials, deadline: time.Now().Add(-time.Second)}
	a.mu.Unlock()

	if _, err := a.AuthenticateCredentials("exp-tok", "nope"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials after expiry, got %v", err)
	}
	a.mu.RLock()
	e, ok := a.failCache[key]
	a.mu.RUnlock()
	if !ok || !time.Now().Before(e.deadline) {
		t.Error("expired entry should have been refreshed by the slow path")
	}
}

func TestInvalidateToken_ClearsNegativeCache(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "inv-neg", "goodpass", []string{"*"})
	a := New(db)

	if _, err := a.AuthenticateCredentials("inv-neg", "badpass"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("want ErrInvalidCredentials, got %v", err)
	}

	a.InvalidateToken("inv-neg")

	a.mu.RLock()
	n := len(a.failCache)
	a.mu.RUnlock()
	if n != 0 {
		t.Errorf("negative cache should be empty after invalidation, got %d entries", n)
	}
}

// ---- canonicalQueryString ---------------------------------------------------

func TestCanonicalQueryString_SortsAndEncodes(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"", ""},
		{"prefix=foo", "prefix=foo"},
		{"b=2&a=1", "a=1&b=2"},
		{"a=2&a=1", "a=1&a=2"},
		{"uploads", "uploads="},
		{"key=a+b", "key=a%20b"},
		{"key=a/b", "key=a%2Fb"},
		{"marker=caf%C3%A9", "marker=caf%C3%A9"},
		{"list-type=2&prefix=x&delimiter=/", "delimiter=%2F&list-type=2&prefix=x"},
	}
	for _, c := range cases {
		if got := canonicalQueryString(c.raw); got != c.want {
			t.Errorf("canonicalQueryString(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestRFC3986Escape_UnreservedUntouched(t *testing.T) {
	const unreserved = "abcXYZ019-_.~"
	if got := rfc3986Escape(unreserved); got != unreserved {
		t.Errorf("unreserved chars must not be escaped: got %q", got)
	}
	if got := rfc3986Escape("a b"); got != "a%20b" {
		t.Errorf("space must encode as %%20, got %q", got)
	}
}

// ---- payload hash verification ---------------------------------------------

// signRequestWithPayload signs r declaring payloadHash in x-amz-content-sha256.
func signRequestWithPayload(r *http.Request, tokenID, secretKey, region, dateStr, amzDate, payloadHash string) {
	r.Header.Set("x-amz-date", amzDate)
	r.Header.Set("host", r.Host)
	r.Header.Set("x-amz-content-sha256", payloadHash)

	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := buildCanonicalRequest(r, signedHeaders)
	signingKey := deriveSigningKey(secretKey, dateStr, region, "s3")
	stringToSign := buildStringToSign(dateStr, amzDate, region, canonicalRequest)
	h := hmac.New(sha256.New, signingKey)
	h.Write([]byte(stringToSign))
	sig := hex.EncodeToString(h.Sum(nil))

	r.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s/%s/s3/aws4_request, SignedHeaders=%s, Signature=%s",
		tokenID, dateStr, region, signedHeaders, sig,
	))
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestAuthenticateSigV4_PayloadHashMatches(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "pay-ok", "sigv4-secret-key", []string{"*"})
	a := New(db)

	now := time.Now().UTC()
	dateStr, amzDate := now.Format("20060102"), now.Format("20060102T150405Z")

	body := "hello world"
	r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader(body))
	r.Host = "s3.example.com"
	signRequestWithPayload(r, "pay-ok", "sigv4-secret-key", "us-east-1", dateStr, amzDate, sha256Hex(body))

	if _, err := a.AuthenticateSigV4(r); err != nil {
		t.Fatalf("AuthenticateSigV4: %v", err)
	}

	// The body must still be readable by the handler chain.
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != body {
		t.Errorf("body not restored: got %q, want %q", got, body)
	}
	if r.ContentLength != int64(len(body)) {
		t.Errorf("ContentLength = %d, want %d", r.ContentLength, len(body))
	}
}

// A tampered body must be rejected even though the signature is intact — this
// is the MITM case the payload hash exists to prevent.
func TestAuthenticateSigV4_PayloadHashMismatch(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "pay-bad", "sigv4-secret-key", []string{"*"})
	a := New(db)

	now := time.Now().UTC()
	dateStr, amzDate := now.Format("20060102"), now.Format("20060102T150405Z")

	r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("tampered"))
	r.Host = "s3.example.com"
	// Sign declaring the hash of the ORIGINAL body while sending another one.
	signRequestWithPayload(r, "pay-bad", "sigv4-secret-key", "us-east-1", dateStr, amzDate, sha256Hex("hello world"))

	if _, err := a.AuthenticateSigV4(r); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials for payload hash mismatch, got %v", err)
	}
}

func TestAuthenticateSigV4_UnsignedPayloadSkipsVerification(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "pay-unsigned", "sigv4-secret-key", []string{"*"})
	a := New(db)

	now := time.Now().UTC()
	dateStr, amzDate := now.Format("20060102"), now.Format("20060102T150405Z")

	r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("anything at all"))
	r.Host = "s3.example.com"
	signRequestWithPayload(r, "pay-unsigned", "sigv4-secret-key", "us-east-1", dateStr, amzDate, "UNSIGNED-PAYLOAD")

	if _, err := a.AuthenticateSigV4(r); err != nil {
		t.Fatalf("UNSIGNED-PAYLOAD must not be verified: %v", err)
	}
}

// STREAMING-* means the body is aws-chunked, and jay has no decoder for that
// framing. This test used to assert the opposite — that the mode was accepted
// and verification skipped — which is exactly what let the chunk headers and
// signatures be stored as the object body under a 200. The signature itself
// still verifies here; what must fail is the payload gate.
func TestAuthenticateSigV4_StreamingPayloadRejected(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "pay-stream", "sigv4-secret-key", []string{"*"})
	a := New(db)

	now := time.Now().UTC()
	dateStr, amzDate := now.Format("20060102"), now.Format("20060102T150405Z")

	for _, declared := range []string{
		"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
		"STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
		"STREAMING-UNSIGNED-PAYLOAD-TRAILER",
	} {
		t.Run(declared, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("chunk data"))
			r.Host = "s3.example.com"
			signRequestWithPayload(r, "pay-stream", "sigv4-secret-key", "us-east-1", dateStr, amzDate, declared)

			_, err := a.AuthenticateSigV4(r)
			if !errors.Is(err, ErrChunkedBodyUnsupported) {
				t.Fatalf("want ErrChunkedBodyUnsupported for %s, got %v", declared, err)
			}
		})
	}
}

// A framed body announced only by x-amz-decoded-content-length is refused too:
// the declared hash is a perfectly ordinary UNSIGNED-PAYLOAD, so the payload
// hash alone would have waved it through.
func TestAuthenticateSigV4_DecodedContentLengthRejected(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "pay-decoded", "sigv4-secret-key", []string{"*"})
	a := New(db)

	now := time.Now().UTC()
	dateStr, amzDate := now.Format("20060102"), now.Format("20060102T150405Z")

	r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("chunk data"))
	r.Host = "s3.example.com"
	r.Header.Set("x-amz-decoded-content-length", "10")
	signRequestWithPayload(r, "pay-decoded", "sigv4-secret-key", "us-east-1", dateStr, amzDate, "UNSIGNED-PAYLOAD")

	if _, err := a.AuthenticateSigV4(r); !errors.Is(err, ErrChunkedBodyUnsupported) {
		t.Fatalf("want ErrChunkedBodyUnsupported, got %v", err)
	}
}

// A signed payload larger than maxSignedPayloadSize is rejected, not buffered.
func TestAuthenticateSigV4_SignedPayloadTooLarge(t *testing.T) {
	db := openTestDB(t)
	_, _ = seedToken(t, db, "pay-huge", "sigv4-secret-key", []string{"*"})
	a := New(db)

	now := time.Now().UTC()
	dateStr, amzDate := now.Format("20060102"), now.Format("20060102T150405Z")

	r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("small body, big claim"))
	r.Host = "s3.example.com"
	signRequestWithPayload(r, "pay-huge", "sigv4-secret-key", "us-east-1", dateStr, amzDate, sha256Hex("x"))
	r.ContentLength = maxSignedPayloadSize + 1

	if _, err := a.AuthenticateSigV4(r); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("want ErrInvalidCredentials for oversized signed payload, got %v", err)
	}
}

func TestVerifyPayloadHash_EmptyBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	if err := verifyPayloadHash(r, sha256Hex("")); err != nil {
		t.Errorf("empty body must hash to the empty sha256: %v", err)
	}
}
