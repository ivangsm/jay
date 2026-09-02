package admin

// Tests for POST /_jay/presign in both styles.
//
// The aws-style assertions do not stop at "a URL came back": they feed the URL
// to the real S3 handler and check the object's bytes come out. A presign
// endpoint that answers 200 with a URL nobody accepts is exactly the kind of
// confirmation-without-work this repo refuses.

import (
	jsonv2 "encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"uuid"

	"github.com/ivangsm/jay/api"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

const (
	testAdminToken   = "admin-token-for-tests"
	testSigningKey   = "signing-secret-of-at-least-32-characters"
	testTokenID      = "presign-token"
	testTokenSecret  = "presign-token-secret"
	testBucketName   = "presign-bucket"
	testObjectKey    = "hello.txt"
	testObjectBody   = "hola"
	testListenAddrNH = ":9000" // no hostname, the shipped default
)

type presignFixture struct {
	admin *Handler
	s3    *api.Handler
	db    *meta.DB
}

func newPresignFixture(t *testing.T, listenAddr string) *presignFixture {
	t.Helper()
	dir := t.TempDir()

	db, err := meta.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetSigningSecret(testSigningKey)
	t.Cleanup(func() { _ = db.Close() })

	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	acc := &meta.Account{AccountID: uuid.New().String(), Name: "test", Status: "active"}
	if err := db.CreateAccount(acc); err != nil {
		t.Fatalf("create account: %v", err)
	}

	hash, err := auth.HashSecret(testTokenSecret)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	tok := &meta.Token{
		TokenID:        testTokenID,
		AccountID:      acc.AccountID,
		Name:           "presign",
		SecretHash:     hash,
		SecretKey:      testTokenSecret,
		AllowedActions: meta.AllActions,
		Status:         "active",
	}
	if err := db.CreateToken(tok); err != nil {
		t.Fatalf("create token: %v", err)
	}

	bucket := &meta.Bucket{
		ID:             uuid.New().String(),
		Name:           testBucketName,
		OwnerAccountID: acc.AccountID,
		Visibility:     "private",
		Status:         "active",
	}
	if err := db.CreateBucket(bucket); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	au := auth.New(db)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	metrics := maintenance.NewMetrics()

	s3 := api.NewHandler(db, st, au, log, metrics, testSigningKey, nil)

	// Seed one object through the S3 handler so the round trip has something
	// to fetch.
	put := httptest.NewRequest(http.MethodPut, "http://jay.test/"+testBucketName+"/"+testObjectKey,
		strings.NewReader(testObjectBody))
	put.Header.Set("Authorization", "Bearer "+testTokenID+":"+testTokenSecret)
	w := httptest.NewRecorder()
	s3.ServeHTTP(w, put)
	if w.Code != http.StatusOK {
		t.Fatalf("seed object: want 200, got %d: %s", w.Code, w.Body.String())
	}

	adm := NewHandler(AdminConfig{
		DB:            db,
		Store:         st,
		Auth:          au,
		AdminToken:    testAdminToken,
		Log:           log,
		Metrics:       metrics,
		SigningSecret: testSigningKey,
		ListenAddr:    listenAddr,
	})
	t.Cleanup(func() { _ = adm.Close() })

	return &presignFixture{admin: adm, s3: s3, db: db}
}

// callPresign posts a raw JSON body to /_jay/presign.
func (f *presignFixture) callPresign(t *testing.T, body string) (int, presignResponse, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://jay.test/_jay/presign", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.admin.ServeHTTP(w, req)

	var resp presignResponse
	if w.Code == http.StatusOK {
		if err := jsonv2.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode presign response %q: %v", w.Body.String(), err)
		}
	}
	return w.Code, resp, w.Body.String()
}

// fetch replays a presigned URL against the S3 handler.
func (f *presignFixture) fetch(t *testing.T, rawURL string) *httptest.ResponseRecorder {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse presigned URL %q: %v", rawURL, err)
	}
	req := httptest.NewRequest(http.MethodGet, rawURL, nil)
	req.Host = u.Host
	w := httptest.NewRecorder()
	f.s3.ServeHTTP(w, req)
	return w
}

func TestPresign_DefaultStyleIsJay(t *testing.T) {
	f := newPresignFixture(t, "jay.test:9000")

	code, resp, body := f.callPresign(t, `{"token_id":"presign-token","method":"GET","bucket":"presign-bucket","key":"hello.txt"}`)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", code, body)
	}
	if resp.Style != presignStyleJay {
		t.Fatalf("default style = %q, want %q — changing it is a contract change for jay-admin and falco", resp.Style, presignStyleJay)
	}
	if !strings.Contains(resp.URL, "X-Jay-Signature=") {
		t.Fatalf("jay style URL has no X-Jay-Signature: %s", resp.URL)
	}

	if w := f.fetch(t, resp.URL); w.Code != http.StatusOK || w.Body.String() != testObjectBody {
		t.Fatalf("jay-style URL did not serve the object: %d %s", w.Code, w.Body.String())
	}
}

func TestPresign_AWSStyle_IsAcceptedByTheS3Handler(t *testing.T) {
	f := newPresignFixture(t, "jay.test:9000")

	code, resp, body := f.callPresign(t,
		`{"token_id":"presign-token","method":"GET","bucket":"presign-bucket","key":"hello.txt","style":"aws"}`)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", code, body)
	}
	if resp.Style != presignStyleAWS {
		t.Fatalf("style = %q, want %q", resp.Style, presignStyleAWS)
	}
	for _, want := range []string{"X-Amz-Algorithm=AWS4-HMAC-SHA256", "X-Amz-Credential=", "X-Amz-Date=", "X-Amz-Expires=", "X-Amz-SignedHeaders=host", "X-Amz-Signature="} {
		if !strings.Contains(resp.URL, want) {
			t.Fatalf("aws style URL is missing %s: %s", want, resp.URL)
		}
	}

	w := f.fetch(t, resp.URL)
	if w.Code != http.StatusOK {
		t.Fatalf("aws-style URL rejected by the S3 handler: %d %s", w.Code, w.Body.String())
	}
	if w.Body.String() != testObjectBody {
		t.Fatalf("body = %q, want %q", w.Body.String(), testObjectBody)
	}
}

func TestPresign_AWSStyle_RefusesAHostlessListenAddr(t *testing.T) {
	f := newPresignFixture(t, testListenAddrNH)

	code, _, body := f.callPresign(t,
		`{"token_id":"presign-token","method":"GET","bucket":"presign-bucket","key":"hello.txt","style":"aws"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", code, body)
	}
	if !strings.Contains(body, "host") {
		t.Fatalf("the error must say what is missing, got %s", body)
	}
}

func TestPresign_AWSStyle_ExplicitHostOverridesListenAddr(t *testing.T) {
	f := newPresignFixture(t, testListenAddrNH)

	code, resp, body := f.callPresign(t,
		`{"token_id":"presign-token","method":"GET","bucket":"presign-bucket","key":"hello.txt","style":"aws","host":"jay.test:9000"}`)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", code, body)
	}
	if !strings.HasPrefix(resp.URL, "http://jay.test:9000/") {
		t.Fatalf("URL does not use the requested host: %s", resp.URL)
	}
	if w := f.fetch(t, resp.URL); w.Code != http.StatusOK {
		t.Fatalf("aws-style URL rejected: %d %s", w.Code, w.Body.String())
	}
}

func TestPresign_JayStyle_KeepsWorkingWithAHostlessListenAddr(t *testing.T) {
	// The jay form does not sign the host, so a hostless listen address is not
	// a reason to start failing a call that used to answer.
	f := newPresignFixture(t, testListenAddrNH)

	code, resp, body := f.callPresign(t,
		`{"token_id":"presign-token","method":"GET","bucket":"presign-bucket","key":"hello.txt"}`)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", code, body)
	}
	if !strings.Contains(resp.URL, "X-Jay-Signature=") {
		t.Fatalf("no signature in %s", resp.URL)
	}
}

func TestPresign_RejectsUnknownStyle(t *testing.T) {
	f := newPresignFixture(t, "jay.test:9000")

	code, _, body := f.callPresign(t,
		`{"token_id":"presign-token","method":"GET","bucket":"presign-bucket","style":"minio"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", code, body)
	}
}

func TestPresign_RejectsExpiryBeyondSevenDays(t *testing.T) {
	f := newPresignFixture(t, "jay.test:9000")

	for _, style := range []string{presignStyleJay, presignStyleAWS} {
		t.Run(style, func(t *testing.T) {
			code, _, body := f.callPresign(t,
				`{"token_id":"presign-token","method":"GET","bucket":"presign-bucket","key":"hello.txt","expires_seconds":604801,"style":"`+style+`"}`)
			if code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", code, body)
			}
		})
	}
}

// TestPresign_ExpiresSecondsIsANumber pins the wire type. jay-admin used to
// send it as a JSON string, which the strict decoder refused — every single
// `jay-admin presign` answered 400 "invalid request body".
func TestPresign_ExpiresSecondsIsANumber(t *testing.T) {
	f := newPresignFixture(t, "jay.test:9000")

	code, _, _ := f.callPresign(t,
		`{"token_id":"presign-token","method":"GET","bucket":"presign-bucket","key":"hello.txt","expires_seconds":"3600"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("a string expires_seconds must be refused, got %d", code)
	}

	code, resp, body := f.callPresign(t,
		`{"token_id":"presign-token","method":"GET","bucket":"presign-bucket","key":"hello.txt","expires_seconds":3600}`)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", code, body)
	}
	if resp.URL == "" {
		t.Fatal("no URL returned")
	}
}

func TestPresign_UnknownTokenIsRefused(t *testing.T) {
	f := newPresignFixture(t, "jay.test:9000")

	for _, style := range []string{presignStyleJay, presignStyleAWS} {
		t.Run(style, func(t *testing.T) {
			code, _, body := f.callPresign(t,
				`{"token_id":"no-such-token","method":"GET","bucket":"presign-bucket","key":"hello.txt","style":"`+style+`"}`)
			if code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", code, body)
			}
		})
	}
}

func TestPresign_RevokedTokenIsRefused(t *testing.T) {
	f := newPresignFixture(t, "jay.test:9000")

	if err := f.db.RevokeToken(testTokenID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	for _, style := range []string{presignStyleJay, presignStyleAWS} {
		t.Run(style, func(t *testing.T) {
			// A URL signed by a revoked token is refused the moment anyone uses
			// it, so answering 200 with one would be a confirmation with
			// nothing behind it.
			code, _, body := f.callPresign(t,
				`{"token_id":"presign-token","method":"GET","bucket":"presign-bucket","key":"hello.txt","style":"`+style+`"}`)
			if code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", code, body)
			}
		})
	}
}

func TestResolvePresignHost(t *testing.T) {
	cases := []struct{ requested, listen, want string }{
		{"", "jay.test:9000", "jay.test:9000"},
		{"otro.test", "jay.test:9000", "otro.test"},
		{"  otro.test  ", "jay.test:9000", "otro.test"},
		// The jay form does not sign the host, so it takes what it is given.
		{"", ":9000", ":9000"},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := resolvePresignHost(c.requested, c.listen); got != c.want {
			t.Fatalf("resolvePresignHost(%q,%q) = %q, want %q", c.requested, c.listen, got, c.want)
		}
	}
}

func TestRequirePresignHostname(t *testing.T) {
	for _, ok := range []string{"jay.test", "jay.test:9000", "127.0.0.1:4010", "[::1]:4010"} {
		if err := requirePresignHostname(ok); err != nil {
			t.Fatalf("requirePresignHostname(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", ":9000", ":4010"} {
		if err := requirePresignHostname(bad); err == nil {
			t.Fatalf("requirePresignHostname(%q) should have failed", bad)
		}
	}
}
