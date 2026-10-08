package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
)

const presignTestSecret = "presign-request-signing-secret"

// presignFixture is a Handler that has a signing secret wired (the shared
// setup helpers leave it empty, which switches the X-Jay branch off) plus a
// bucket owned by the token's account.
func presignFixture(t *testing.T) (*Handler, *meta.DB, *meta.Token, string) {
	t.Helper()
	base, db, tok, secret := fullSetupTestHandler(t)
	h := NewHandler(db, base.store, auth.New(db), testLogger(), maintenance.NewMetrics(), presignTestSecret, nil)
	createBucketForTest(t, db, tok.AccountID, "pb")
	return h, db, tok, secret
}

func presignServe(h *Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func presignObjectExists(t *testing.T, db *meta.DB, bucket, key string) bool {
	t.Helper()
	b, err := db.GetBucket(bucket)
	if err != nil {
		t.Fatalf("get bucket: %v", err)
	}
	_, err = db.GetObjectMeta(b.ID, key)
	return err == nil
}

func TestPresignRequest_GetServedWithBytes(t *testing.T) {
	h, _, tok, secret := presignFixture(t)
	putObjectForTest(t, h, tok, secret, "pb", "k", "hello presign")

	r := httptest.NewRequest(http.MethodGet, "/pb/k", nil)
	if err := PresignRequest(r, presignTestSecret, tok.TokenID, time.Minute); err != nil {
		t.Fatalf("PresignRequest: %v", err)
	}
	w := presignServe(h, r)
	if w.Code != http.StatusOK || w.Body.String() != "hello presign" {
		t.Fatalf("want 200 with bytes, got %d %q", w.Code, w.Body.String())
	}
}

func TestPresignRequest_PutCreatesObject(t *testing.T) {
	h, db, tok, _ := presignFixture(t)

	r := httptest.NewRequest(http.MethodPut, "/pb/up", strings.NewReader("body"))
	if err := PresignRequest(r, presignTestSecret, tok.TokenID, time.Minute); err != nil {
		t.Fatalf("PresignRequest: %v", err)
	}
	if w := presignServe(h, r); w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	if !presignObjectExists(t, db, "pb", "up") {
		t.Fatal("signed PUT left no object")
	}
}

func TestPresignRequest_TamperingIs403AndLeavesNoObject(t *testing.T) {
	cases := map[string]func(r *http.Request){
		"path": func(r *http.Request) { r.URL.Path = "/pb/other" },
		"query value": func(r *http.Request) {
			q := r.URL.Query()
			q.Set("x-id", "tampered")
			r.URL.RawQuery = q.Encode()
		},
		"query added": func(r *http.Request) {
			q := r.URL.Query()
			q.Set("extra", "1")
			r.URL.RawQuery = q.Encode()
		},
		"method": func(r *http.Request) { r.Method = http.MethodDelete },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			h, db, tok, secret := presignFixture(t)
			putObjectForTest(t, h, tok, secret, "pb", "victim", "keep")

			r := httptest.NewRequest(http.MethodPut, "/pb/signed?x-id=PutObject", strings.NewReader("evil"))
			if err := PresignRequest(r, presignTestSecret, tok.TokenID, time.Minute); err != nil {
				t.Fatalf("PresignRequest: %v", err)
			}
			tamper(r)
			if w := presignServe(h, r); w.Code != http.StatusForbidden {
				t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
			}
			if presignObjectExists(t, db, "pb", "signed") || presignObjectExists(t, db, "pb", "other") {
				t.Fatal("tampered PUT left an object")
			}
			if !presignObjectExists(t, db, "pb", "victim") {
				t.Fatal("tampered request deleted the victim object")
			}
		})
	}
}

func TestPresignRequest_WrongSecretIs403(t *testing.T) {
	h, db, tok, _ := presignFixture(t)
	r := httptest.NewRequest(http.MethodPut, "/pb/ws", strings.NewReader("x"))
	if err := PresignRequest(r, "some-other-secret", tok.TokenID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if w := presignServe(h, r); w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
	if presignObjectExists(t, db, "pb", "ws") {
		t.Fatal("object created with a foreign secret")
	}
}

func TestPresignRequest_RevokedTokenIs403(t *testing.T) {
	h, db, tok, _ := presignFixture(t)
	r := httptest.NewRequest(http.MethodPut, "/pb/rev", strings.NewReader("x"))
	if err := PresignRequest(r, presignTestSecret, tok.TokenID, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeToken(tok.TokenID); err != nil {
		t.Fatal(err)
	}
	if w := presignServe(h, r); w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
	if presignObjectExists(t, db, "pb", "rev") {
		t.Fatal("revoked token wrote an object")
	}
}

func TestPresignRequest_ExpiredIs403(t *testing.T) {
	h, db, tok, _ := presignFixture(t)
	r := httptest.NewRequest(http.MethodPut, "/pb/exp", strings.NewReader("x"))
	if err := PresignRequest(r, presignTestSecret, tok.TokenID, time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2100 * time.Millisecond)
	if w := presignServe(h, r); w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
	if presignObjectExists(t, db, "pb", "exp") {
		t.Fatal("expired URL wrote an object")
	}
}

func TestPresignRequest_MaxTTLIsAccepted(t *testing.T) {
	h, _, tok, secret := presignFixture(t)
	putObjectForTest(t, h, tok, secret, "pb", "k", "v")
	r := httptest.NewRequest(http.MethodGet, "/pb/k", nil)
	if err := PresignRequest(r, presignTestSecret, tok.TokenID, auth.MaxPresignExpiry); err != nil {
		t.Fatalf("7 d ttl refused: %v", err)
	}
	if w := presignServe(h, r); w.Code != http.StatusOK {
		t.Fatalf("want 200 at the 7 d ceiling, got %d", w.Code)
	}
}

func TestPresignRequest_RefusalsLeaveURLIntact(t *testing.T) {
	cases := map[string]struct {
		target  string
		header  string
		secret  string
		tokenID string
		ttl     time.Duration
	}{
		"ttl zero":        {"/pb/k?a=1", "", presignTestSecret, "t", 0},
		"ttl negative":    {"/pb/k?a=1", "", presignTestSecret, "t", -time.Minute},
		"ttl over 7 d":    {"/pb/k?a=1", "", presignTestSecret, "t", auth.MaxPresignExpiry + time.Second},
		"empty secret":    {"/pb/k?a=1", "", "", "t", time.Minute},
		"empty token id":  {"/pb/k?a=1", "", presignTestSecret, "", time.Minute},
		"authorization":   {"/pb/k?a=1", "Bearer t:s", presignTestSecret, "t", time.Minute},
		"x-amz in query":  {"/pb/k?X-Amz-Signature=abc", "", presignTestSecret, "t", time.Minute},
		"x-amz lowercase": {"/pb/k?x-amz-date=1", "", presignTestSecret, "t", time.Minute},
		"x-jay in query":  {"/pb/k?X-Jay-Token=evil", "", presignTestSecret, "t", time.Minute},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, c.target, nil)
			if c.header != "" {
				r.Header.Set("Authorization", c.header)
			}
			before := r.URL.String()
			if err := PresignRequest(r, c.secret, c.tokenID, c.ttl); err == nil {
				t.Fatal("want an error")
			}
			if r.URL.String() != before {
				t.Fatalf("URL changed on refusal: %q -> %q", before, r.URL.String())
			}
			if _, err := url.ParseQuery(r.URL.RawQuery); err != nil {
				t.Fatal(err)
			}
		})
	}
}
