package admin

// PND-0187: bucket policies and visibility were implemented and unreachable.
// The evaluator was real and tested; installing one required stopping jay and
// writing the bucket record into bbolt with a purpose-built program.
//
// So no test here asserts that the endpoint answered 200. Every one of them
// asks the S3 handler the SAME question before and after the admin call and
// requires the ANSWER to change — a request that was refused and is now served
// with the right bytes, or the reverse. A 200 from the admin API proves the
// route exists; only the flipped decision proves the policy is installed.

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	policyBucket    = "shared-bucket"
	policyKey       = "public/report.txt"
	policyBody      = "the owner's bytes"
	ownerTokenID    = "owner-token"
	ownerSecret     = "owner-token-secret-value"
	strangerTokenID = "stranger-token"
	strangerSecret  = "stranger-token-secret-value"
)

// policyFixture is one bucket owned by account A holding one object, plus a
// token of account B with wildcard actions and no scopes: the widest credential
// another tenant can hold, and one that must still be refused until the bucket
// itself says otherwise.
type policyFixture struct {
	admin *Handler
	s3    *api.Handler
	db    *meta.DB
}

func newPolicyFixture(t *testing.T) *policyFixture {
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

	owner := createAccountForTest(t, db, "owner")
	stranger := createAccountForTest(t, db, "stranger")
	createTokenForTest(t, db, owner.AccountID, ownerTokenID, ownerSecret)
	createTokenForTest(t, db, stranger.AccountID, strangerTokenID, strangerSecret)

	bucket := &meta.Bucket{
		ID:             uuid.New().String(),
		Name:           policyBucket,
		OwnerAccountID: owner.AccountID,
		Visibility:     meta.VisibilityPrivate,
		Status:         "active",
	}
	if err := db.CreateBucket(bucket); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	au := auth.New(db)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	metrics := maintenance.NewMetrics()

	s3 := api.NewHandler(db, st, au, log, metrics, testSigningKey, nil)
	adm := NewHandler(AdminConfig{
		DB:            db,
		Store:         st,
		Auth:          au,
		AdminToken:    testAdminToken,
		Log:           log,
		Metrics:       metrics,
		SigningSecret: testSigningKey,
		ListenAddr:    ":9000",
	})
	t.Cleanup(func() { _ = adm.Close() })

	f := &policyFixture{admin: adm, s3: s3, db: db}

	// Seed the object through the S3 handler, as the owner.
	put := httptest.NewRequest(http.MethodPut, "http://jay.test/"+policyBucket+"/"+policyKey,
		strings.NewReader(policyBody))
	put.Header.Set("Authorization", bearer(ownerTokenID, ownerSecret))
	w := httptest.NewRecorder()
	s3.ServeHTTP(w, put)
	if w.Code != http.StatusOK {
		t.Fatalf("seed object: want 200, got %d: %s", w.Code, w.Body.String())
	}
	return f
}

func createAccountForTest(t *testing.T, db *meta.DB, name string) *meta.Account {
	t.Helper()
	acc := &meta.Account{AccountID: uuid.New().String(), Name: name, Status: "active"}
	if err := db.CreateAccount(acc); err != nil {
		t.Fatalf("create account %s: %v", name, err)
	}
	return acc
}

func createTokenForTest(t *testing.T, db *meta.DB, accountID, tokenID, secret string) {
	t.Helper()
	hash, err := auth.HashSecret(secret)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	tok := &meta.Token{
		TokenID:        tokenID,
		AccountID:      accountID,
		Name:           tokenID,
		SecretHash:     hash,
		SecretKey:      secret,
		AllowedActions: []string{"*"},
		Status:         "active",
	}
	if err := db.CreateToken(tok); err != nil {
		t.Fatalf("create token %s: %v", tokenID, err)
	}
}

func bearer(tokenID, secret string) string { return "Bearer " + tokenID + ":" + secret }

// get reads the seeded object with the given Authorization header ("" means an
// anonymous request) and returns the status and body the caller saw. This is
// the decision every test below watches.
func (f *policyFixture) get(t *testing.T, authorization string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://jay.test/"+policyBucket+"/"+policyKey, nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	w := httptest.NewRecorder()
	f.s3.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// adminCall issues one admin request. rawBody is sent as-is; "" sends no body.
func (f *policyFixture) adminCall(t *testing.T, method, path, rawBody, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if rawBody != "" {
		body = strings.NewReader(rawBody)
	}
	req := httptest.NewRequest(method, "http://jay.test"+path, body)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.admin.ServeHTTP(w, req)
	return w
}

func (f *policyFixture) putPolicy(t *testing.T, document string) *httptest.ResponseRecorder {
	t.Helper()
	return f.adminCall(t, http.MethodPut, "/_jay/buckets/"+policyBucket+"/policy",
		document, "Bearer "+testAdminToken)
}

func (f *policyFixture) setVisibility(t *testing.T, visibility string) *httptest.ResponseRecorder {
	t.Helper()
	return f.adminCall(t, http.MethodPut, "/_jay/buckets/"+policyBucket+"/visibility",
		`{"visibility":"`+visibility+`"}`, "Bearer "+testAdminToken)
}

// storedPolicy reads the policy straight out of bbolt.
func (f *policyFixture) storedPolicy(t *testing.T) jsontext.Value {
	t.Helper()
	bucket, err := f.db.GetBucket(policyBucket)
	if err != nil {
		t.Fatalf("get bucket: %v", err)
	}
	return bucket.PolicyJSON
}

// crossAccountAllow grants the stranger token read access to one prefix.
const crossAccountAllow = `{
  "version": "2024-01-01",
  "statements": [
    {
      "effect": "allow",
      "actions": ["object:get"],
      "prefixes": ["public/"],
      "subjects": ["` + strangerTokenID + `"]
    }
  ]
}`

func TestPutBucketPolicy_AllowOpensACrossAccountRead(t *testing.T) {
	f := newPolicyFixture(t)
	stranger := bearer(strangerTokenID, strangerSecret)

	// Before: the widest possible token of another account is refused, which is
	// the behaviour PND-0185 established and this must not change.
	if code, body := f.get(t, stranger); code == http.StatusOK || body == policyBody {
		t.Fatalf("the stranger could already read the object (%d, %q) — the test "+
			"would prove nothing", code, body)
	}

	if w := f.putPolicy(t, crossAccountAllow); w.Code != http.StatusOK {
		t.Fatalf("install policy: want 200, got %d: %s", w.Code, w.Body.String())
	}

	// After: the SAME request now succeeds and returns the object's bytes. This
	// is the assertion the pendiente is about — the endpoint changed a decision.
	code, body := f.get(t, stranger)
	if code != http.StatusOK {
		t.Fatalf("after installing the allow the stranger still gets %d: %s", code, body)
	}
	if body != policyBody {
		t.Fatalf("the stranger read %q, want the object's bytes %q", body, policyBody)
	}

	// A key outside the granted prefix is still refused: the statement's scope
	// is real, not decorative.
	req := httptest.NewRequest(http.MethodGet, "http://jay.test/"+policyBucket+"/private/other.txt", nil)
	req.Header.Set("Authorization", stranger)
	w := httptest.NewRecorder()
	f.s3.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("the allow leaked outside its prefix: %d %s", w.Code, w.Body.String())
	}
}

func TestDeleteBucketPolicy_ClosesTheAccessItHadOpened(t *testing.T) {
	f := newPolicyFixture(t)
	stranger := bearer(strangerTokenID, strangerSecret)

	if w := f.putPolicy(t, crossAccountAllow); w.Code != http.StatusOK {
		t.Fatalf("install policy: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if code, body := f.get(t, stranger); code != http.StatusOK || body != policyBody {
		t.Fatalf("precondition: the allow did not take effect (%d, %q)", code, body)
	}

	w := f.adminCall(t, http.MethodDelete, "/_jay/buckets/"+policyBucket+"/policy",
		"", "Bearer "+testAdminToken)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete policy: want 204, got %d: %s", w.Code, w.Body.String())
	}

	if code, body := f.get(t, stranger); code == http.StatusOK || body == policyBody {
		t.Fatalf("the stranger still reads the object after the policy was removed (%d, %q)", code, body)
	}
	if raw := f.storedPolicy(t); len(raw) != 0 {
		t.Fatalf("the policy is still in the database: %s", raw)
	}
}

func TestPutBucketPolicy_DenyClosesTheOwnersOwnRead(t *testing.T) {
	f := newPolicyFixture(t)
	owner := bearer(ownerTokenID, ownerSecret)

	if code, body := f.get(t, owner); code != http.StatusOK || body != policyBody {
		t.Fatalf("precondition: the owner cannot read its own object (%d, %q)", code, body)
	}

	deny := `{"version":"1","statements":[{"effect":"deny","actions":["object:get"],` +
		`"prefixes":["public/"],"subjects":["*"]}]}`
	if w := f.putPolicy(t, deny); w.Code != http.StatusOK {
		t.Fatalf("install deny: want 200, got %d: %s", w.Code, w.Body.String())
	}

	// deny is evaluated after everything else and wins, owner included.
	if code, body := f.get(t, owner); code == http.StatusOK || body == policyBody {
		t.Fatalf("the deny did not take effect for the owner (%d, %q)", code, body)
	}
}

func TestPutBucketVisibility_PublicReadOpensAnonymousGet(t *testing.T) {
	f := newPolicyFixture(t)

	if code, body := f.get(t, ""); code == http.StatusOK || body == policyBody {
		t.Fatalf("the object was already readable with no credentials (%d, %q)", code, body)
	}

	if w := f.setVisibility(t, meta.VisibilityPublicRead); w.Code != http.StatusOK {
		t.Fatalf("set visibility: want 200, got %d: %s", w.Code, w.Body.String())
	}

	code, body := f.get(t, "")
	if code != http.StatusOK || body != policyBody {
		t.Fatalf("public-read did not open the anonymous read (%d, %q)", code, body)
	}

	// And back, because a switch that only goes one way is half a feature.
	if w := f.setVisibility(t, meta.VisibilityPrivate); w.Code != http.StatusOK {
		t.Fatalf("set visibility back: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if code, body := f.get(t, ""); code == http.StatusOK || body == policyBody {
		t.Fatalf("the bucket stayed public after being set back to private (%d, %q)", code, body)
	}
}

func TestPutBucketVisibility_UnknownValueIsRefusedAndNothingChanges(t *testing.T) {
	f := newPolicyFixture(t)

	w := f.setVisibility(t, "public-write")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
	bucket, err := f.db.GetBucket(policyBucket)
	if err != nil {
		t.Fatalf("get bucket: %v", err)
	}
	if bucket.Visibility != meta.VisibilityPrivate {
		t.Fatalf("visibility is now %q — an unrecognised value was stored", bucket.Visibility)
	}
}

// Validation happens where the document ENTERS. Every case below is one that
// parses, stores fine and then silently never matches — which is the failure
// mode an access-control document must never have, because the policy looks
// installed and does nothing.
func TestPutBucketPolicy_InvalidDocumentsAreRefusedAndNotStored(t *testing.T) {
	cases := []struct {
		name     string
		document string
		why      string
	}{
		{
			"unknown action",
			`{"statements":[{"effect":"deny","actions":["object:read"],"subjects":["*"]}]}`,
			"object:read is not an action, so the deny would never fire and the prefix would stay open",
		},
		{
			"unknown effect",
			`{"statements":[{"effect":"Deny-all","actions":["*"],"subjects":["*"]}]}`,
			"an effect that is neither allow nor deny matches nothing",
		},
		{
			"no subjects",
			`{"statements":[{"effect":"allow","actions":["object:get"],"subjects":[]}]}`,
			"matchesSubject returns false on an empty list, so the statement is inert",
		},
		{
			"no actions",
			`{"statements":[{"effect":"allow","actions":[],"subjects":["*"]}]}`,
			"same, one field over",
		},
		{
			"no statements",
			`{"version":"1","statements":[]}`,
			"a policy that grants and denies nothing is a no-op wearing the shape of a policy",
		},
		{
			"malformed CIDR",
			`{"statements":[{"effect":"allow","actions":["object:get"],"subjects":["*"],` +
				`"conditions":{"ip_whitelist":["10.0.0/8"]}}]}`,
			"Compile drops what does not parse and an EMPTY network list matches every address: " +
				"one missing dot turns an internal-only grant into an internet-wide one",
		},
		{
			"not JSON at all",
			`not a policy`,
			"",
		},
		{
			"empty body",
			``,
			"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPolicyFixture(t)

			w := f.putPolicy(t, tc.document)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s\n(%s)", w.Code, w.Body.String(), tc.why)
			}
			if raw := f.storedPolicy(t); len(raw) != 0 {
				t.Fatalf("a refused document was stored anyway: %s", raw)
			}
			// The refusal did not open anything either.
			if code, body := f.get(t, bearer(strangerTokenID, strangerSecret)); code == http.StatusOK {
				t.Fatalf("a refused policy granted access (%d, %q)", code, body)
			}
		})
	}
}

func TestPutBucketPolicy_UnknownBucketIs404(t *testing.T) {
	f := newPolicyFixture(t)

	w := f.adminCall(t, http.MethodPut, "/_jay/buckets/no-such-bucket/policy",
		crossAccountAllow, "Bearer "+testAdminToken)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBucketRoutes_RequireTheAdminToken(t *testing.T) {
	f := newPolicyFixture(t)

	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/_jay/buckets/" + policyBucket, ""},
		{http.MethodPut, "/_jay/buckets/" + policyBucket + "/policy", crossAccountAllow},
		{http.MethodDelete, "/_jay/buckets/" + policyBucket + "/policy", ""},
		{http.MethodPut, "/_jay/buckets/" + policyBucket + "/visibility", `{"visibility":"public-read"}`},
	} {
		w := f.adminCall(t, tc.method, tc.path, tc.body, "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without the admin token: want 401, got %d", tc.method, tc.path, w.Code)
		}
	}

	// And nothing moved.
	if raw := f.storedPolicy(t); len(raw) != 0 {
		t.Fatalf("an unauthenticated call installed a policy: %s", raw)
	}
	if code, _ := f.get(t, ""); code == http.StatusOK {
		t.Fatal("an unauthenticated call opened the bucket to anonymous reads")
	}
}

func TestGetBucket_ReportsWhatWasInstalled(t *testing.T) {
	f := newPolicyFixture(t)

	if w := f.putPolicy(t, crossAccountAllow); w.Code != http.StatusOK {
		t.Fatalf("install policy: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := f.setVisibility(t, meta.VisibilityPublicRead); w.Code != http.StatusOK {
		t.Fatalf("set visibility: want 200, got %d: %s", w.Code, w.Body.String())
	}

	w := f.adminCall(t, http.MethodGet, "/_jay/buckets/"+policyBucket, "", "Bearer "+testAdminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp bucketResponse
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode get-bucket response %q: %v", w.Body.String(), err)
	}
	if resp.Name != policyBucket {
		t.Fatalf("name = %q, want %q", resp.Name, policyBucket)
	}
	if resp.Visibility != meta.VisibilityPublicRead {
		t.Fatalf("visibility = %q, want %q", resp.Visibility, meta.VisibilityPublicRead)
	}
	// The document comes back as it was sent, so an operator can diff what is
	// installed against the file they have.
	var installed auth.BucketPolicy
	if err := jsonv2.Unmarshal(resp.Policy, &installed); err != nil {
		t.Fatalf("the reported policy is not a policy: %v (%s)", err, resp.Policy)
	}
	if len(installed.Statements) != 1 || installed.Statements[0].Effect != "allow" {
		t.Fatalf("the reported policy is not the one installed: %s", resp.Policy)
	}
}
