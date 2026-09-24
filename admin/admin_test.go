package admin

// Tests for the control plane in admin.go: accounts, tokens, revocation,
// metrics, quarantine, and the bearer gate in front of all of it.
//
// Three rules hold for every test in this file, because each one is a defect
// this API could have had while answering with the right status code:
//
//   - A success is checked where it lands: the record in bbolt, the token
//     authenticating through auth (the path the S3 and native listeners use),
//     the object readable or gone on the S3 port.
//   - A refusal is checked for having changed nothing. dbDigest hashes the
//     whole bbolt file, so "nothing moved" covers records nobody thought to
//     look at.
//   - An error is checked for being the structured JSON body clients parse.

import (
	"bytes"
	"crypto/sha256"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	"github.com/ivangsm/jay/api"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
	"golang.org/x/crypto/bcrypt"
)

const (
	ctlBucket      = "control-bucket"
	ctlTokenID     = "control-token"
	ctlTokenSecret = "control-token-secret-value"
	healthyKey     = "healthy.txt"
	healthyBody    = "bytes that nobody should lose"
	sickKey        = "sick.txt"
	sickBody       = "quarantined, but intact on disk"
	adminBearer    = "Bearer " + testAdminToken
	defaultRemote  = "192.0.2.1:4321"
)

// controlFixture is one account with one wildcard token, and one bucket
// holding two objects: healthyKey, active, and sickKey, quarantined with its
// file intact — so a revalidation has something to restore and a purge has
// something it must NOT touch.
type controlFixture struct {
	admin    *Handler
	s3       *api.Handler
	db       *meta.DB
	st       *store.Store
	au       *auth.Auth
	metrics  *maintenance.Metrics
	account  *meta.Account
	bucketID string
}

func newControlFixture(t *testing.T) *controlFixture {
	t.Helper()
	dir := t.TempDir()

	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetSigningSecret(testSigningKey)
	t.Cleanup(func() { _ = db.Close() })

	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	account := createAccountForTest(t, db, "control")
	seedCheapToken(t, db, account.AccountID, ctlTokenID, ctlTokenSecret)

	bucket := &meta.Bucket{
		ID:             uuid.New().String(),
		Name:           ctlBucket,
		OwnerAccountID: account.AccountID,
		Visibility:     meta.VisibilityPrivate,
		Status:         "active",
	}
	if err := db.CreateBucket(bucket); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	au := auth.New(db)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	metrics := maintenance.NewMetrics()

	f := &controlFixture{
		s3:       api.NewHandler(db, st, au, log, metrics, testSigningKey, nil),
		db:       db,
		st:       st,
		au:       au,
		metrics:  metrics,
		account:  account,
		bucketID: bucket.ID,
	}
	f.admin = NewHandler(AdminConfig{
		DB:            db,
		Store:         st,
		Auth:          au,
		AdminToken:    testAdminToken,
		Log:           log,
		Metrics:       metrics,
		SigningSecret: testSigningKey,
		ListenAddr:    "jay.test:9000",
	})
	t.Cleanup(func() { _ = f.admin.Close() })

	// Seeded through the S3 handler, so the files and records are the ones a
	// real PUT leaves — and the token's positive auth cache entry is warm,
	// which is what a revocation has to evict.
	for key, body := range map[string]string{healthyKey: healthyBody, sickKey: sickBody} {
		req := httptest.NewRequest(http.MethodPut, "http://jay.test/"+ctlBucket+"/"+key, strings.NewReader(body))
		req.Header.Set("Authorization", bearer(ctlTokenID, ctlTokenSecret))
		w := httptest.NewRecorder()
		f.s3.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("seed %s: want 200, got %d: %s", key, w.Code, w.Body.String())
		}
	}
	if err := db.QuarantineObject(bucket.ID, sickKey); err != nil {
		t.Fatalf("quarantine %s: %v", sickKey, err)
	}
	return f
}

// cheapHash is bcrypt at its minimum cost. The secrets seeded here are not
// what these tests are about, and at the default cost every fixture spends
// seconds hashing under -race. Tokens minted through the API still get the
// real cost.
func cheapHash(t *testing.T, secret string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return string(hash)
}

// seedCheapToken stores a wildcard token whose secret is hashed by cheapHash.
func seedCheapToken(t *testing.T, db *meta.DB, accountID, tokenID, secret string) {
	t.Helper()
	if err := db.CreateToken(&meta.Token{
		TokenID: tokenID, AccountID: accountID, Name: tokenID, SecretHash: cheapHash(t, secret),
		SecretKey: secret, AllowedActions: []string{"*"}, Status: "active",
	}); err != nil {
		t.Fatalf("create token %s: %v", tokenID, err)
	}
}

// call issues one admin request from remoteAddr. rawBody "" sends no body and
// authorization "" sends no Authorization header.
func (f *controlFixture) call(t *testing.T, method, path, rawBody, authorization, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if rawBody != "" {
		body = strings.NewReader(rawBody)
	}
	req := httptest.NewRequest(method, "http://jay.test"+path, body)
	req.RemoteAddr = remoteAddr
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	w := httptest.NewRecorder()
	f.admin.ServeHTTP(w, req)
	return w
}

// as issues one request with the admin token.
func (f *controlFixture) as(t *testing.T, method, path, rawBody string) *httptest.ResponseRecorder {
	t.Helper()
	return f.call(t, method, path, rawBody, adminBearer, defaultRemote)
}

// s3Get reads key from the fixture bucket as the fixture token.
func (f *controlFixture) s3Get(t *testing.T, key string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://jay.test/"+ctlBucket+"/"+key, nil)
	req.Header.Set("Authorization", bearer(ctlTokenID, ctlTokenSecret))
	w := httptest.NewRecorder()
	f.s3.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// objectState returns the state of key in bbolt, or "" when there is no record.
func (f *controlFixture) objectState(t *testing.T, key string) string {
	t.Helper()
	obj, err := f.db.GetObjectMetaAny(f.bucketID, key)
	if errors.Is(err, meta.ErrObjectNotFound) {
		return ""
	}
	if err != nil {
		t.Fatalf("get object %s: %v", key, err)
	}
	return obj.State
}

// objectFile returns the path of key's file on disk. The record must exist.
func (f *controlFixture) objectFile(t *testing.T, key string) string {
	t.Helper()
	obj, err := f.db.GetObjectMetaAny(f.bucketID, key)
	if err != nil {
		t.Fatalf("get object %s: %v", key, err)
	}
	path, err := f.st.SafePath(obj.LocationRef)
	if err != nil {
		t.Fatalf("resolve %s: %v", obj.LocationRef, err)
	}
	return path
}

// dbDigest hashes a consistent copy of the whole bbolt file. Two equal digests
// mean no write transaction committed in between — for every record, including
// the ones a test did not think to check.
func (f *controlFixture) dbDigest(t *testing.T) [sha256.Size]byte {
	t.Helper()
	var buf bytes.Buffer
	if err := f.db.Backup(&buf); err != nil {
		t.Fatalf("backup: %v", err)
	}
	return sha256.Sum256(buf.Bytes())
}

func (f *controlFixture) requireUnchanged(t *testing.T, before [sha256.Size]byte, what string) {
	t.Helper()
	if f.dbDigest(t) != before {
		t.Fatalf("%s wrote to the database", what)
	}
}

// Every "changed nothing" assertion in this file rests on dbDigest seeing a
// write. If it did not, they would all pass vacuously.
func TestDBDigest_SeesACommittedWrite(t *testing.T) {
	f := newControlFixture(t)
	before := f.dbDigest(t)
	if f.dbDigest(t) != before {
		t.Fatal("two digests with no write in between differ; the digest is not stable")
	}
	if err := f.db.RevokeToken(ctlTokenID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if f.dbDigest(t) == before {
		t.Fatal("a committed write left the digest unchanged; requireUnchanged would prove nothing")
	}
}

// errorMessage requires the body to be the API's JSON error document, labelled
// as JSON, and returns its message.
func errorMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("error response (%d) has Content-Type %q, want application/json: %s", w.Code, ct, w.Body.String())
	}
	var doc struct {
		Error string `json:"error"`
	}
	if err := jsonv2.Unmarshal(bytes.TrimSpace(w.Body.Bytes()), &doc); err != nil {
		t.Fatalf("error body is not JSON (%d): %q: %v", w.Code, w.Body.String(), err)
	}
	if doc.Error == "" {
		t.Fatalf("error body has no \"error\" message (%d): %s", w.Code, w.Body.String())
	}
	return doc.Error
}

func requireStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("want %d, got %d: %s", want, w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Every route, and the gate in front of it
// ---------------------------------------------------------------------------

// adminRoute is one row of the test's route table: a route the handler serves,
// spelled "METHOD pattern" exactly as in admin.go's routes, and a request to it
// that must succeed with the admin token.
type adminRoute struct {
	signature  string
	method     string
	path       func(f *controlFixture) string
	body       func(f *controlFixture) string
	wantStatus int
}

func fixed(s string) func(*controlFixture) string { return func(*controlFixture) string { return s } }

// adminRoutes is checked against the handler's own routes table by
// TestAdminRoutes_TableMatchesTheRouter, so an endpoint added to the handler
// without a row here fails the build — and with a row, it is covered by the
// authentication test below.
var adminRoutes = []adminRoute{
	{"POST /accounts", http.MethodPost, fixed("/_jay/accounts"), fixed(`{"name":"from-the-table"}`), http.StatusCreated},
	{"POST /tokens", http.MethodPost, fixed("/_jay/tokens"), func(f *controlFixture) string {
		return `{"account_id":"` + f.account.AccountID + `","name":"t","allowed_actions":["object:get"]}`
	}, http.StatusCreated},
	{"GET /tokens", http.MethodGet, fixed("/_jay/tokens"), fixed(""), http.StatusOK},
	{"DELETE /tokens/{id...}", http.MethodDelete, fixed("/_jay/tokens/" + ctlTokenID), fixed(""), http.StatusNoContent},
	{"GET /metrics", http.MethodGet, fixed("/_jay/metrics"), fixed(""), http.StatusOK},
	{"POST /presign", http.MethodPost, fixed("/_jay/presign"),
		fixed(`{"token_id":"` + ctlTokenID + `","method":"GET","bucket":"` + ctlBucket + `","key":"` + healthyKey + `"}`),
		http.StatusOK},
	{"GET /quarantine", http.MethodGet, fixed("/_jay/quarantine"), fixed(""), http.StatusOK},
	{"DELETE /quarantine", http.MethodDelete, fixed("/_jay/quarantine"), fixed(`{"mode":"all"}`), http.StatusOK},
	{"POST /quarantine/revalidate", http.MethodPost, fixed("/_jay/quarantine/revalidate"), func(f *controlFixture) string {
		return `{"bucket_id":"` + f.bucketID + `","key":"` + sickKey + `"}`
	}, http.StatusOK},
	{"GET /buckets/{name}", http.MethodGet, fixed("/_jay/buckets/" + ctlBucket), fixed(""), http.StatusOK},
	{"PUT /buckets/{name}/policy", http.MethodPut, fixed("/_jay/buckets/" + ctlBucket + "/policy"),
		fixed(`{"statements":[{"effect":"deny","actions":["object:delete"],"subjects":["*"]}]}`), http.StatusOK},
	{"DELETE /buckets/{name}/policy", http.MethodDelete, fixed("/_jay/buckets/" + ctlBucket + "/policy"), fixed(""), http.StatusNoContent},
	{"PUT /buckets/{name}/visibility", http.MethodPut, fixed("/_jay/buckets/" + ctlBucket + "/visibility"),
		fixed(`{"visibility":"public-read"}`), http.StatusOK},
}

func TestAdminRoutes_TableMatchesTheRouter(t *testing.T) {
	inRouter := map[string]bool{}
	for _, r := range routes {
		inRouter[r.method+" "+r.pattern] = true
	}
	inTable := map[string]bool{}
	for _, r := range adminRoutes {
		if inTable[r.signature] {
			t.Errorf("%s appears twice in adminRoutes", r.signature)
		}
		inTable[r.signature] = true
		if !strings.HasPrefix(r.signature, r.method+" ") {
			t.Errorf("%s: the row's method is %s", r.signature, r.method)
		}
	}
	for sig := range inRouter {
		if !inTable[sig] {
			t.Errorf("the handler serves %s but adminRoutes has no row for it, so nothing checks that it "+
				"requires the admin token: add one", sig)
		}
	}
	for sig := range inTable {
		if !inRouter[sig] {
			t.Errorf("adminRoutes has %s but the handler does not serve it", sig)
		}
	}
}

// badCredentials are the Authorization headers the gate must refuse. Every one
// is close to the real one, because those are the ones a sloppy comparison
// (prefix, case-insensitive, trimmed) would let through.
var badCredentials = []struct{ name, header string }{
	{"no header", ""},
	{"scheme only", "Bearer"},
	{"empty bearer", "Bearer "},
	{"lower-case scheme", "bearer " + testAdminToken},
	{"basic scheme", "Basic " + testAdminToken},
	{"token without scheme", testAdminToken},
	{"double space", "Bearer  " + testAdminToken},
	{"trailing space", "Bearer " + testAdminToken + " "},
	{"prefix of the token", "Bearer " + testAdminToken[:len(testAdminToken)-1]},
	{"token plus a suffix", "Bearer " + testAdminToken + "x"},
	{"wrong token", "Bearer not-the-admin-token-at-all"},
	{"an S3 token", bearer(ctlTokenID, ctlTokenSecret)},
}

func TestAdminRoutes_EveryRouteRequiresTheAdminToken(t *testing.T) {
	for _, route := range adminRoutes {
		t.Run(route.signature, func(t *testing.T) {
			f := newControlFixture(t)
			path, body := route.path(f), route.body(f)
			before := f.dbDigest(t)

			for i, bad := range badCredentials {
				// One source address per attempt: the per-IP lockout would
				// otherwise refuse the valid call at the end for the wrong
				// reason.
				remote := "198.51.100." + strconv.Itoa(i+1) + ":1234"
				w := f.call(t, route.method, path, body, bad.header, remote)
				if w.Code != http.StatusUnauthorized {
					t.Fatalf("%s: want 401, got %d: %s", bad.name, w.Code, w.Body.String())
				}
				if msg := errorMessage(t, w); msg != "unauthorized" {
					t.Fatalf("%s: error = %q, want \"unauthorized\"", bad.name, msg)
				}
			}

			f.requireUnchanged(t, before, "an unauthenticated call")
			if got := f.objectState(t, sickKey); got != "quarantined" {
				t.Fatalf("an unauthenticated call moved the quarantined object to %q", got)
			}
			if _, err := os.Stat(f.objectFile(t, sickKey)); err != nil {
				t.Fatalf("an unauthenticated call removed the quarantined file: %v", err)
			}

			// And with the token the route is really there: the row is not a
			// path that falls through to the router's 404.
			w := f.as(t, route.method, path, body)
			requireStatus(t, w, route.wantStatus)
		})
	}
}

// A database that fails is jay's problem, and has to be reported as one: a 500
// with the JSON error, never a 2xx and never a 4xx that sends the operator off
// to check an id that is fine. (A server started with the wrong
// JAY_SIGNING_SECRET is the realistic case: every token read fails to decrypt.)
func TestAdminRoutes_ADatabaseFailureIsAServerError(t *testing.T) {
	noDatabase := map[string]bool{"GET /metrics": true}

	for _, route := range adminRoutes {
		t.Run(route.signature, func(t *testing.T) {
			f := newControlFixture(t)
			path, body := route.path(f), route.body(f)
			if err := f.db.Close(); err != nil {
				t.Fatalf("close db: %v", err)
			}

			w := f.as(t, route.method, path, body)
			if noDatabase[route.signature] {
				requireStatus(t, w, route.wantStatus)
				return
			}
			requireStatus(t, w, http.StatusInternalServerError)
			_ = errorMessage(t, w)
		})
	}
}

// The gate runs before the router looks at the path, so an unknown path tells
// an unauthenticated caller nothing about which routes exist.
func TestAdminAuth_RunsBeforeRouting(t *testing.T) {
	f := newControlFixture(t)

	w := f.call(t, http.MethodGet, "/_jay/no-such-route", "", "", defaultRemote)
	requireStatus(t, w, http.StatusUnauthorized)

	w = f.as(t, http.MethodGet, "/_jay/no-such-route", "")
	requireStatus(t, w, http.StatusNotFound)
	if msg := errorMessage(t, w); msg != "not found" {
		t.Fatalf("error = %q, want \"not found\"", msg)
	}
}

// With no admin token configured the comparison would be against "Bearer ",
// which an empty bearer matches. The gate has to refuse everything instead.
func TestAdminAuth_EmptyConfiguredTokenRefusesEverything(t *testing.T) {
	h := NewHandler(AdminConfig{
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics: maintenance.NewMetrics(),
	})
	t.Cleanup(func() { _ = h.Close() })

	for i, header := range []string{"", "Bearer", "Bearer ", "Bearer x"} {
		req := httptest.NewRequest(http.MethodGet, "http://jay.test/_jay/metrics", nil)
		req.RemoteAddr = "203.0.113." + strconv.Itoa(i+1) + ":1"
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("Authorization %q with no admin token configured: want 401, got %d", header, w.Code)
		}
	}
}

// gateOnlyHandler is an admin handler with no database: enough to exercise the
// bearer gate through GET /_jay/metrics, which needs nothing else.
func gateOnlyHandler(t *testing.T) *Handler {
	t.Helper()
	h := NewHandler(AdminConfig{
		AdminToken: testAdminToken,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:    maintenance.NewMetrics(),
	})
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func metricsFrom(t *testing.T, h http.Handler, authorization, remote string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://jay.test/_jay/metrics", nil)
	req.RemoteAddr = remote
	req.Header.Set("Authorization", authorization)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

// Five failures from one address lock that address out — including for the
// right token — while every other address is unaffected.
func TestAdminAuth_RepeatedFailuresLockTheSourceOut(t *testing.T) {
	h := gateOnlyHandler(t)
	const attacker, operator = "192.0.2.66:5000", "192.0.2.77:5000"

	for i := range maxAuthFailures {
		if code := metricsFrom(t, h, "Bearer wrong-guess", attacker); code != http.StatusUnauthorized {
			t.Fatalf("failure %d: want 401, got %d", i+1, code)
		}
	}
	if code := metricsFrom(t, h, adminBearer, attacker); code != http.StatusUnauthorized {
		t.Fatalf("after %d failures the right token from the same address got %d, want 401", maxAuthFailures, code)
	}
	if code := metricsFrom(t, h, adminBearer, operator); code != http.StatusOK {
		t.Fatalf("another address was locked out too: %d", code)
	}
}

// A success clears the count, so an operator who mistypes now and then is
// never locked out by failures spread over the day.
func TestAdminAuth_SuccessClearsTheFailureCount(t *testing.T) {
	h := gateOnlyHandler(t)
	const operator = "192.0.2.88:5000"

	for round := range 3 {
		for range maxAuthFailures - 1 {
			_ = metricsFrom(t, h, "Bearer typo", operator)
		}
		if code := metricsFrom(t, h, adminBearer, operator); code != http.StatusOK {
			t.Fatalf("round %d: the right token got %d after %d failures", round, code, maxAuthFailures-1)
		}
	}
}

// RequireAdmin (the pprof guard) is the same gate with the same counter:
// guessing on /debug/pprof must cost the same as guessing on /_jay.
func TestRequireAdmin_SharesTheGateAndItsCounter(t *testing.T) {
	h := gateOnlyHandler(t)
	reached := 0
	guarded := h.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusOK)
	}))
	const source = "192.0.2.99:5000"

	for range maxAuthFailures {
		if code := metricsFrom(t, guarded, "Bearer guess", source); code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", code)
		}
	}
	if reached != 0 {
		t.Fatalf("the guarded handler ran %d times without the token", reached)
	}
	// The failures on the guard locked the address out of the admin API.
	if code := metricsFrom(t, h, adminBearer, source); code != http.StatusUnauthorized {
		t.Fatalf("failures on RequireAdmin did not count toward the admin lockout: %d", code)
	}
	if code := metricsFrom(t, guarded, adminBearer, "192.0.2.100:5000"); code != http.StatusOK || reached != 1 {
		t.Fatalf("with the token from a clean address: status %d, reached %d times", code, reached)
	}
}

func TestAdminAuth_LockoutEndsAfterTheWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := gateOnlyHandler(t)
		const source = "192.0.2.10:5000"

		for range maxAuthFailures {
			_ = metricsFrom(t, h, "Bearer guess", source)
		}
		time.Sleep(authFailureWindow - time.Second)
		if code := metricsFrom(t, h, adminBearer, source); code != http.StatusUnauthorized {
			t.Fatalf("still inside the window: want 401, got %d", code)
		}
		time.Sleep(2 * time.Second)
		if code := metricsFrom(t, h, adminBearer, source); code != http.StatusOK {
			t.Fatalf("after the window: want 200, got %d", code)
		}
	})
}

func TestAdminAuth_SweeperForgetsStaleFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := gateOnlyHandler(t)
		_ = metricsFrom(t, h, "Bearer guess", "192.0.2.11:5000")
		if n := h.authFailureMapLen(); n != 1 {
			t.Fatalf("tracked sources = %d, want 1", n)
		}

		// The first sweep finds the entry still inside its window.
		time.Sleep(authFailureSweepInt)
		synctest.Wait()
		if n := h.authFailureMapLen(); n != 1 {
			t.Fatalf("a failure inside its window was swept: tracked = %d", n)
		}

		time.Sleep(authFailureWindow)
		synctest.Wait()
		if n := h.authFailureMapLen(); n != 0 {
			t.Fatalf("stale failures were not swept: tracked = %d", n)
		}
	})
}

// The failure map is capped so rotating source addresses cannot grow it
// without bound. Crossing the cap evicts the OLDEST entries — never the
// failure that was just recorded, or the address that triggered the eviction
// would start over from zero failures.
func TestAdminAuth_FailureMapEvictsTheOldest(t *testing.T) {
	h := gateOnlyHandler(t)

	start := time.Now().Add(-authFailureWindow / 2)
	ip := func(i int) string {
		return "10." + strconv.Itoa(i/65536) + "." + strconv.Itoa(i/256%256) + "." + strconv.Itoa(i%256)
	}
	for i := range authFailureCap {
		h.recordAuthFailure(ip(i), start.Add(time.Duration(i)*time.Millisecond))
	}

	const newcomer = "172.16.0.1"
	if code := metricsFrom(t, h, "Bearer guess", newcomer+":1"); code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", code)
	}

	if n, want := h.authFailureMapLen(), authFailureCap+1-authFailureEvictN; n != want {
		t.Fatalf("tracked sources = %d, want %d", n, want)
	}
	if _, ok := h.authFailures.Load(newcomer); !ok {
		t.Fatal("the failure that crossed the cap was evicted instead of the oldest entry")
	}
	for i := range authFailureEvictN {
		if _, ok := h.authFailures.Load(ip(i)); ok {
			t.Fatalf("entry %d, among the %d oldest, survived the eviction", i, authFailureEvictN)
		}
	}
	if _, ok := h.authFailures.Load(ip(authFailureEvictN)); !ok {
		t.Fatalf("entry %d is not among the %d oldest but was evicted", authFailureEvictN, authFailureEvictN)
	}
}

// authFailureMapLen is a counter kept beside the map, not a walk of it. Every
// path that adds or drops an entry has to keep the two in step, or the cap
// check drifts: too high and it evicts for nothing, too low and the map grows
// past the cap it exists to enforce.
func TestAdminAuth_TheFailureCountMatchesTheMap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := gateOnlyHandler(t)
		walk := func() int {
			n := 0
			h.authFailures.Range(func(_, _ any) bool { n++; return true })
			return n
		}
		requireInStep := func(when string) {
			t.Helper()
			if got, want := h.authFailureMapLen(), walk(); got != want {
				t.Fatalf("%s: counter says %d tracked sources, the map holds %d", when, got, want)
			}
		}

		for i := range 20 {
			_ = metricsFrom(t, h, "Bearer guess", "198.18.0."+strconv.Itoa(i)+":1")
			_ = metricsFrom(t, h, "Bearer guess", "198.18.0."+strconv.Itoa(i)+":1") // same source again
		}
		requireInStep("after failures")

		for i := range 5 {
			_ = metricsFrom(t, h, adminBearer, "198.18.0."+strconv.Itoa(i)+":1") // success clears
		}
		requireInStep("after successes")

		time.Sleep(authFailureSweepInt + authFailureWindow)
		synctest.Wait()
		requireInStep("after the sweep")
		if h.authFailureMapLen() != 0 {
			t.Fatalf("the sweep left %d sources", h.authFailureMapLen())
		}

		for i := range authFailureCap + 5 {
			h.recordAuthFailure("10.9."+strconv.Itoa(i/256)+"."+strconv.Itoa(i%256), time.Now())
		}
		requireInStep("after crossing the cap")
		if n := h.authFailureMapLen(); n > authFailureCap {
			t.Fatalf("the map holds %d sources, over the cap of %d", n, authFailureCap)
		}
	})
}

// A method a path does not serve is a 405 that names the methods it does
// serve, and it changes nothing.
func TestAdminRouter_UnservedMethodIs405WithAllow(t *testing.T) {
	f := newControlFixture(t)
	before := f.dbDigest(t)

	for _, c := range []struct{ method, path, body, allow string }{
		{http.MethodGet, "/_jay/accounts", "", "POST"},
		{http.MethodPut, "/_jay/accounts", `{"name":"x"}`, "POST"},
		{http.MethodDelete, "/_jay/tokens", "", "GET, POST"},
		{http.MethodPost, "/_jay/tokens/" + ctlTokenID, "", "DELETE"},
		{http.MethodGet, "/_jay/tokens/" + ctlTokenID, "", "DELETE"},
		{http.MethodPost, "/_jay/metrics", "", "GET"},
		{http.MethodGet, "/_jay/presign", "", "POST"},
		{http.MethodPost, "/_jay/quarantine", `{"mode":"all"}`, "DELETE, GET"},
		{http.MethodPut, "/_jay/quarantine", `{"mode":"all"}`, "DELETE, GET"},
		{http.MethodGet, "/_jay/quarantine/revalidate", "", "POST"},
		{http.MethodDelete, "/_jay/quarantine/revalidate", `{"mode":"all"}`, "POST"},
		{http.MethodPost, "/_jay/buckets/" + ctlBucket, "", "GET"},
		{http.MethodDelete, "/_jay/buckets/" + ctlBucket, "", "GET"},
		{http.MethodGet, "/_jay/buckets/" + ctlBucket + "/policy", "", "DELETE, PUT"},
		{http.MethodPost, "/_jay/buckets/" + ctlBucket + "/policy", `{"statements":[]}`, "DELETE, PUT"},
		{http.MethodDelete, "/_jay/buckets/" + ctlBucket + "/visibility", "", "PUT"},
	} {
		w := f.as(t, c.method, c.path, c.body)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: want 405, got %d: %s", c.method, c.path, w.Code, w.Body.String())
		}
		if got := w.Header().Get("Allow"); got != c.allow {
			t.Fatalf("%s %s: Allow = %q, want %q", c.method, c.path, got, c.allow)
		}
		if msg := errorMessage(t, w); msg != "method not allowed" {
			t.Fatalf("%s %s: error = %q", c.method, c.path, msg)
		}
	}
	f.requireUnchanged(t, before, "a refused method")
}

// A path no route serves is a 404, whatever the method.
func TestAdminRouter_UnknownPathIs404(t *testing.T) {
	f := newControlFixture(t)
	before := f.dbDigest(t)

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/_jay/no-such-route"},
		{http.MethodDelete, "/_jay/tokens/"},
		{http.MethodGet, "/_jay/buckets/"},
		{http.MethodGet, "/_jay/buckets/" + ctlBucket + "/acl"},
		{http.MethodPut, "/_jay/buckets/" + ctlBucket + "/policy/extra"},
		{http.MethodPost, "/_jay/accounts/extra"},
	} {
		w := f.as(t, c.method, c.path, "")
		if w.Code != http.StatusNotFound || w.Header().Get("Allow") != "" {
			t.Fatalf("%s %s: want 404 without Allow, got %d (Allow %q): %s",
				c.method, c.path, w.Code, w.Header().Get("Allow"), w.Body.String())
		}
		if msg := errorMessage(t, w); msg != "not found" {
			t.Fatalf("%s %s: error = %q", c.method, c.path, msg)
		}
	}
	f.requireUnchanged(t, before, "a request to an unknown path")
}

func TestMatchPattern(t *testing.T) {
	for _, c := range []struct {
		pattern, path, param string
		ok                   bool
	}{
		{"/accounts", "/accounts", "", true},
		{"/accounts", "/accounts/", "", false},
		{"/accounts", "/account", "", false},
		{"/tokens/{id...}", "/tokens/abc", "abc", true},
		{"/tokens/{id...}", "/tokens/a/b", "a/b", true},
		{"/tokens/{id...}", "/tokens/", "", false},
		{"/tokens/{id...}", "/tokens", "", false},
		{"/buckets/{name}", "/buckets/photos", "photos", true},
		{"/buckets/{name}", "/buckets/", "", false},
		{"/buckets/{name}", "/buckets/photos/policy", "", false},
		{"/buckets/{name}/policy", "/buckets/photos/policy", "photos", true},
		{"/buckets/{name}/policy", "/buckets//policy", "", false},
	} {
		param, ok := matchPattern(c.pattern, c.path)
		if ok != c.ok || param != c.param {
			t.Errorf("matchPattern(%q, %q) = %q, %v; want %q, %v", c.pattern, c.path, param, ok, c.param, c.ok)
		}
	}
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

func TestCreateAccount_PersistsTheAccount(t *testing.T) {
	f := newControlFixture(t)

	w := f.as(t, http.MethodPost, "/_jay/accounts", `{"name":"acme"}`)
	requireStatus(t, w, http.StatusCreated)

	var resp meta.Account
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	stored, err := f.db.GetAccount(resp.AccountID)
	if err != nil {
		t.Fatalf("the account the API reported (%q) is not in the database: %v", resp.AccountID, err)
	}
	if stored.Name != "acme" || stored.Status != "active" {
		t.Fatalf("stored account = %+v, want name acme and status active", stored)
	}
}

func TestCreateAccount_RefusesBadBodiesAndCreatesNothing(t *testing.T) {
	f := newControlFixture(t)
	before := f.dbDigest(t)

	for _, c := range []struct{ name, body, wantError string }{
		{"no body", "", "invalid request body"},
		{"not JSON", `{"name":`, "invalid request body"},
		{"misspelt field", `{"nmae":"acme"}`, "invalid request body"},
		{"wrong type", `{"name":5}`, "invalid request body"},
		{"array", `["acme"]`, "invalid request body"},
		// There is no endpoint that lists accounts: the name is the only
		// handle an operator has on one.
		{"no name", `{}`, "name is required"},
		{"empty name", `{"name":""}`, "name is required"},
		{"blank name", `{"name":"  \t"}`, "name is required"},
	} {
		w := f.as(t, http.MethodPost, "/_jay/accounts", c.body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d: %s", c.name, w.Code, w.Body.String())
		}
		if msg := errorMessage(t, w); msg != c.wantError {
			t.Fatalf("%s: error = %q, want %q", c.name, msg, c.wantError)
		}
	}
	f.requireUnchanged(t, before, "a refused create-account")
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

type createdToken struct {
	TokenID   string     `json:"token_id"`
	Secret    string     `json:"secret"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func (f *controlFixture) createToken(t *testing.T, body string) createdToken {
	t.Helper()
	w := f.as(t, http.MethodPost, "/_jay/tokens", body)
	requireStatus(t, w, http.StatusCreated)
	var tok createdToken
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &tok); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	if tok.TokenID == "" || tok.Secret == "" {
		t.Fatalf("create-token answered 201 without a token id or secret: %s", w.Body.String())
	}
	return tok
}

// The secret the API returns is checked the way every client presents it —
// through auth, and then against the S3 port — not by reading the record.
func TestCreateToken_TheReturnedSecretAuthenticates(t *testing.T) {
	f := newControlFixture(t)

	tok := f.createToken(t, `{"account_id":"`+f.account.AccountID+`","name":"reader",`+
		`"allowed_actions":["object:get"],"bucket_scope":["`+ctlBucket+`"],"prefix_scope":["healthy"]}`)

	got, err := f.au.AuthenticateCredentials(tok.TokenID, tok.Secret)
	if err != nil {
		t.Fatalf("the returned secret does not authenticate: %v", err)
	}
	if got.AccountID != f.account.AccountID || !slices.Equal(got.AllowedActions, []string{"object:get"}) ||
		!slices.Equal(got.BucketScope, []string{ctlBucket}) || !slices.Equal(got.PrefixScope, []string{"healthy"}) {
		t.Fatalf("the stored token is not the one requested: %+v", got)
	}
	if _, err := f.au.AuthenticateCredentials(tok.TokenID, tok.Secret+"x"); err == nil {
		t.Fatal("a different secret authenticated as the new token")
	}

	req := httptest.NewRequest(http.MethodGet, "http://jay.test/"+ctlBucket+"/"+healthyKey, nil)
	req.Header.Set("Authorization", bearer(tok.TokenID, tok.Secret))
	w := httptest.NewRecorder()
	f.s3.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != healthyBody {
		t.Fatalf("the new token cannot read through the S3 port: %d %q", w.Code, w.Body.String())
	}

	// The scope is real: object:get only, so a write is refused.
	put := httptest.NewRequest(http.MethodPut, "http://jay.test/"+ctlBucket+"/healthy-2.txt", strings.NewReader("x"))
	put.Header.Set("Authorization", bearer(tok.TokenID, tok.Secret))
	w = httptest.NewRecorder()
	f.s3.ServeHTTP(w, put)
	if w.Code == http.StatusOK {
		t.Fatal("a token created with object:get only could write")
	}
}

func TestCreateToken_RefusalsCreateNothing(t *testing.T) {
	f := newControlFixture(t)
	acc := f.account.AccountID
	before := f.dbDigest(t)

	for _, c := range []struct{ name, body, wantError string }{
		{"no body", "", "invalid request body"},
		{"not JSON", `{"account_id":`, "invalid request body"},
		{"misspelt field", `{"account":"` + acc + `","allowed_actions":["*"]}`, "invalid request body"},
		{"actions as a string", `{"account_id":"` + acc + `","allowed_actions":"*"}`, "invalid request body"},
		{"no account_id", `{"name":"x","allowed_actions":["*"]}`, "account_id required"},
		{"unknown account", `{"account_id":"no-such-account","allowed_actions":["*"]}`, "account not found"},
		{"no allowed_actions", `{"account_id":"` + acc + `","name":"x"}`, "allowed_actions is required"},
		{"empty allowed_actions", `{"account_id":"` + acc + `","allowed_actions":[]}`, "allowed_actions is required"},
	} {
		w := f.as(t, http.MethodPost, "/_jay/tokens", c.body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d: %s", c.name, w.Code, w.Body.String())
		}
		if msg := errorMessage(t, w); msg != c.wantError {
			t.Fatalf("%s: error = %q, want %q", c.name, msg, c.wantError)
		}
	}
	f.requireUnchanged(t, before, "a refused create-token")
}

// An action jay does not know matches nothing: the token would answer 201 and
// fail every request that needed that action. Refused where it enters, like a
// bucket policy's.
func TestCreateToken_UnknownActionIsRefused(t *testing.T) {
	f := newControlFixture(t)
	acc := f.account.AccountID
	before := f.dbDigest(t)

	for _, c := range []struct{ name, actions, bad string }{
		{"a verb S3 does not use here", `["object:read"]`, "object:read"},
		{"one typo among valid ones", `["object:get","objects:put"]`, "objects:put"},
		{"a partial wildcard", `["object:*"]`, "object:*"},
		{"wrong case", `["Object:Get"]`, "Object:Get"},
		{"empty string", `[""]`, ""},
	} {
		w := f.as(t, http.MethodPost, "/_jay/tokens", `{"account_id":"`+acc+`","allowed_actions":`+c.actions+`}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d: %s", c.name, w.Code, w.Body.String())
		}
		msg := errorMessage(t, w)
		if !strings.Contains(msg, strconv.Quote(c.bad)) || !strings.Contains(msg, meta.ActionObjectGet) {
			t.Fatalf("%s: the error neither names %q nor lists the valid actions: %q", c.name, c.bad, msg)
		}
	}
	f.requireUnchanged(t, before, "a create-token with an unknown action")

	// Every real action, and the wildcard, is accepted.
	for _, actions := range [][]string{meta.AllActions, {"*"}} {
		quoted := make([]string, len(actions))
		for i, a := range actions {
			quoted[i] = strconv.Quote(a)
		}
		tok := f.createToken(t, `{"account_id":"`+acc+`","allowed_actions":[`+strings.Join(quoted, ",")+`]}`)
		stored, err := f.db.GetToken(tok.TokenID)
		if err != nil || !slices.Equal(stored.AllowedActions, actions) {
			t.Fatalf("stored actions = %v (%v), want %v", stored, err, actions)
		}
	}
}

// expires_at is part of the request type, so the strict decoder accepts it. A
// field that is accepted has to be honoured: a caller that asked for a token
// that dies on Friday and got 201 must not hold one that never dies.
func TestCreateToken_HonoursExpiresAt(t *testing.T) {
	f := newControlFixture(t)
	want := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)

	tok := f.createToken(t, `{"account_id":"`+f.account.AccountID+`","allowed_actions":["object:get"],`+
		`"expires_at":"`+want.Format(time.RFC3339)+`"}`)

	stored, err := f.db.GetToken(tok.TokenID)
	if err != nil {
		t.Fatalf("get token: %v", err)
	}
	if stored.ExpiresAt == nil || !stored.ExpiresAt.Equal(want) {
		t.Fatalf("stored expires_at = %v, want %v — the requested expiry was dropped", stored.ExpiresAt, want)
	}
	if tok.ExpiresAt == nil || !tok.ExpiresAt.Equal(want) {
		t.Fatalf("the response does not confirm the expiry it installed: %v", tok.ExpiresAt)
	}
	if _, err := f.au.AuthenticateCredentials(tok.TokenID, tok.Secret); err != nil {
		t.Fatalf("a token that has not expired yet does not authenticate: %v", err)
	}

	// Without expires_at the token does not expire, and the response says
	// nothing about an expiry.
	open := f.createToken(t, `{"account_id":"`+f.account.AccountID+`","allowed_actions":["object:get"]}`)
	if stored, err := f.db.GetToken(open.TokenID); err != nil || stored.ExpiresAt != nil {
		t.Fatalf("a token created without expires_at: %+v, %v", stored, err)
	}
	if open.ExpiresAt != nil {
		t.Fatalf("the response reports an expiry nobody asked for: %v", open.ExpiresAt)
	}
}

func TestCreateToken_RefusesAnUnusableExpiry(t *testing.T) {
	f := newControlFixture(t)
	before := f.dbDigest(t)

	for _, c := range []struct{ name, expiresAt string }{
		{"in the past", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)},
		{"not a timestamp", "next friday"},
		{"date only", "2030-01-02"},
		{"unix seconds", "1893456000"},
	} {
		w := f.as(t, http.MethodPost, "/_jay/tokens", `{"account_id":"`+f.account.AccountID+
			`","allowed_actions":["object:get"],"expires_at":"`+c.expiresAt+`"}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d: %s", c.name, w.Code, w.Body.String())
		}
		if msg := errorMessage(t, w); !strings.Contains(msg, "expires_at") {
			t.Fatalf("%s: the error does not name the field: %q", c.name, msg)
		}
	}
	f.requireUnchanged(t, before, "a create-token with an unusable expiry")
}

func TestListTokens_NeverReturnsSecrets(t *testing.T) {
	f := newControlFixture(t)
	tok := f.createToken(t, `{"account_id":"`+f.account.AccountID+`","allowed_actions":["object:get"]}`)
	stored, err := f.db.GetToken(tok.TokenID)
	if err != nil {
		t.Fatalf("get token: %v", err)
	}

	w := f.as(t, http.MethodGet, "/_jay/tokens", "")
	requireStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for what, secret := range map[string]string{
		"the new token's secret":       tok.Secret,
		"the new token's bcrypt hash":  stored.SecretHash,
		"the seeded token's secret":    ctlTokenSecret,
		"an encrypted secret envelope": "enc:v1:",
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("the token listing leaks %s: %s", what, body)
		}
	}

	var listed []meta.Token
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	ids := map[string]bool{}
	for _, l := range listed {
		ids[l.TokenID] = true
	}
	if !ids[tok.TokenID] || !ids[ctlTokenID] || len(listed) != 2 {
		t.Fatalf("listing = %v, want exactly %s and %s", ids, ctlTokenID, tok.TokenID)
	}
}

func TestListTokens_FiltersByAccount(t *testing.T) {
	f := newControlFixture(t)
	other := createAccountForTest(t, f.db, "other")
	seedCheapToken(t, f.db, other.AccountID, "other-token", "other-token-secret")

	w := f.as(t, http.MethodGet, "/_jay/tokens?account_id="+other.AccountID, "")
	requireStatus(t, w, http.StatusOK)
	var listed []meta.Token
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	if len(listed) != 1 || listed[0].TokenID != "other-token" {
		t.Fatalf("filtered listing = %+v, want only other-token", listed)
	}

	// An account with no tokens is an empty list, not null: a client ranging
	// over the answer should not need a nil check.
	w = f.as(t, http.MethodGet, "/_jay/tokens?account_id=no-such-account", "")
	requireStatus(t, w, http.StatusOK)
	if got := strings.TrimSpace(w.Body.String()); got != "[]" {
		t.Fatalf("empty listing = %s, want []", got)
	}
}

// The auth cache holds the token as valid (the fixture's S3 PUTs warmed it).
// Revocation has to take effect on the next request, not when the cache entry
// expires.
func TestRevokeToken_StopsAuthenticationImmediately(t *testing.T) {
	f := newControlFixture(t)
	if _, err := f.au.AuthenticateCredentials(ctlTokenID, ctlTokenSecret); err != nil {
		t.Fatalf("precondition: the token does not authenticate: %v", err)
	}

	requireStatus(t, f.as(t, http.MethodDelete, "/_jay/tokens/"+ctlTokenID, ""), http.StatusNoContent)

	if _, err := f.au.AuthenticateCredentials(ctlTokenID, ctlTokenSecret); !errors.Is(err, auth.ErrTokenRevoked) {
		t.Fatalf("after revocation: err = %v, want %v", err, auth.ErrTokenRevoked)
	}
	if code, body := f.s3Get(t, healthyKey); code == http.StatusOK || body == healthyBody {
		t.Fatalf("the revoked token still reads through the S3 port (%d)", code)
	}
	stored, err := f.db.GetToken(ctlTokenID)
	if err != nil || stored.Status != "revoked" {
		t.Fatalf("stored token after revocation: %+v, %v", stored, err)
	}

	// Revoking again is not an error, and does not bring the token back.
	requireStatus(t, f.as(t, http.MethodDelete, "/_jay/tokens/"+ctlTokenID, ""), http.StatusNoContent)
	if _, err := f.au.AuthenticateCredentials(ctlTokenID, ctlTokenSecret); !errors.Is(err, auth.ErrTokenRevoked) {
		t.Fatalf("after the second revocation: err = %v", err)
	}
}

// Revoking a token that does not exist is the caller's mistake, not jay
// breaking: 404 with a reason, never "internal error".
func TestRevokeToken_UnknownTokenIs404(t *testing.T) {
	f := newControlFixture(t)
	before := f.dbDigest(t)

	for _, path := range []string{"/_jay/tokens/no-such-token", "/_jay/tokens/a/b"} {
		w := f.as(t, http.MethodDelete, path, "")
		if w.Code != http.StatusNotFound {
			t.Fatalf("DELETE %s: want 404, got %d: %s", path, w.Code, w.Body.String())
		}
		if msg := errorMessage(t, w); msg != "token not found" {
			t.Fatalf("DELETE %s: error = %q", path, msg)
		}
	}
	f.requireUnchanged(t, before, "revoking an unknown token")
	if _, err := f.au.AuthenticateCredentials(ctlTokenID, ctlTokenSecret); err != nil {
		t.Fatalf("revoking an unknown token broke an existing one: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

func TestMetrics_ReportsTheLiveCounters(t *testing.T) {
	f := newControlFixture(t)
	f.metrics.ChecksumFailures.Add(3)

	w := f.as(t, http.MethodGet, "/_jay/metrics", "")
	requireStatus(t, w, http.StatusOK)
	var snap maintenance.MetricsSnapshot
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	// Two PUTs went through the S3 handler in the fixture.
	if snap.PutObjectTotal != 2 || snap.ChecksumFailures != 3 {
		t.Fatalf("snapshot = %+v, want put_object_total 2 and checksum_failures 3", snap)
	}
}

func TestMetrics_WithoutMetricsIs503(t *testing.T) {
	h := NewHandler(AdminConfig{
		AdminToken: testAdminToken,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	t.Cleanup(func() { _ = h.Close() })

	req := httptest.NewRequest(http.MethodGet, "http://jay.test/_jay/metrics", nil)
	req.Header.Set("Authorization", adminBearer)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	requireStatus(t, w, http.StatusServiceUnavailable)
	if msg := errorMessage(t, w); msg != "metrics not available" {
		t.Fatalf("error = %q", msg)
	}
}

// ---------------------------------------------------------------------------
// Presign: the validation presign_test.go does not reach
// ---------------------------------------------------------------------------

func TestPresign_RefusesIncompleteRequests(t *testing.T) {
	f := newControlFixture(t)

	for _, c := range []struct{ name, body string }{
		{"no body", ""},
		{"not JSON", `{"token_id":`},
		{"misspelt field", `{"token":"` + ctlTokenID + `","method":"GET","bucket":"` + ctlBucket + `"}`},
		{"no token_id", `{"method":"GET","bucket":"` + ctlBucket + `"}`},
		{"no method", `{"token_id":"` + ctlTokenID + `","bucket":"` + ctlBucket + `"}`},
		{"no bucket", `{"token_id":"` + ctlTokenID + `","method":"GET"}`},
	} {
		w := f.as(t, http.MethodPost, "/_jay/presign", c.body)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d: %s", c.name, w.Code, w.Body.String())
		}
		_ = errorMessage(t, w)
	}
}

func TestPresign_ExpiredTokenIsRefused(t *testing.T) {
	f := newControlFixture(t)
	past := time.Now().Add(-time.Minute)
	if err := f.db.CreateToken(&meta.Token{
		TokenID: "expired-token", AccountID: f.account.AccountID, SecretHash: cheapHash(t, "expired-secret"),
		SecretKey: "expired-secret", AllowedActions: []string{"*"}, ExpiresAt: &past,
	}); err != nil {
		t.Fatalf("create token: %v", err)
	}

	for _, style := range []string{presignStyleJay, presignStyleAWS} {
		w := f.as(t, http.MethodPost, "/_jay/presign", `{"token_id":"expired-token","method":"GET","bucket":"`+
			ctlBucket+`","key":"`+healthyKey+`","style":"`+style+`"}`)
		requireStatus(t, w, http.StatusBadRequest)
		if msg := errorMessage(t, w); msg != "token has expired" {
			t.Fatalf("%s: error = %q", style, msg)
		}
	}
}

// A token that exists but cannot be decrypted — the server was started with a
// JAY_SIGNING_SECRET other than the one it was stored under — is not "token
// not found": that answer sends the operator to check an id that is correct.
func TestPresign_UndecryptableTokenIsAServerError(t *testing.T) {
	f := newControlFixture(t)
	f.db.SetSigningSecret("a-different-signing-secret-of-32-bytes")

	for _, style := range []string{presignStyleJay, presignStyleAWS} {
		w := f.as(t, http.MethodPost, "/_jay/presign", `{"token_id":"`+ctlTokenID+`","method":"GET","bucket":"`+
			ctlBucket+`","key":"`+healthyKey+`","style":"`+style+`"}`)
		requireStatus(t, w, http.StatusInternalServerError)
		if msg := errorMessage(t, w); msg != "internal error" {
			t.Fatalf("%s: error = %q", style, msg)
		}
	}
}

func TestPresign_JayStyleWithoutASigningSecretIsRefused(t *testing.T) {
	f := newControlFixture(t)
	h := NewHandler(AdminConfig{
		DB: f.db, Store: f.st, Auth: f.au, AdminToken: testAdminToken,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), ListenAddr: "jay.test:9000",
	})
	t.Cleanup(func() { _ = h.Close() })

	req := httptest.NewRequest(http.MethodPost, "http://jay.test/_jay/presign", strings.NewReader(
		`{"token_id":"`+ctlTokenID+`","method":"GET","bucket":"`+ctlBucket+`","key":"`+healthyKey+`"}`))
	req.Header.Set("Authorization", adminBearer)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	requireStatus(t, w, http.StatusBadRequest)
	if msg := errorMessage(t, w); msg != "signing secret not configured" {
		t.Fatalf("error = %q", msg)
	}
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

func TestListQuarantined_ReportsTheQuarantinedObject(t *testing.T) {
	f := newControlFixture(t)

	w := f.as(t, http.MethodGet, "/_jay/quarantine", "")
	requireStatus(t, w, http.StatusOK)
	var listed []maintenance.QuarantinedObject
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	if len(listed) != 1 || listed[0].Key != sickKey || listed[0].BucketName != ctlBucket || listed[0].BucketID != f.bucketID {
		t.Fatalf("quarantine listing = %+v, want only %s/%s", listed, ctlBucket, sickKey)
	}
}

func TestListQuarantined_EmptyIsAnEmptyList(t *testing.T) {
	f := newControlFixture(t)
	if err := f.db.RestoreObject(f.bucketID, sickKey); err != nil {
		t.Fatalf("restore: %v", err)
	}

	w := f.as(t, http.MethodGet, "/_jay/quarantine", "")
	requireStatus(t, w, http.StatusOK)
	if got := strings.TrimSpace(w.Body.String()); got != "[]" {
		t.Fatalf("empty quarantine = %s, want []", got)
	}
}

func (f *controlFixture) quarantineBody(key string) string {
	return `{"bucket_id":"` + f.bucketID + `","key":"` + key + `"}`
}

func TestRevalidate_RestoresAnObjectThatVerifies(t *testing.T) {
	f := newControlFixture(t)
	if code, _ := f.s3Get(t, sickKey); code == http.StatusOK {
		t.Fatal("precondition: the quarantined object is readable")
	}

	w := f.as(t, http.MethodPost, "/_jay/quarantine/revalidate", f.quarantineBody(sickKey))
	requireStatus(t, w, http.StatusOK)
	if got := strings.TrimSpace(w.Body.String()); got != `{"restored":true}` {
		t.Fatalf("response = %s, want {\"restored\":true}", got)
	}
	if got := f.objectState(t, sickKey); got != "active" {
		t.Fatalf("state after revalidation = %q, want active", got)
	}
	if code, body := f.s3Get(t, sickKey); code != http.StatusOK || body != sickBody {
		t.Fatalf("the restored object is not readable: %d %q", code, body)
	}
}

// Bytes that still do not match stay in quarantine — and stay on disk.
func TestRevalidate_ACorruptObjectStaysQuarantined(t *testing.T) {
	f := newControlFixture(t)
	file := f.objectFile(t, sickKey)
	if err := os.WriteFile(file, []byte("bit rot"), 0o600); err != nil {
		t.Fatalf("corrupt the file: %v", err)
	}

	w := f.as(t, http.MethodPost, "/_jay/quarantine/revalidate", f.quarantineBody(sickKey))
	requireStatus(t, w, http.StatusOK)
	if got := strings.TrimSpace(w.Body.String()); got != `{"restored":false}` {
		t.Fatalf("response = %s, want {\"restored\":false}", got)
	}
	if got := f.objectState(t, sickKey); got != "quarantined" {
		t.Fatalf("state = %q, want quarantined", got)
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "bit rot" {
		t.Fatalf("the corrupt file was not left as evidence: %q, %v", data, err)
	}
}

// Revalidation is for quarantined objects. Every other request is refused with
// a status that says why, and changes nothing — in particular, an ACTIVE
// object is not reported as "restored".
func TestRevalidate_RefusalsChangeNothing(t *testing.T) {
	f := newControlFixture(t)
	before := f.dbDigest(t)

	for _, c := range []struct {
		name, body string
		wantStatus int
	}{
		{"no body", "", http.StatusBadRequest},
		{"not JSON", `{"bucket_id":`, http.StatusBadRequest},
		{"misspelt field", `{"bucket":"` + f.bucketID + `","key":"` + sickKey + `"}`, http.StatusBadRequest},
		{"no fields", `{}`, http.StatusBadRequest},
		{"no key", `{"bucket_id":"` + f.bucketID + `"}`, http.StatusBadRequest},
		{"no bucket_id", `{"key":"` + sickKey + `"}`, http.StatusBadRequest},
		{"unknown key", f.quarantineBody("no-such-key"), http.StatusNotFound},
		{"unknown bucket", `{"bucket_id":"no-such-bucket","key":"` + sickKey + `"}`, http.StatusNotFound},
		{"active object", f.quarantineBody(healthyKey), http.StatusConflict},
	} {
		w := f.as(t, http.MethodPost, "/_jay/quarantine/revalidate", c.body)
		if w.Code != c.wantStatus {
			t.Fatalf("%s: want %d, got %d: %s", c.name, c.wantStatus, w.Code, w.Body.String())
		}
		_ = errorMessage(t, w)
	}
	f.requireUnchanged(t, before, "a refused revalidation")
}

func TestPurge_RemovesOneQuarantinedObject(t *testing.T) {
	f := newControlFixture(t)
	file := f.objectFile(t, sickKey)

	requireStatus(t, f.as(t, http.MethodDelete, "/_jay/quarantine", f.quarantineBody(sickKey)), http.StatusNoContent)

	if got := f.objectState(t, sickKey); got != "" {
		t.Fatalf("the purged record is still there, state %q", got)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("the purged file is still on disk: %v", err)
	}
	if code, body := f.s3Get(t, healthyKey); code != http.StatusOK || body != healthyBody {
		t.Fatalf("purging one object touched another: %d %q", code, body)
	}
}

// The quarantine purge must never be a way to delete a live object. Naming an
// active key — a typo, a key copied from the wrong listing — is refused, and
// the object stays readable byte for byte.
func TestPurge_RefusesAnActiveObject(t *testing.T) {
	f := newControlFixture(t)
	file := f.objectFile(t, healthyKey)
	before := f.dbDigest(t)

	w := f.as(t, http.MethodDelete, "/_jay/quarantine", f.quarantineBody(healthyKey))
	requireStatus(t, w, http.StatusConflict)
	if msg := errorMessage(t, w); msg != "object is not quarantined" {
		t.Fatalf("error = %q", msg)
	}

	f.requireUnchanged(t, before, "a refused purge")
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("the active object's file is gone: %v", err)
	}
	if code, body := f.s3Get(t, healthyKey); code != http.StatusOK || body != healthyBody {
		t.Fatalf("the active object is no longer readable: %d %q", code, body)
	}
}

func TestPurge_RefusalsChangeNothing(t *testing.T) {
	f := newControlFixture(t)
	before := f.dbDigest(t)

	for _, c := range []struct {
		name, body string
		wantStatus int
	}{
		{"no body", "", http.StatusBadRequest},
		{"not JSON", `{"mode":`, http.StatusBadRequest},
		{"misspelt field", `{"mdoe":"all"}`, http.StatusBadRequest},
		{"no fields", `{}`, http.StatusBadRequest},
		{"unknown mode", `{"mode":"everything"}`, http.StatusBadRequest},
		{"bucket_id without key", `{"bucket_id":"` + f.bucketID + `"}`, http.StatusBadRequest},
		{"key without bucket_id", `{"key":"` + sickKey + `"}`, http.StatusBadRequest},
		// Either a single purge or all of them — a request that says both is
		// not guessed at in either direction.
		{"mode and key together", `{"mode":"all","bucket_id":"` + f.bucketID + `","key":"` + sickKey + `"}`, http.StatusBadRequest},
		{"unknown key", f.quarantineBody("no-such-key"), http.StatusNotFound},
		{"unknown bucket", `{"bucket_id":"no-such-bucket","key":"` + sickKey + `"}`, http.StatusNotFound},
	} {
		w := f.as(t, http.MethodDelete, "/_jay/quarantine", c.body)
		if w.Code != c.wantStatus {
			t.Fatalf("%s: want %d, got %d: %s", c.name, c.wantStatus, w.Code, w.Body.String())
		}
		_ = errorMessage(t, w)
	}
	f.requireUnchanged(t, before, "a refused purge")
	if _, err := os.Stat(f.objectFile(t, sickKey)); err != nil {
		t.Fatalf("a refused purge removed the quarantined file: %v", err)
	}
}

// blockRemoval replaces key's file with a non-empty directory of the same
// name, which os.Remove cannot delete — as root too, unlike a permission
// change. The returned func puts the file back.
func (f *controlFixture) blockRemoval(t *testing.T, key string) (unblock func()) {
	t.Helper()
	path := f.objectFile(t, key)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
	if err := os.MkdirAll(filepath.Join(path, "blocker"), 0o755); err != nil {
		t.Fatalf("block %s: %v", path, err)
	}
	return func() {
		if err := os.RemoveAll(path); err != nil {
			t.Fatalf("unblock %s: %v", path, err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("restore %s: %v", path, err)
		}
	}
}

// A purge whose file cannot be removed is a failure, and the record stays:
// still quarantined, still listed, and purgeable once the cause is fixed. It
// used to delete the record anyway and answer 204, leaving the bytes on disk
// behind a response that said they were gone.
func TestPurge_AFileThatCannotBeRemovedFailsAndKeepsTheRecord(t *testing.T) {
	f := newControlFixture(t)
	unblock := f.blockRemoval(t, sickKey)
	before := f.dbDigest(t)

	w := f.as(t, http.MethodDelete, "/_jay/quarantine", f.quarantineBody(sickKey))
	requireStatus(t, w, http.StatusInternalServerError)
	if msg := errorMessage(t, w); !strings.HasPrefix(msg, "purge failed: ") {
		t.Fatalf("error = %q, want the reason the purge failed", msg)
	}
	f.requireUnchanged(t, before, "a purge that could not remove the file")
	if got := f.objectState(t, sickKey); got != "quarantined" {
		t.Fatalf("state after a failed purge = %q, want quarantined", got)
	}

	unblock()
	requireStatus(t, f.as(t, http.MethodDelete, "/_jay/quarantine", f.quarantineBody(sickKey)), http.StatusNoContent)
	if got := f.objectState(t, sickKey); got != "" {
		t.Fatalf("the retried purge left the record, state %q", got)
	}
}

// A purge-all that could not remove everything says so: not a 200, and the
// body names each object that is still there and why. It used to answer 200
// with a count that silently left the failures out.
func TestPurgeAll_APartialPurgeIsReportedAsOne(t *testing.T) {
	f := newControlFixture(t)
	if err := f.db.QuarantineObject(f.bucketID, healthyKey); err != nil {
		t.Fatalf("quarantine %s: %v", healthyKey, err)
	}
	f.blockRemoval(t, sickKey)

	w := f.as(t, http.MethodDelete, "/_jay/quarantine", `{"mode":"all"}`)
	requireStatus(t, w, http.StatusInternalServerError)
	var resp purgeAllResponse
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	if resp.Error == "" || resp.Purged != 1 || len(resp.Failed) != 1 {
		t.Fatalf("response = %+v, want an error, purged 1 and one failure", resp)
	}
	if got := resp.Failed[0]; got.BucketID != f.bucketID || got.Key != sickKey || got.Error == "" {
		t.Fatalf("failure = %+v, want %s in bucket %s with a reason", got, sickKey, f.bucketID)
	}

	// And the database agrees with the answer, both ways.
	if got := f.objectState(t, healthyKey); got != "" {
		t.Fatalf("the object reported purged is still there, state %q", got)
	}
	if got := f.objectState(t, sickKey); got != "quarantined" {
		t.Fatalf("the object reported failed is no longer quarantined: %q", got)
	}
}

func TestPurgeAll_RemovesOnlyQuarantinedObjects(t *testing.T) {
	f := newControlFixture(t)
	sickFile := f.objectFile(t, sickKey)

	w := f.as(t, http.MethodDelete, "/_jay/quarantine", `{"mode":"all"}`)
	requireStatus(t, w, http.StatusOK)
	if got := strings.TrimSpace(w.Body.String()); got != `{"purged":1,"failed":[]}` {
		t.Fatalf("response = %s, want {\"purged\":1,\"failed\":[]}", got)
	}
	if got := f.objectState(t, sickKey); got != "" {
		t.Fatalf("the quarantined record survived purge-all, state %q", got)
	}
	if _, err := os.Stat(sickFile); !os.IsNotExist(err) {
		t.Fatalf("the quarantined file survived purge-all: %v", err)
	}
	if code, body := f.s3Get(t, healthyKey); code != http.StatusOK || body != healthyBody {
		t.Fatalf("purge-all touched an active object: %d %q", code, body)
	}
}

func TestPurgeAll_EmptyQuarantinePurgesNothing(t *testing.T) {
	f := newControlFixture(t)
	if err := f.db.RestoreObject(f.bucketID, sickKey); err != nil {
		t.Fatalf("restore: %v", err)
	}
	before := f.dbDigest(t)

	w := f.as(t, http.MethodDelete, "/_jay/quarantine", `{"mode":"all"}`)
	requireStatus(t, w, http.StatusOK)
	if got := strings.TrimSpace(w.Body.String()); got != `{"purged":0,"failed":[]}` {
		t.Fatalf("response = %s, want {\"purged\":0,\"failed\":[]}", got)
	}
	f.requireUnchanged(t, before, "purge-all of an empty quarantine")
	for key, want := range map[string]string{healthyKey: healthyBody, sickKey: sickBody} {
		if code, body := f.s3Get(t, key); code != http.StatusOK || body != want {
			t.Fatalf("%s after an empty purge-all: %d %q", key, code, body)
		}
	}
}
