package api

import (
	"encoding/xml"
	"net/http"
	"strings"
	"testing"
	"uuid"

	"github.com/ivangsm/jay/meta"
)

// Cross-account isolation (PND-0185).
//
// Every assertion here reads the DATABASE after the attempt, not the status
// code. A handler that answers 403 and writes the object anyway would pass a
// status-code test; the only thing that proves an object was not touched is
// looking at the object.

// crossAccountEnv is one bucket owned by account A holding one object, plus a
// token of account B with wildcard actions and no scopes at all — the widest
// credential another tenant can hold.
type crossAccountEnv struct {
	h         *Handler
	db        *meta.DB
	bucket    *meta.Bucket
	ownerAuth string
	otherAuth string
}

const (
	crossAccountBucket  = "owned"
	crossAccountKey     = "private/report.txt"
	crossAccountContent = "the owner's bytes"
)

func setupCrossAccount(t *testing.T) *crossAccountEnv {
	t.Helper()
	h, db, ownerTok, ownerSecret := fullSetupTestHandler(t)
	bucket := createBucketForTest(t, db, ownerTok.AccountID, crossAccountBucket)

	ownerAuth := authHeader(ownerTok, ownerSecret)
	w := do(t, h, ownerAuth, http.MethodPut, "/"+crossAccountBucket+"/"+crossAccountKey, crossAccountContent)
	if w.Code != http.StatusOK {
		t.Fatalf("owner put: want 200, got %d: %s", w.Code, w.Body.String())
	}

	intruder := &meta.Account{AccountID: uuid.New().String(), Name: "intruder", Status: "active"}
	if err := db.CreateAccount(intruder); err != nil {
		t.Fatalf("create intruder account: %v", err)
	}
	otherTok, otherSecret := scopedToken(t, db, intruder.AccountID, "intruder-token", []string{"*"}, nil, nil)

	return &crossAccountEnv{
		h:         h,
		db:        db,
		bucket:    bucket,
		ownerAuth: ownerAuth,
		otherAuth: authHeader(otherTok, otherSecret),
	}
}

// assertObjectIntact reads the stored record and fails if the object is gone or
// its bytes changed. This is the assertion that matters — not the status code
// the intruder saw.
func (e *crossAccountEnv) assertObjectIntact(t *testing.T, what string) {
	t.Helper()
	obj, err := e.db.GetObjectMeta(e.bucket.ID, crossAccountKey)
	if err != nil {
		t.Fatalf("%s: the owner's object is gone from the database: %v", what, err)
	}
	if obj.SizeBytes != int64(len(crossAccountContent)) {
		t.Fatalf("%s: object size = %d, want %d — the bytes were replaced",
			what, obj.SizeBytes, len(crossAccountContent))
	}
	code, body := getObjectBody(t, e.h, e.ownerAuth, crossAccountBucket, crossAccountKey)
	if code != http.StatusOK || body != crossAccountContent {
		t.Fatalf("%s: owner reads %q (status %d), want %q", what, body, code, crossAccountContent)
	}
}

// assertKeyAbsent fails if the key exists in the bucket at all.
func (e *crossAccountEnv) assertKeyAbsent(t *testing.T, key, what string) {
	t.Helper()
	if _, err := e.db.GetObjectMeta(e.bucket.ID, key); err == nil {
		t.Fatalf("%s: %q was written into another account's bucket", what, key)
	}
}

func TestCrossAccount_GetObjectDeniedAndObjectUntouched(t *testing.T) {
	e := setupCrossAccount(t)

	code, body := getObjectBody(t, e.h, e.otherAuth, crossAccountBucket, crossAccountKey)
	if body == crossAccountContent {
		t.Fatalf("GET handed another account's bytes to the intruder (status %d)", code)
	}
	e.assertObjectIntact(t, "GetObject")
}

func TestCrossAccount_PutObjectDeniedAndNothingWritten(t *testing.T) {
	e := setupCrossAccount(t)

	do(t, e.h, e.otherAuth, http.MethodPut, "/"+crossAccountBucket+"/injected.txt", "not mine")
	e.assertKeyAbsent(t, "injected.txt", "PutObject")

	// Overwriting an existing key is the same attack with worse consequences.
	do(t, e.h, e.otherAuth, http.MethodPut, "/"+crossAccountBucket+"/"+crossAccountKey, "overwritten")
	e.assertObjectIntact(t, "PutObject overwrite")
}

func TestCrossAccount_DeleteObjectDeniedAndObjectSurvives(t *testing.T) {
	e := setupCrossAccount(t)

	do(t, e.h, e.otherAuth, http.MethodDelete, "/"+crossAccountBucket+"/"+crossAccountKey, "")
	e.assertObjectIntact(t, "DeleteObject")
}

func TestCrossAccount_DeleteObjectsBatchDeniedAndObjectSurvives(t *testing.T) {
	e := setupCrossAccount(t)

	body := "<Delete><Object><Key>" + crossAccountKey + "</Key></Object></Delete>"
	do(t, e.h, e.otherAuth, http.MethodPost, "/"+crossAccountBucket+"?delete", body)
	e.assertObjectIntact(t, "DeleteObjects")
}

func TestCrossAccount_ListObjectsDoesNotDiscloseKeys(t *testing.T) {
	e := setupCrossAccount(t)

	w := do(t, e.h, e.otherAuth, http.MethodGet, "/"+crossAccountBucket+"?list-type=2", "")
	if strings.Contains(w.Body.String(), crossAccountKey) {
		t.Fatalf("ListObjectsV2 disclosed another account's keys: %s", w.Body.String())
	}
}

func TestCrossAccount_MultipartCannotStartInAForeignBucket(t *testing.T) {
	e := setupCrossAccount(t)

	w := do(t, e.h, e.otherAuth, http.MethodPost, "/"+crossAccountBucket+"/sneak.bin?uploads", "")
	if w.Code == http.StatusOK {
		uploadID := extractTag(t, w.Body.String(), "UploadId")
		t.Fatalf("multipart upload %q started in another account's bucket", uploadID)
	}
}

func TestCrossAccount_StatsDoNotLeak(t *testing.T) {
	e := setupCrossAccount(t)

	w := do(t, e.h, e.otherAuth, http.MethodGet, "/_stats/"+crossAccountBucket, "")
	if w.Code == http.StatusOK {
		t.Fatalf("bucket stats disclosed to another account: %s", w.Body.String())
	}
}

// ── The other direction: an explicit policy allow opens the bucket ────────
//
// The account check runs BEFORE the bucket policy is consulted for a grant, so
// a bucket with no policy denies a stranger. A policy that names the action and
// the subject is the one thing that opens the door — that is what makes sharing
// a deliberate act instead of the default.

// setPolicy attaches a policy document to the shared bucket.
func (e *crossAccountEnv) setPolicy(t *testing.T, policyJSON string) {
	t.Helper()
	if err := e.db.UpdateBucketPolicy(crossAccountBucket, []byte(policyJSON)); err != nil {
		t.Fatalf("update bucket policy: %v", err)
	}
}

const allowReadPolicy = `{
  "version": "2024-01-01",
  "statements": [
    {"effect": "allow", "actions": ["object:get", "object:list"], "subjects": ["*"]}
  ]
}`

func TestCrossAccount_PolicyAllowGrantsRead(t *testing.T) {
	e := setupCrossAccount(t)
	e.setPolicy(t, allowReadPolicy)

	code, body := getObjectBody(t, e.h, e.otherAuth, crossAccountBucket, crossAccountKey)
	if code != http.StatusOK || body != crossAccountContent {
		t.Fatalf("an explicit allow did not grant the read: status %d body %q", code, body)
	}

	w := do(t, e.h, e.otherAuth, http.MethodGet, "/"+crossAccountBucket+"?list-type=2", "")
	if !strings.Contains(w.Body.String(), crossAccountKey) {
		t.Fatalf("an explicit allow did not grant the listing: %s", w.Body.String())
	}
}

// A read grant is not a write grant: the actions of the statement are the
// actions that are opened, and nothing else.
func TestCrossAccount_PolicyAllowReadStillRefusesWrites(t *testing.T) {
	e := setupCrossAccount(t)
	e.setPolicy(t, allowReadPolicy)

	do(t, e.h, e.otherAuth, http.MethodDelete, "/"+crossAccountBucket+"/"+crossAccountKey, "")
	e.assertObjectIntact(t, "DeleteObject under a read-only allow")

	do(t, e.h, e.otherAuth, http.MethodPut, "/"+crossAccountBucket+"/injected.txt", "not mine")
	e.assertKeyAbsent(t, "injected.txt", "PutObject under a read-only allow")
}

// A prefix on the allow statement is honoured: the grant reaches the keys it
// names and stops there.
func TestCrossAccount_PolicyAllowIsScopedByPrefix(t *testing.T) {
	e := setupCrossAccount(t)
	w := do(t, e.h, e.ownerAuth, http.MethodPut, "/"+crossAccountBucket+"/public/open.txt", "shared")
	if w.Code != http.StatusOK {
		t.Fatalf("owner put: want 200, got %d", w.Code)
	}
	e.setPolicy(t, `{"statements":[{"effect":"allow","actions":["object:get"],"prefixes":["public/"],"subjects":["*"]}]}`)

	if code, body := getObjectBody(t, e.h, e.otherAuth, crossAccountBucket, "public/open.txt"); code != http.StatusOK || body != "shared" {
		t.Fatalf("allow on public/ did not grant public/open.txt: status %d body %q", code, body)
	}
	if code, body := getObjectBody(t, e.h, e.otherAuth, crossAccountBucket, crossAccountKey); body == crossAccountContent {
		t.Fatalf("allow on public/ leaked %s (status %d)", crossAccountKey, code)
	}
}

// Deny is evaluated after the grant and outranks it.
func TestCrossAccount_PolicyDenyBeatsAllow(t *testing.T) {
	e := setupCrossAccount(t)
	e.setPolicy(t, `{"statements":[
	  {"effect":"allow","actions":["*"],"subjects":["*"]},
	  {"effect":"deny","actions":["object:delete"],"subjects":["*"]}
	]}`)

	do(t, e.h, e.otherAuth, http.MethodDelete, "/"+crossAccountBucket+"/"+crossAccountKey, "")
	e.assertObjectIntact(t, "DeleteObject against an allow-all with a delete deny")
}

// public-read is the other documented door and it must keep working: a bucket
// that answers a stranger with no credentials at all cannot refuse the same
// read to an authenticated token of another account.
func TestCrossAccount_PublicReadBucketStaysReadable(t *testing.T) {
	h, db, ownerTok, ownerSecret := fullSetupTestHandler(t)
	public := &meta.Bucket{
		ID:             uuid.New().String(),
		Name:           "shared",
		OwnerAccountID: ownerTok.AccountID,
		Visibility:     "public-read",
		Status:         "active",
	}
	if err := db.CreateBucket(public); err != nil {
		t.Fatalf("create public bucket: %v", err)
	}
	if w := do(t, h, authHeader(ownerTok, ownerSecret), http.MethodPut, "/shared/open.txt", "published"); w.Code != http.StatusOK {
		t.Fatalf("owner put: want 200, got %d: %s", w.Code, w.Body.String())
	}

	intruder := &meta.Account{AccountID: uuid.New().String(), Name: "intruder", Status: "active"}
	if err := db.CreateAccount(intruder); err != nil {
		t.Fatalf("create intruder account: %v", err)
	}
	otherTok, otherSecret := scopedToken(t, db, intruder.AccountID, "intruder-token", []string{"*"}, nil, nil)
	otherAuth := authHeader(otherTok, otherSecret)

	if code, body := getObjectBody(t, h, otherAuth, "shared", "open.txt"); code != http.StatusOK || body != "published" {
		t.Fatalf("public-read refused an authenticated cross-account read: status %d body %q", code, body)
	}
	if code, body := getObjectBody(t, h, "", "shared", "open.txt"); code != http.StatusOK || body != "published" {
		t.Fatalf("public-read refused the anonymous read: status %d body %q", code, body)
	}
	// Readable does not mean writable.
	do(t, h, otherAuth, http.MethodPut, "/shared/injected.txt", "not mine")
	if _, err := db.GetObjectMeta(public.ID, "injected.txt"); err == nil {
		t.Fatal("a public-read bucket accepted a write from another account")
	}
}

// An operator can still delegate a single bucket to a foreign token through the
// admin API, by naming it in the token's BucketScope.
func TestCrossAccount_BucketScopeDelegationStillWorks(t *testing.T) {
	h, db, ownerTok, ownerSecret := fullSetupTestHandler(t)
	bucket := createBucketForTest(t, db, ownerTok.AccountID, crossAccountBucket)
	if w := do(t, h, authHeader(ownerTok, ownerSecret), http.MethodPut,
		"/"+crossAccountBucket+"/"+crossAccountKey, crossAccountContent); w.Code != http.StatusOK {
		t.Fatalf("owner put: want 200, got %d", w.Code)
	}

	guest := &meta.Account{AccountID: uuid.New().String(), Name: "guest", Status: "active"}
	if err := db.CreateAccount(guest); err != nil {
		t.Fatalf("create guest account: %v", err)
	}
	guestTok, guestSecret := scopedToken(t, db, guest.AccountID, "guest-token",
		[]string{"*"}, []string{crossAccountBucket}, nil)

	code, body := getObjectBody(t, h, authHeader(guestTok, guestSecret), crossAccountBucket, crossAccountKey)
	if code != http.StatusOK || body != crossAccountContent {
		t.Fatalf("delegated BucketScope was refused: status %d body %q", code, body)
	}
	if _, err := db.GetObjectMeta(bucket.ID, crossAccountKey); err != nil {
		t.Fatalf("object vanished: %v", err)
	}
}

// A bucket with no recorded owner predates ownership tracking. Refusing those
// would lock existing deployments out of their own data.
func TestCrossAccount_LegacyUnownedBucketStaysReachable(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	legacy := &meta.Bucket{ID: uuid.New().String(), Name: "legacy", Status: "active", Visibility: "private"}
	if err := db.CreateBucket(legacy); err != nil {
		t.Fatalf("create legacy bucket: %v", err)
	}

	if w := do(t, h, authHeader(tok, secret), http.MethodPut, "/legacy/k.txt", "data"); w.Code != http.StatusOK {
		t.Fatalf("write to an unowned bucket: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := db.GetObjectMeta(legacy.ID, "k.txt"); err != nil {
		t.Fatalf("object not stored in the legacy bucket: %v", err)
	}
}

// The seeded token falco uses is wildcard and owns its buckets — the path that
// must not move.
func TestCrossAccount_OwnerIsUnaffected(t *testing.T) {
	e := setupCrossAccount(t)

	if w := do(t, e.h, e.ownerAuth, http.MethodPut, "/"+crossAccountBucket+"/second.txt", "more"); w.Code != http.StatusOK {
		t.Fatalf("owner put: want 200, got %d: %s", w.Code, w.Body.String())
	}
	w := do(t, e.h, e.ownerAuth, http.MethodGet, "/"+crossAccountBucket+"?list-type=2", "")
	var res ListBucketResult
	if err := xml.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode listing: %v (%s)", err, w.Body.String())
	}
	if len(res.Contents) != 2 {
		t.Fatalf("owner listing = %d keys, want 2", len(res.Contents))
	}
	if w := do(t, e.h, e.ownerAuth, http.MethodDelete, "/"+crossAccountBucket+"/second.txt", ""); w.Code != http.StatusNoContent {
		t.Fatalf("owner delete: want 204, got %d", w.Code)
	}
	if _, err := e.db.GetObjectMeta(e.bucket.ID, "second.txt"); err == nil {
		t.Fatal("owner delete did not remove the object")
	}
}
