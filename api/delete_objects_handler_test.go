package api

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ivangsm/jay/meta"
)

// ── helpers ────────────────────────────────────────────────────────────────

// objectExists asserts against the database, not against a response body: the
// point of these tests is whether the delete happened, not what the XML said.
func objectExists(t *testing.T, db *meta.DB, bucket, key string) bool {
	t.Helper()
	b, err := db.GetBucket(bucket)
	if err != nil {
		t.Fatalf("get bucket %s: %v", bucket, err)
	}
	_, err = db.GetObjectMeta(b.ID, key)
	switch {
	case err == nil:
		return true
	case errors.Is(err, meta.ErrObjectNotFound):
		return false
	default:
		t.Fatalf("get object %s/%s: %v", bucket, key, err)
		return false
	}
}

func deleteRequest(keys ...string) string {
	var sb strings.Builder
	sb.WriteString(`<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	for _, k := range keys {
		sb.WriteString("<Object><Key>" + k + "</Key></Object>")
	}
	sb.WriteString("</Delete>")
	return sb.String()
}

func decodeDeleteResult(t *testing.T, body string) DeleteResult {
	t.Helper()
	var res DeleteResult
	if err := xml.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("decode DeleteResult: %v (body: %s)", err, body)
	}
	return res
}

// ── the happy path, asserted against the database ─────────────────────────

func TestDeleteObjects_RemovesEveryRequestedKey(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")
	putObjectForTest(t, h, tok, secret, "photos", "a.jpg", "aaa")
	putObjectForTest(t, h, tok, secret, "photos", "b.jpg", "bbb")
	putObjectForTest(t, h, tok, secret, "photos", "keep.jpg", "ccc")

	w := do(t, h, authz, http.MethodPost, "/photos?delete", deleteRequest("a.jpg", "b.jpg"))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	res := decodeDeleteResult(t, w.Body.String())
	if len(res.Deleted) != 2 || len(res.Errors) != 0 {
		t.Fatalf("want 2 deleted / 0 errors, got %d/%d: %s", len(res.Deleted), len(res.Errors), w.Body.String())
	}

	if objectExists(t, db, "photos", "a.jpg") || objectExists(t, db, "photos", "b.jpg") {
		t.Fatal("DeleteObjects reported success but the objects are still in the database")
	}
	if !objectExists(t, db, "photos", "keep.jpg") {
		t.Fatal("DeleteObjects removed a key that was not in the request")
	}
}

// S3 makes DeleteObject idempotent, so a key that was never there is a success.
func TestDeleteObjects_MissingKeyIsDeleted(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")

	w := do(t, h, authz, http.MethodPost, "/photos?delete", deleteRequest("never-existed.jpg"))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	res := decodeDeleteResult(t, w.Body.String())
	if len(res.Deleted) != 1 || len(res.Errors) != 0 {
		t.Fatalf("want 1 deleted / 0 errors, got %d/%d", len(res.Deleted), len(res.Errors))
	}
}

// ── a partial delete is reported as partial ───────────────────────────────

// The failure this operation exists to avoid: `aws s3 rm --recursive` reporting
// success over objects that are still there. A key the token may not touch has
// to come back as <Error>, and the object has to still be in the database.
func TestDeleteObjects_KeyOutsidePrefixScope_IsReportedNotDeleted(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "photos")
	putObjectForTest(t, h, tok, secret, "photos", "allowed/a.jpg", "aaa")
	putObjectForTest(t, h, tok, secret, "photos", "denied/b.jpg", "bbb")

	scoped, scopedSecret := scopedToken(t, db, tok.AccountID, "prefix-scoped", meta.AllActions, nil, []string{"allowed/"})
	w := do(t, h, authHeader(scoped, scopedSecret), http.MethodPost, "/photos?delete",
		deleteRequest("allowed/a.jpg", "denied/b.jpg"))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	res := decodeDeleteResult(t, w.Body.String())
	if len(res.Deleted) != 1 || res.Deleted[0].Key != "allowed/a.jpg" {
		t.Fatalf("want allowed/a.jpg deleted, got %+v", res.Deleted)
	}
	if len(res.Errors) != 1 || res.Errors[0].Key != "denied/b.jpg" || res.Errors[0].Code != S3ErrAccessDenied {
		t.Fatalf("want AccessDenied for denied/b.jpg, got %+v", res.Errors)
	}

	if objectExists(t, db, "photos", "allowed/a.jpg") {
		t.Fatal("the in-scope key was reported deleted but is still stored")
	}
	if !objectExists(t, db, "photos", "denied/b.jpg") {
		t.Fatal("the out-of-scope key was deleted despite the token's prefix scope")
	}
}

// Quiet suppresses the successes. It must not suppress the failures — that is
// the mode where a silent drop is invisible.
func TestDeleteObjects_QuietStillReportsErrors(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "photos")
	putObjectForTest(t, h, tok, secret, "photos", "allowed/a.jpg", "aaa")
	putObjectForTest(t, h, tok, secret, "photos", "denied/b.jpg", "bbb")

	scoped, scopedSecret := scopedToken(t, db, tok.AccountID, "prefix-scoped", meta.AllActions, nil, []string{"allowed/"})
	body := `<Delete><Quiet>true</Quiet>` +
		`<Object><Key>allowed/a.jpg</Key></Object>` +
		`<Object><Key>denied/b.jpg</Key></Object></Delete>`

	w := do(t, h, authHeader(scoped, scopedSecret), http.MethodPost, "/photos?delete", body)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	res := decodeDeleteResult(t, w.Body.String())
	if len(res.Deleted) != 0 {
		t.Fatalf("quiet mode must not list successes, got %+v", res.Deleted)
	}
	if len(res.Errors) != 1 || res.Errors[0].Code != S3ErrAccessDenied {
		t.Fatalf("quiet mode dropped the failure: %+v", res.Errors)
	}
	if !objectExists(t, db, "photos", "denied/b.jpg") {
		t.Fatal("the out-of-scope key was deleted in quiet mode")
	}
}

// jay has no versioning. Deleting the live object because a version was named
// would be doing something other than what was asked.
func TestDeleteObjects_VersionedEntry_IsRefusedNotApplied(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")
	putObjectForTest(t, h, tok, secret, "photos", "a.jpg", "aaa")

	body := `<Delete><Object><Key>a.jpg</Key><VersionId>v1</VersionId></Object></Delete>`
	w := do(t, h, authz, http.MethodPost, "/photos?delete", body)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	res := decodeDeleteResult(t, w.Body.String())
	if len(res.Errors) != 1 || res.Errors[0].Code != S3ErrNotImplemented {
		t.Fatalf("want NotImplemented for the versioned entry, got %+v", res.Errors)
	}
	if !objectExists(t, db, "photos", "a.jpg") {
		t.Fatal("a versioned entry deleted the live object")
	}
}

// ── request-level refusals: nothing is applied ────────────────────────────

func TestDeleteObjects_OverKeyLimit_DeletesNothing(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")
	putObjectForTest(t, h, tok, secret, "photos", "a.jpg", "aaa")

	keys := make([]string, 0, maxDeleteKeys+1)
	keys = append(keys, "a.jpg")
	for i := range maxDeleteKeys {
		keys = append(keys, fmt.Sprintf("filler-%d.jpg", i))
	}

	w := do(t, h, authz, http.MethodPost, "/photos?delete", deleteRequest(keys...))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), s3ErrMalformedXML) {
		t.Errorf("want MalformedXML, got %s", w.Body.String())
	}
	if !objectExists(t, db, "photos", "a.jpg") {
		t.Fatal("an over-sized batch was partially applied")
	}
}

func TestDeleteObjects_MalformedOrEmptyXML_DeletesNothing(t *testing.T) {
	cases := map[string]string{
		"not xml":     "this is not xml at all",
		"unclosed":    "<Delete><Object><Key>a.jpg</Key>",
		"no objects":  "<Delete></Delete>",
		"empty body":  "",
		"wrong root":  "<NotDelete><Object><Key>a.jpg</Key></Object></NotDelete>",
		"doctype ent": `<!DOCTYPE d [<!ENTITY x "boom">]><Delete><Object><Key>&x;</Key></Object></Delete>`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			h, db, tok, secret := fullSetupTestHandler(t)
			authz := authHeader(tok, secret)
			createBucket(t, h, authz, "photos")
			putObjectForTest(t, h, tok, secret, "photos", "a.jpg", "aaa")

			w := do(t, h, authz, http.MethodPost, "/photos?delete", body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
			}
			if !objectExists(t, db, "photos", "a.jpg") {
				t.Fatal("a rejected request still deleted an object")
			}
		})
	}
}

func TestDeleteObjects_OverSizedBody_IsRefused(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")
	putObjectForTest(t, h, tok, secret, "photos", "a.jpg", "aaa")

	// One key whose name alone blows past the ceiling.
	body := deleteRequest(strings.Repeat("x", maxDeleteRequestSize+1))
	w := do(t, h, authz, http.MethodPost, "/photos?delete", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), s3ErrMaxMessageLengthExceeded) {
		t.Errorf("want MaxMessageLengthExceeded, got %s", w.Body.String())
	}
	if !objectExists(t, db, "photos", "a.jpg") {
		t.Fatal("an over-sized body still deleted an object")
	}
}

// A body that does not match the digest the client computed is not the body the
// client meant to send, so it must not be acted on.
func TestDeleteObjects_ContentMD5(t *testing.T) {
	body := deleteRequest("a.jpg")
	sum := md5.Sum([]byte(body))
	valid := base64.StdEncoding.EncodeToString(sum[:])

	t.Run("matching digest is accepted", func(t *testing.T) {
		h, db, tok, secret := fullSetupTestHandler(t)
		authz := authHeader(tok, secret)
		createBucket(t, h, authz, "photos")
		putObjectForTest(t, h, tok, secret, "photos", "a.jpg", "aaa")

		req := httptest.NewRequest(http.MethodPost, "/photos?delete", strings.NewReader(body))
		req.Header.Set("Authorization", authz)
		req.Header.Set("Content-MD5", valid)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
		}
		if objectExists(t, db, "photos", "a.jpg") {
			t.Fatal("the object survived a delete that reported success")
		}
	})

	t.Run("mismatched digest is refused", func(t *testing.T) {
		h, db, tok, secret := fullSetupTestHandler(t)
		authz := authHeader(tok, secret)
		createBucket(t, h, authz, "photos")
		putObjectForTest(t, h, tok, secret, "photos", "a.jpg", "aaa")

		req := httptest.NewRequest(http.MethodPost, "/photos?delete", strings.NewReader(body))
		req.Header.Set("Authorization", authz)
		req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(make([]byte, 16)))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), s3ErrBadDigest) {
			t.Errorf("want BadDigest, got %s", w.Body.String())
		}
		if !objectExists(t, db, "photos", "a.jpg") {
			t.Fatal("a body with a bad digest was acted on")
		}
	})
}

func TestDeleteObjects_UnknownBucket_Returns404(t *testing.T) {
	h, _, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)

	w := do(t, h, authz, http.MethodPost, "/no-such-bucket?delete", deleteRequest("a.jpg"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), S3ErrNoSuchBucket) {
		t.Errorf("want NoSuchBucket, got %s", w.Body.String())
	}
}

// A token without object:delete fails the whole batch, before any key is
// touched — the bucket-level half of the authorization.
func TestDeleteObjects_TokenWithoutDeleteAction_DeletesNothing(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "photos")
	putObjectForTest(t, h, tok, secret, "photos", "a.jpg", "aaa")

	reader, readerSecret := scopedToken(t, db, tok.AccountID, "reader-token",
		[]string{meta.ActionObjectGet, meta.ActionObjectList}, nil, nil)

	w := do(t, h, authHeader(reader, readerSecret), http.MethodPost, "/photos?delete", deleteRequest("a.jpg"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
	if !objectExists(t, db, "photos", "a.jpg") {
		t.Fatal("a token without object:delete deleted an object")
	}
}

// A bucket policy that denies object:delete must apply per key, exactly as it
// does to a single-object DELETE.
func TestDeleteObjects_BucketPolicyDeny_IsReportedNotDeleted(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")
	putObjectForTest(t, h, tok, secret, "photos", "a.jpg", "aaa")

	policy := `{"statements":[{"effect":"deny","actions":["object:delete"],"subjects":["*"]}]}`
	if err := db.UpdateBucketPolicy("photos", []byte(policy)); err != nil {
		t.Fatalf("update bucket policy: %v", err)
	}

	w := do(t, h, authz, http.MethodPost, "/photos?delete", deleteRequest("a.jpg"))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	res := decodeDeleteResult(t, w.Body.String())
	if len(res.Errors) != 1 || res.Errors[0].Code != S3ErrAccessDenied {
		t.Fatalf("want AccessDenied from the bucket policy, got %+v (deleted %+v)", res.Errors, res.Deleted)
	}
	if !objectExists(t, db, "photos", "a.jpg") {
		t.Fatal("a bucket policy deny did not stop the batch delete")
	}
}

// The response has to carry the elements a real S3 client parses.
func TestDeleteObjects_ResponseShape(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")
	putObjectForTest(t, h, tok, secret, "photos", "a.jpg", "aaa")

	w := do(t, h, authz, http.MethodPost, "/photos?delete", deleteRequest("a.jpg"))
	body := w.Body.String()
	for _, want := range []string{
		`<DeleteResult xmlns="` + s3Namespace + `">`,
		"<Deleted><Key>a.jpg</Key></Deleted>",
		"</DeleteResult>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %q: %s", want, body)
		}
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/xml" {
		t.Errorf("Content-Type = %q, want application/xml", ct)
	}
}
