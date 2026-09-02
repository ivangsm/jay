package api

import (
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/ivangsm/jay/meta"
)

// ── helpers ────────────────────────────────────────────────────────────────

// startUpload creates a multipart upload and returns its id.
func startUpload(t *testing.T, h *Handler, authz, bucket, key string) string {
	t.Helper()
	w := do(t, h, authz, http.MethodPost, "/"+bucket+"/"+key+"?uploads", "")
	if w.Code != http.StatusOK {
		t.Fatalf("create upload %s/%s: want 200, got %d: %s", bucket, key, w.Code, w.Body.String())
	}
	return extractTag(t, w.Body.String(), "UploadId")
}

func listUploads(t *testing.T, h *Handler, authz, bucket, query string) ListMultipartUploadsResult {
	t.Helper()
	target := "/" + bucket + "?uploads"
	if query != "" {
		target += "&" + query
	}
	w := do(t, h, authz, http.MethodGet, target, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list uploads %s: want 200, got %d: %s", target, w.Code, w.Body.String())
	}
	var res ListMultipartUploadsResult
	if err := xml.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode ListMultipartUploadsResult: %v (body: %s)", err, w.Body.String())
	}
	return res
}

func uploadKeys(res ListMultipartUploadsResult) []string {
	keys := make([]string, 0, len(res.Uploads))
	for _, u := range res.Uploads {
		keys = append(keys, u.Key)
	}
	return keys
}

// ── ListMultipartUploads ──────────────────────────────────────────────────

func TestListMultipartUploads_ListsActiveUploads(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")

	idA := startUpload(t, h, authz, "photos", "a.bin")
	idB := startUpload(t, h, authz, "photos", "b.bin")

	res := listUploads(t, h, authz, "photos", "")
	if res.Bucket != "photos" || res.MaxUploads != defaultMaxUploads || res.IsTruncated {
		t.Fatalf("unexpected page header: %+v", res)
	}
	if got := uploadKeys(res); len(got) != 2 || got[0] != "a.bin" || got[1] != "b.bin" {
		t.Fatalf("want [a.bin b.bin] in order, got %v", got)
	}
	ids := map[string]bool{res.Uploads[0].UploadID: true, res.Uploads[1].UploadID: true}
	if !ids[idA] || !ids[idB] {
		t.Fatalf("listing does not carry the upload ids that were handed out: %+v", res.Uploads)
	}
	for _, u := range res.Uploads {
		if u.StorageClass != "STANDARD" || u.Initiated == "" {
			t.Errorf("upload missing StorageClass/Initiated: %+v", u)
		}
		if u.Initiator.ID != tok.AccountID || u.Owner.ID != tok.AccountID {
			t.Errorf("upload initiator/owner = %q/%q, want %q", u.Initiator.ID, u.Owner.ID, tok.AccountID)
		}
	}
}

// The point of the operation: an upload that is aborted stops being listed, so
// a client can actually verify that it cleaned up.
func TestListMultipartUploads_AbortedUploadDisappears(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")

	id := startUpload(t, h, authz, "photos", "a.bin")
	startUpload(t, h, authz, "photos", "b.bin")

	if w := do(t, h, authz, http.MethodDelete, "/photos/a.bin?uploadId="+id, ""); w.Code != http.StatusNoContent {
		t.Fatalf("abort: want 204, got %d: %s", w.Code, w.Body.String())
	}

	if got := uploadKeys(listUploads(t, h, authz, "photos", "")); len(got) != 1 || got[0] != "b.bin" {
		t.Fatalf("aborted upload still listed: %v", got)
	}
}

func TestListMultipartUploads_CompletedUploadDisappears(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")

	id := startUpload(t, h, authz, "photos", "a.bin")
	part := do(t, h, authz, http.MethodPut, "/photos/a.bin?uploadId="+id+"&partNumber=1", "payload")
	if part.Code != http.StatusOK {
		t.Fatalf("upload part: want 200, got %d: %s", part.Code, part.Body.String())
	}
	body := "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>" +
		part.Header().Get("ETag") + "</ETag></Part></CompleteMultipartUpload>"
	if w := do(t, h, authz, http.MethodPost, "/photos/a.bin?uploadId="+id, body); w.Code != http.StatusOK {
		t.Fatalf("complete: want 200, got %d: %s", w.Code, w.Body.String())
	}

	if got := uploadKeys(listUploads(t, h, authz, "photos", "")); len(got) != 0 {
		t.Fatalf("completed upload still listed: %v", got)
	}
}

func TestListMultipartUploads_PrefixAndDelimiter(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")

	startUpload(t, h, authz, "photos", "raw/2026/a.bin")
	startUpload(t, h, authz, "photos", "raw/2026/b.bin")
	startUpload(t, h, authz, "photos", "raw/top.bin")
	startUpload(t, h, authz, "photos", "other/c.bin")

	res := listUploads(t, h, authz, "photos", "prefix=raw%2F&delimiter=%2F")
	if got := uploadKeys(res); len(got) != 1 || got[0] != "raw/top.bin" {
		t.Fatalf("want only raw/top.bin listed directly, got %v", got)
	}
	if len(res.CommonPrefixes) != 1 || res.CommonPrefixes[0].Prefix != "raw/2026/" {
		t.Fatalf("want CommonPrefixes [raw/2026/], got %+v", res.CommonPrefixes)
	}
	if res.Prefix != "raw/" || res.Delimiter != "/" {
		t.Fatalf("page must echo prefix and delimiter, got %+v", res)
	}
}

// Pagination has to hand back a marker that actually resumes, and the two pages
// together have to be the whole set with nothing repeated and nothing lost.
func TestListMultipartUploads_PaginationResumes(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")

	for _, k := range []string{"a.bin", "b.bin", "c.bin"} {
		startUpload(t, h, authz, "photos", k)
	}

	first := listUploads(t, h, authz, "photos", "max-uploads=2")
	if !first.IsTruncated || len(first.Uploads) != 2 {
		t.Fatalf("want a truncated page of 2, got truncated=%v keys=%v", first.IsTruncated, uploadKeys(first))
	}
	if first.NextKeyMarker == "" {
		t.Fatal("a truncated page without NextKeyMarker cannot be resumed")
	}

	q := url.Values{}
	q.Set("key-marker", first.NextKeyMarker)
	q.Set("upload-id-marker", first.NextUploadIDMarker)
	second := listUploads(t, h, authz, "photos", q.Encode())
	if second.IsTruncated {
		t.Fatalf("second page should be the last, got truncated: %v", uploadKeys(second))
	}

	all := append(uploadKeys(first), uploadKeys(second)...)
	if len(all) != 3 || all[0] != "a.bin" || all[1] != "b.bin" || all[2] != "c.bin" {
		t.Fatalf("pages do not reconstruct the set exactly once: %v", all)
	}
}

// Another account's upload must not appear: its id is useless to this token
// (every part/complete/abort checks InitiatedBy), so listing it would only leak
// the object key.
func TestListMultipartUploads_OtherAccountUploadNotListed(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")
	startUpload(t, h, authz, "photos", "mine.bin")

	other := &meta.Account{AccountID: uuid.New().String(), Name: "other", Status: "active"}
	if err := db.CreateAccount(other); err != nil {
		t.Fatalf("create account: %v", err)
	}
	// Seeded straight into bbolt, not through the API: a token of another
	// account can no longer start an upload in this bucket at all (PND-0185).
	// The row is planted anyway so the listing is asked the question it is
	// here to answer — does it show an upload that is not this account's?
	bucket, err := db.GetBucket("photos")
	if err != nil {
		t.Fatalf("get bucket: %v", err)
	}
	if err := db.CreateMultipartUpload(&meta.MultipartUpload{
		UploadID:    uuid.New().String(),
		BucketID:    bucket.ID,
		ObjectKey:   "theirs.bin",
		InitiatedBy: other.AccountID,
		CreatedAt:   time.Now().UTC(),
		State:       "initiated",
	}); err != nil {
		t.Fatalf("seed foreign upload: %v", err)
	}

	if got := uploadKeys(listUploads(t, h, authz, "photos", "")); len(got) != 1 || got[0] != "mine.bin" {
		t.Fatalf("listing leaked another account's upload: %v", got)
	}
}

// A public-read bucket publishes its objects, not the uploads still in flight.
func TestListMultipartUploads_AnonymousIsRefused(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	public := &meta.Bucket{
		ID:             uuid.New().String(),
		Name:           "photos",
		OwnerAccountID: tok.AccountID,
		Visibility:     "public-read",
		Status:         "active",
	}
	if err := db.CreateBucket(public); err != nil {
		t.Fatalf("create public bucket: %v", err)
	}
	startUpload(t, h, authz, "photos", "a.bin")

	w := do(t, h, "", http.MethodGet, "/photos?uploads", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 for an anonymous upload listing, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListMultipartUploads_UnknownBucket_Returns404(t *testing.T) {
	h, _, tok, secret := fullSetupTestHandler(t)

	w := do(t, h, authHeader(tok, secret), http.MethodGet, "/no-such-bucket?uploads", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), S3ErrNoSuchBucket) {
		t.Errorf("want NoSuchBucket, got %s", w.Body.String())
	}
}

func TestListMultipartUploads_ResponseShape(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")
	startUpload(t, h, authz, "photos", "a.bin")

	w := do(t, h, authz, http.MethodGet, "/photos?uploads", "")
	body := w.Body.String()
	for _, want := range []string{
		`<ListMultipartUploadsResult xmlns="` + s3Namespace + `">`,
		"<Bucket>photos</Bucket>",
		"<Key>a.bin</Key>",
		"<UploadId>",
		"<IsTruncated>false</IsTruncated>",
		"<MaxUploads>1000</MaxUploads>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("response missing %q: %s", want, body)
		}
	}
}

// ── GetBucketLocation ─────────────────────────────────────────────────────

func TestGetBucketLocation_ReturnsEmptyConstraint(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "photos")

	w := do(t, h, authHeader(tok, secret), http.MethodGet, "/photos?location", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	var loc LocationConstraint
	if err := xml.Unmarshal(w.Body.Bytes(), &loc); err != nil {
		t.Fatalf("decode LocationConstraint: %v (body: %s)", err, w.Body.String())
	}
	if loc.Value != "" {
		t.Fatalf("LocationConstraint should be empty (us-east-1), got %q", loc.Value)
	}
	if !strings.Contains(w.Body.String(), `<LocationConstraint xmlns="`+s3Namespace+`">`) {
		t.Errorf("response missing the namespaced root element: %s", w.Body.String())
	}
}

func TestGetBucketLocation_UnknownBucket_Returns404(t *testing.T) {
	h, _, tok, secret := fullSetupTestHandler(t)

	w := do(t, h, authHeader(tok, secret), http.MethodGet, "/no-such-bucket?location", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body.String())
	}
}

// The location of a bucket is bucket metadata: another account's token must not
// be able to confirm it exists, exactly as with HeadBucket.
func TestGetBucketLocation_OtherAccount_Returns403(t *testing.T) {
	h, db, tok, _ := fullSetupTestHandler(t)
	createBucketForTest(t, db, tok.AccountID, "photos")

	other := &meta.Account{AccountID: uuid.New().String(), Name: "other", Status: "active"}
	if err := db.CreateAccount(other); err != nil {
		t.Fatalf("create account: %v", err)
	}
	otherTok, otherSecret := scopedToken(t, db, other.AccountID, "outsider", meta.AllActions, nil, nil)

	w := do(t, h, authHeader(otherTok, otherSecret), http.MethodGet, "/photos?location", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
}

// A prefix-scoped token must not learn that an upload exists for a key it
// cannot touch.
func TestListMultipartUploads_PrefixScopedTokenSeesOnlyItsOwnPrefix(t *testing.T) {
	h, db, tok, secret := fullSetupTestHandler(t)
	authz := authHeader(tok, secret)
	createBucketForTest(t, db, tok.AccountID, "photos")
	startUpload(t, h, authz, "photos", "allowed/a.bin")
	startUpload(t, h, authz, "photos", "denied/b.bin")

	scoped, scopedSecret := scopedToken(t, db, tok.AccountID, "uploads-scoped",
		meta.AllActions, nil, []string{"allowed/"})

	got := uploadKeys(listUploads(t, h, authHeader(scoped, scopedSecret), "photos", ""))
	if len(got) != 1 || got[0] != "allowed/a.bin" {
		t.Fatalf("listing leaked a key outside the token's prefix scope: %v", got)
	}
}
