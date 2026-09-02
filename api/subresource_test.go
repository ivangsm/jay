package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── helpers ────────────────────────────────────────────────────────────────

func createBucket(t *testing.T, h *Handler, auth, bucket string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/"+bucket, nil)
	req.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("create bucket: want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// putObject uploads an object so later assertions can prove it is still intact.
func putObject(t *testing.T, h *Handler, auth, bucket, key, body string) {
	t.Helper()
	createBucket(t, h, auth, bucket)

	req := httptest.NewRequest(http.MethodPut, "/"+bucket+"/"+key, strings.NewReader(body))
	req.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("put object: want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func getObjectBody(t *testing.T, h *Handler, auth, bucket, key string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
	req.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func do(t *testing.T, h *Handler, auth, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func assertIntact(t *testing.T, h *Handler, auth, original, what string) {
	t.Helper()
	code, body := getObjectBody(t, h, auth, "photos", "profile.jpg")
	if code != http.StatusOK {
		t.Fatalf("%s destroyed the object: GET returned %d", what, code)
	}
	if body != original {
		t.Fatalf("%s overwrote the object: %q", what, body)
	}
}

// ── writes: nothing unrecognised may reach a destructive handler ───────────

// A write carrying a sub-resource jay does not implement must not reach the
// object's PUT or DELETE handler.
//
// It used to: `PUT /bucket/key?tagging` reached handlePutObject and overwrote
// the photo with the `<Tagging>` XML; `DELETE /bucket/key?tagging` deleted it
// outright. Both answered success. The bbolt backup only holds metadata, so the
// bytes did not come back.
func TestWrite_UnimplementedSubresource_DoesNotDestroyObject(t *testing.T) {
	const original = "the-original-photo-bytes"

	subresources := []string{
		"tagging", "acl", "retention", "legal-hold", "torrent",
		"restore", "select", "attributes", "versionId=v1",
	}

	for _, sub := range subresources {
		for _, method := range []string{http.MethodPut, http.MethodPost, http.MethodDelete} {
			t.Run(method+"_"+sub, func(t *testing.T) {
				h, _, tok, secret := fullSetupTestHandler(t)
				auth := authHeader(tok, secret)
				putObject(t, h, auth, "photos", "profile.jpg", original)

				w := do(t, h, auth, method, "/photos/profile.jpg?"+sub, "<Tagging/>")
				if w.Code != http.StatusNotImplemented {
					t.Errorf("%s ?%s: want 501, got %d: %s", method, sub, w.Code, w.Body.String())
				}

				assertIntact(t, h, auth, original, method+" ?"+sub)
			})
		}
	}
}

// A multipart param on the wrong method is the same failure mode, just spelled
// with a name jay does recognise. `PUT /bucket/key?uploads` is not
// CreateMultipartUpload (that is a POST) — it is a PUT that overwrites the
// object. `DELETE /bucket/key?uploadId=` carries an empty value, so the
// multipart branch declines it and the plain DELETE handler wiped the object.
func TestWrite_MultipartParamOnWrongMethod_DoesNotDestroyObject(t *testing.T) {
	const original = "the-original-photo-bytes"

	cases := []struct{ method, query string }{
		{http.MethodPut, "uploads"},
		{http.MethodDelete, "uploads"},
		{http.MethodPut, "partNumber=1"}, // UploadPart without its uploadId
		{http.MethodDelete, "partNumber=1"},
		{http.MethodDelete, "uploadId="}, // empty value: not a valid abort
		{http.MethodPut, "uploadId="},
	}

	for _, c := range cases {
		t.Run(c.method+"_"+c.query, func(t *testing.T) {
			h, _, tok, secret := fullSetupTestHandler(t)
			auth := authHeader(tok, secret)
			putObject(t, h, auth, "photos", "profile.jpg", original)

			w := do(t, h, auth, c.method, "/photos/profile.jpg?"+c.query, "payload")
			if w.Code != http.StatusNotImplemented {
				t.Errorf("%s ?%s: want 501, got %d: %s", c.method, c.query, w.Code, w.Body.String())
			}

			assertIntact(t, h, auth, original, c.method+" ?"+c.query)
		})
	}
}

// On a write the filter is an allowlist, so a name S3 adds tomorrow — or any
// stray param a client appends — fails on its own instead of being handed to
// handlePutObject.
func TestWrite_UnknownParam_DoesNotDestroyObject(t *testing.T) {
	const original = "the-original-photo-bytes"

	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			h, _, tok, secret := fullSetupTestHandler(t)
			auth := authHeader(tok, secret)
			putObject(t, h, auth, "photos", "profile.jpg", original)

			w := do(t, h, auth, method, "/photos/profile.jpg?somethingNewInS3", "payload")
			if w.Code != http.StatusNotImplemented {
				t.Errorf("%s: want 501, got %d: %s", method, w.Code, w.Body.String())
			}

			assertIntact(t, h, auth, original, method+" ?somethingNewInS3")
		})
	}
}

// ── reads: honest about sub-resources, permissive about the rest ───────────

// A read cannot destroy anything, but answering a sub-resource request with the
// object's bytes is a lie the client will parse as an ACL or a tag set.
func TestRead_UnimplementedSubresource_Returns501(t *testing.T) {
	h, _, tok, secret := fullSetupTestHandler(t)
	auth := authHeader(tok, secret)
	putObject(t, h, auth, "photos", "profile.jpg", "content")

	for _, sub := range []string{"tagging", "acl", "retention", "torrent", "attributes", "versionId=v1"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			w := do(t, h, auth, method, "/photos/profile.jpg?"+sub, "")
			if w.Code != http.StatusNotImplemented {
				t.Errorf("%s ?%s: want 501, got %d", method, sub, w.Code)
			}
		}
	}
}

// The mirror of the rule above: a read is held only to the denylist, so an
// innocuous param must still serve the object. `?v=<hash>` is the ordinary
// cache-busting pattern for images — turning that into a 501 would break
// clients to guard against a risk a GET does not carry.
func TestRead_BenignParam_ServesTheObject(t *testing.T) {
	const content = "content"
	h, _, tok, secret := fullSetupTestHandler(t)
	auth := authHeader(tok, secret)
	putObject(t, h, auth, "photos", "profile.jpg", content)

	for _, q := range []string{
		"v=8f3ac1",                         // cache buster
		"t=1690000000",                     // cache buster
		"response-content-type=image/jpeg", // header override
		"X-Amz-Expires=900",                // presigned SigV4
		"utm_source=newsletter",            // stray tracking param
	} {
		w := do(t, h, auth, http.MethodGet, "/photos/profile.jpg?"+q, "")
		if w.Code != http.StatusOK {
			t.Errorf("GET ?%s: want 200, got %d: %s", q, w.Code, w.Body.String())
			continue
		}
		if w.Body.String() != content {
			t.Errorf("GET ?%s: served %q, want %q", q, w.Body.String(), content)
		}
	}
}

// ── bucket level ──────────────────────────────────────────────────────────

// The bucket switch had the same shape as the object one: `DELETE
// /bucket?tagging` reached handleDeleteBucket and deleted the bucket itself.
func TestBucket_UnimplementedSubresource_DoesNotDeleteTheBucket(t *testing.T) {
	for _, sub := range []string{"tagging", "acl", "policy", "lifecycle", "cors", "versioning"} {
		t.Run(sub, func(t *testing.T) {
			h, _, tok, secret := fullSetupTestHandler(t)
			auth := authHeader(tok, secret)
			createBucket(t, h, auth, "photos")

			w := do(t, h, auth, http.MethodDelete, "/photos?"+sub, "")
			if w.Code != http.StatusNotImplemented {
				t.Errorf("DELETE /photos?%s: want 501, got %d: %s", sub, w.Code, w.Body.String())
			}

			if w := do(t, h, auth, http.MethodHead, "/photos", ""); w.Code != http.StatusOK {
				t.Fatalf("DELETE ?%s deleted the bucket: HEAD returned %d", sub, w.Code)
			}
		})
	}
}

// The three bucket sub-resources jay now implements are claimed by method, and
// only by their own. `?delete` is DeleteObjects on POST; on PUT or DELETE it is
// a name the allowlist still has to refuse, because reaching handleDeleteBucket
// with it would delete the bucket. Same for `?location` and `?uploads`.
func TestBucket_ImplementedSubresource_OnWrongMethod_Returns501(t *testing.T) {
	cases := []struct{ method, sub string }{
		{http.MethodPut, "delete"},
		{http.MethodDelete, "delete"},
		{http.MethodPut, "location"},
		{http.MethodDelete, "location"},
		{http.MethodPut, "uploads"},
		{http.MethodPost, "uploads"},
		{http.MethodDelete, "uploads"},
	}

	for _, c := range cases {
		t.Run(c.method+"_"+c.sub, func(t *testing.T) {
			h, _, tok, secret := fullSetupTestHandler(t)
			auth := authHeader(tok, secret)
			createBucket(t, h, auth, "photos")

			w := do(t, h, auth, c.method, "/photos?"+c.sub, "<Delete><Object><Key>a</Key></Object></Delete>")
			if w.Code != http.StatusNotImplemented {
				t.Errorf("%s /photos?%s: want 501, got %d: %s", c.method, c.sub, w.Code, w.Body.String())
			}

			if w := do(t, h, auth, http.MethodHead, "/photos", ""); w.Code != http.StatusOK {
				t.Fatalf("%s ?%s deleted the bucket: HEAD returned %d", c.method, c.sub, w.Code)
			}
		})
	}
}

// ── supported operations must not be caught by the filter ─────────────────

func TestSupportedOperations_NotBlocked(t *testing.T) {
	h, _, tok, secret := fullSetupTestHandler(t)
	auth := authHeader(tok, secret)
	putObject(t, h, auth, "photos", "profile.jpg", "content")

	if code, _ := getObjectBody(t, h, auth, "photos", "profile.jpg"); code != http.StatusOK {
		t.Fatalf("plain GET: want 200, got %d", code)
	}

	// ListObjectsV2 params are bucket-level and must survive the bucket filter.
	for _, q := range []string{
		"prefix=pro", "delimiter=/", "max-keys=10",
		"continuation-token=x", "start-after=a", "encoding-type=url", "list-type=2",
	} {
		if w := do(t, h, auth, http.MethodGet, "/photos?"+q, ""); w.Code != http.StatusOK {
			t.Errorf("GET /photos?%s: want 200, got %d: %s", q, w.Code, w.Body.String())
		}
	}

	// CreateMultipartUpload still works.
	if w := do(t, h, auth, http.MethodPost, "/photos/big.bin?uploads", ""); w.Code == http.StatusNotImplemented {
		t.Fatalf("?uploads should not 501: %s", w.Body.String())
	}
}

// A full multipart round trip: the write-side allowlist must not break
// UploadPart, which legitimately carries both uploadId and partNumber.
func TestMultipartRoundTrip_NotBlocked(t *testing.T) {
	h, _, tok, secret := fullSetupTestHandler(t)
	auth := authHeader(tok, secret)
	createBucket(t, h, auth, "photos")

	w := do(t, h, auth, http.MethodPost, "/photos/big.bin?uploads", "")
	if w.Code != http.StatusOK {
		t.Fatalf("CreateMultipartUpload: want 200, got %d: %s", w.Code, w.Body.String())
	}
	uploadID := extractTag(t, w.Body.String(), "UploadId")

	part := do(t, h, auth, http.MethodPut,
		"/photos/big.bin?uploadId="+uploadID+"&partNumber=1", "part-one-contents")
	if part.Code != http.StatusOK {
		t.Fatalf("UploadPart: want 200, got %d: %s", part.Code, part.Body.String())
	}
	etag := part.Header().Get("ETag")

	body := "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>" +
		etag + "</ETag></Part></CompleteMultipartUpload>"
	done := do(t, h, auth, http.MethodPost, "/photos/big.bin?uploadId="+uploadID, body)
	if done.Code != http.StatusOK {
		t.Fatalf("CompleteMultipartUpload: want 200, got %d: %s", done.Code, done.Body.String())
	}

	code, got := getObjectBody(t, h, auth, "photos", "big.bin")
	if code != http.StatusOK || got != "part-one-contents" {
		t.Fatalf("assembled object: got %d %q", code, got)
	}
}

func extractTag(t *testing.T, doc, tag string) string {
	t.Helper()
	open, closing := "<"+tag+">", "</"+tag+">"
	i := strings.Index(doc, open)
	j := strings.Index(doc, closing)
	if i < 0 || j < 0 {
		t.Fatalf("no <%s> in %s", tag, doc)
	}
	return doc[i+len(open) : j]
}
