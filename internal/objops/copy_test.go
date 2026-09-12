package objops_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"uuid"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/internal/objops"
	"github.com/ivangsm/jay/meta"
)

func putForCopy(t *testing.T, svc *objops.Service, tok *meta.Token, bucket, key, body string) *meta.Object {
	t.Helper()
	id := objops.Identity{TokenID: tok.TokenID, AccountID: tok.AccountID, Action: meta.ActionObjectPut}
	obj, err := svc.PutObject(context.Background(), tok, bucket, key, "text/plain",
		bytes.NewReader([]byte(body)), objops.PutOptions{UserMetadata: map[string]string{"x-amz-meta-origin": "test"}}, id)
	if err != nil {
		t.Fatalf("put %s/%s: %v", bucket, key, err)
	}
	return obj
}

func TestCopyObject_CarriesBytesAndMetadata(t *testing.T) {
	svc, db, tok, bkt := setupTestService(t)
	src := putForCopy(t, svc, tok, bkt.Name, "a.txt", "hello copy")

	id := objops.Identity{TokenID: tok.TokenID, AccountID: tok.AccountID}
	dst, err := svc.CopyObject(context.Background(), tok, bkt.Name, "a.txt", bkt.Name, "b.txt", objops.CopyOptions{}, id)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if dst.LocationRef == src.LocationRef {
		t.Fatal("copy must write its own file, not alias the source")
	}
	if dst.ChecksumSHA256 != src.ChecksumSHA256 || dst.ETag != src.ETag || dst.SizeBytes != src.SizeBytes {
		t.Fatalf("copy differs from source: %+v vs %+v", dst, src)
	}
	if dst.ContentType != "text/plain" || dst.MetadataHeaders["x-amz-meta-origin"] != "test" {
		t.Fatalf("content type / user metadata not carried over: %+v", dst)
	}

	// The effect in the database, not the return value.
	stored, err := db.GetObjectMeta(bkt.ID, "b.txt")
	if err != nil {
		t.Fatalf("destination not committed: %v", err)
	}
	var buf bytes.Buffer
	getID := objops.Identity{TokenID: tok.TokenID, AccountID: tok.AccountID, Action: meta.ActionObjectGet}
	if _, err := svc.GetObject(context.Background(), tok, bkt.Name, "b.txt", &buf, getID); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "hello copy" || stored.ObjectID != dst.ObjectID {
		t.Fatalf("read back %q (id %s), want %q (id %s)", buf.String(), stored.ObjectID, "hello copy", dst.ObjectID)
	}
}

func TestCopyObject_MissingSourceNamesTheSource(t *testing.T) {
	svc, _, tok, bkt := setupTestService(t)
	id := objops.Identity{TokenID: tok.TokenID, AccountID: tok.AccountID}

	_, err := svc.CopyObject(context.Background(), tok, bkt.Name, "nope", bkt.Name, "b", objops.CopyOptions{}, id)
	if !errors.Is(err, objops.ErrObjectNotFound) || objops.SideOfCopyError(err) != objops.CopySource {
		t.Fatalf("want source ErrObjectNotFound, got %v (side %q)", err, objops.SideOfCopyError(err))
	}

	_, err = svc.CopyObject(context.Background(), tok, "no-such-bucket", "k", bkt.Name, "b", objops.CopyOptions{}, id)
	if !errors.Is(err, objops.ErrBucketNotFound) || objops.SideOfCopyError(err) != objops.CopySource {
		t.Fatalf("want source ErrBucketNotFound, got %v", err)
	}

	putForCopy(t, svc, tok, bkt.Name, "a", "x")
	_, err = svc.CopyObject(context.Background(), tok, bkt.Name, "a", "no-such-bucket", "b", objops.CopyOptions{}, id)
	if !errors.Is(err, objops.ErrBucketNotFound) || objops.SideOfCopyError(err) != objops.CopyDestination {
		t.Fatalf("want destination ErrBucketNotFound, got %v", err)
	}
}

func TestCopyObject_PolicyDenyOnSourceBlocksExfiltration(t *testing.T) {
	svc, db, tok, bkt := setupTestService(t)
	putForCopy(t, svc, tok, bkt.Name, "secret/a", "classified")

	policy := auth.BucketPolicy{
		Version: "1",
		Statements: []auth.PolicyStatement{{
			Effect:   "deny",
			Actions:  []string{meta.ActionObjectGet},
			Prefixes: []string{"secret/"},
			Subjects: []string{tok.TokenID},
		}},
	}
	raw, _ := json.Marshal(policy)
	if err := db.UpdateBucketPolicy(bkt.Name, raw); err != nil {
		t.Fatal(err)
	}

	id := objops.Identity{TokenID: tok.TokenID, AccountID: tok.AccountID}
	_, err := svc.CopyObject(context.Background(), tok, bkt.Name, "secret/a", bkt.Name, "public/a", objops.CopyOptions{}, id)
	if !errors.Is(err, objops.ErrPolicyDenied) || objops.SideOfCopyError(err) != objops.CopySource {
		t.Fatalf("want source ErrPolicyDenied, got %v", err)
	}
	if _, err := db.GetObjectMeta(bkt.ID, "public/a"); !errors.Is(err, meta.ErrObjectNotFound) {
		t.Fatalf("a denied copy must write nothing, got %v", err)
	}
}

func TestCopyObject_CrossAccountDestinationDenied(t *testing.T) {
	svc, db, tok, bkt := setupTestService(t)
	putForCopy(t, svc, tok, bkt.Name, "a", "x")

	other := &meta.Account{AccountID: uuid.New().String(), Name: "other", Status: "active"}
	if err := db.CreateAccount(other); err != nil {
		t.Fatal(err)
	}
	foreign := &meta.Bucket{ID: uuid.New().String(), Name: "foreign", OwnerAccountID: other.AccountID, Visibility: "private", Status: "active"}
	if err := db.CreateBucket(foreign); err != nil {
		t.Fatal(err)
	}

	id := objops.Identity{TokenID: tok.TokenID, AccountID: tok.AccountID}
	_, err := svc.CopyObject(context.Background(), tok, bkt.Name, "a", "foreign", "a", objops.CopyOptions{}, id)
	if !errors.Is(err, objops.ErrAccessDenied) || objops.SideOfCopyError(err) != objops.CopyDestination {
		t.Fatalf("want destination ErrAccessDenied, got %v", err)
	}
}

func TestCopyObject_BeforeCommitRefusalWritesNothing(t *testing.T) {
	svc, db, tok, bkt := setupTestService(t)
	putForCopy(t, svc, tok, bkt.Name, "a", "x")
	prev := putForCopy(t, svc, tok, bkt.Name, "b", "previous version")

	refused := errors.New("no digest for you")
	id := objops.Identity{TokenID: tok.TokenID, AccountID: tok.AccountID}
	_, err := svc.CopyObject(context.Background(), tok, bkt.Name, "a", bkt.Name, "b",
		objops.CopyOptions{BeforeCommit: func(string) error { return refused }}, id)
	if !errors.Is(err, refused) {
		t.Fatalf("want the hook's error, got %v", err)
	}

	// The previous version of the destination is untouched, on disk and in
	// bbolt: the refusal happened before anything replaced it.
	stored, err := db.GetObjectMeta(bkt.ID, "b")
	if err != nil || stored.ObjectID != prev.ObjectID {
		t.Fatalf("previous version replaced or lost: %v %+v", err, stored)
	}
	f, err := svc.OpenObjectFile(stored)
	if err != nil {
		t.Fatalf("previous version's file is gone: %v", err)
	}
	_ = f.Close()
}

func TestResolveRange(t *testing.T) {
	cases := []struct {
		name                 string
		offset, length, size int64
		wantStart, wantN     int64
		wantErr              bool
	}{
		{"whole via zero length", 0, 0, 10, 0, 10, false},
		{"whole via negative length", 0, -1, 10, 0, 10, false},
		{"middle", 2, 3, 10, 2, 3, false},
		{"length clamped to end", 8, 100, 10, 8, 2, false},
		{"tail", 9, 1, 10, 9, 1, false},
		{"offset at end", 10, 1, 10, 0, 0, true},
		{"offset past end", 11, 1, 10, 0, 0, true},
		{"negative offset", -1, 1, 10, 0, 0, true},
		{"empty object", 0, 0, 0, 0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, n, err := objops.ResolveRange(tc.offset, tc.length, tc.size)
			if tc.wantErr {
				if !errors.Is(err, objops.ErrInvalidRange) {
					t.Fatalf("want ErrInvalidRange, got %v", err)
				}
				return
			}
			if err != nil || start != tc.wantStart || n != tc.wantN {
				t.Fatalf("got (%d, %d, %v), want (%d, %d, nil)", start, n, err, tc.wantStart, tc.wantN)
			}
		})
	}
}
