package objops_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"uuid"

	"github.com/ivangsm/jay/internal/objops"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

type bucketFixture struct {
	svc     *objops.Service
	db      *meta.DB
	st      *store.Store
	account *meta.Account
	token   *meta.Token
}

func newBucketFixture(t *testing.T) *bucketFixture {
	t.Helper()
	dir := t.TempDir()
	db, err := meta.Open(filepath.Join(dir, "jay.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetSigningSecret("test-signing-secret-at-least-32-chars-long!")
	t.Cleanup(func() { _ = db.Close() })
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	acc := &meta.Account{AccountID: uuid.New().String(), Name: "owner", Status: "active"}
	if err := db.CreateAccount(acc); err != nil {
		t.Fatal(err)
	}
	tok := &meta.Token{TokenID: "tok", AccountID: acc.AccountID, Name: "t", SecretHash: "ignored",
		AllowedActions: meta.AllActions, Status: "active"}
	if err := db.CreateToken(tok); err != nil {
		t.Fatal(err)
	}
	return &bucketFixture{
		svc:     objops.New(db, st, slog.New(slog.NewTextHandler(io.Discard, nil))),
		db:      db,
		st:      st,
		account: acc,
		token:   tok,
	}
}

func TestCreateBucket_CommitsTheRecordAndTheDirectory(t *testing.T) {
	f := newBucketFixture(t)

	b, err := f.svc.CreateBucket("fresh-bucket", f.account.AccountID)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	stored, err := f.db.GetBucket("fresh-bucket")
	if err != nil {
		t.Fatalf("the bucket is not in meta: %v", err)
	}
	if stored.ID != b.ID || stored.OwnerAccountID != f.account.AccountID ||
		stored.Visibility != meta.VisibilityPrivate || stored.Status != "active" {
		t.Fatalf("stored %+v, returned %+v; want the owner, private and active", stored, b)
	}
	dir, err := f.st.BucketObjectsDir(b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("the bucket directory %s was not created: %v", dir, err)
	}
}

func TestCreateBucket_AnInvalidNameLeavesNothingBehind(t *testing.T) {
	f := newBucketFixture(t)

	for _, name := range []string{"", "ab", "UPPER", "has_underscore", "double--dash", "dots..dots", "192.168.0.1", "-leading"} {
		if _, err := f.svc.CreateBucket(name, f.account.AccountID); !errors.Is(err, objops.ErrInvalidBucketName) {
			t.Fatalf("%q: want ErrInvalidBucketName, got %v", name, err)
		}
	}
	buckets, err := f.db.ListBuckets("")
	if err != nil {
		t.Fatal(err)
	}
	if len(buckets) != 0 {
		t.Fatalf("refused names left %d buckets in meta", len(buckets))
	}
}

func TestCreateBucket_ARepeatedNameIsRefusedAndKeepsTheFirst(t *testing.T) {
	f := newBucketFixture(t)
	first, err := f.svc.CreateBucket("taken-name", f.account.AccountID)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.svc.CreateBucket("taken-name", f.account.AccountID); !errors.Is(err, meta.ErrBucketExists) {
		t.Fatalf("want meta.ErrBucketExists, got %v", err)
	}
	stored, err := f.db.GetBucket("taken-name")
	if err != nil || stored.ID != first.ID {
		t.Fatalf("the repeated create replaced the first bucket: %+v, %v", stored, err)
	}
}

func TestDeleteBucket_AnEmptyBucketIsGoneFromMetaAndDisk(t *testing.T) {
	f := newBucketFixture(t)
	b, err := f.svc.CreateBucket("to-remove", f.account.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := f.st.BucketObjectsDir(b.ID)

	removed, err := f.svc.DeleteBucket("to-remove")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if removed.ID != b.ID {
		t.Fatalf("returned bucket %s, want the removed one %s", removed.ID, b.ID)
	}
	if _, err := f.db.GetBucket("to-remove"); !errors.Is(err, meta.ErrBucketNotFound) {
		t.Fatalf("the bucket is still in meta: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the bucket directory survived: %v", err)
	}
}

func TestDeleteBucket_ABucketWithAnObjectIsRefusedAndSurvives(t *testing.T) {
	f := newBucketFixture(t)
	b, err := f.svc.CreateBucket("not-empty", f.account.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	id := objops.Identity{TokenID: f.token.TokenID, AccountID: f.account.AccountID, Action: meta.ActionObjectPut}
	if _, err := f.svc.PutObject(context.Background(), f.token, "not-empty", "k", "text/plain",
		bytes.NewReader([]byte("payload")), objops.PutOptions{}, id); err != nil {
		t.Fatalf("put: %v", err)
	}

	if _, err := f.svc.DeleteBucket("not-empty"); !errors.Is(err, meta.ErrBucketNotEmpty) {
		t.Fatalf("want meta.ErrBucketNotEmpty, got %v", err)
	}
	if _, err := f.db.GetBucket("not-empty"); err != nil {
		t.Fatalf("a refused delete removed the bucket record: %v", err)
	}
	if _, err := f.db.GetObjectMeta(b.ID, "k"); err != nil {
		t.Fatalf("a refused delete lost the object record: %v", err)
	}
	dir, _ := f.st.BucketObjectsDir(b.ID)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("a refused delete removed the directory: %v", err)
	}
}

func TestDeleteBucket_AMissingBucketIsNotFound(t *testing.T) {
	f := newBucketFixture(t)
	_, err := f.svc.DeleteBucket("never-existed")
	if !errors.Is(err, objops.ErrBucketNotFound) || !errors.Is(err, meta.ErrBucketNotFound) {
		t.Fatalf("want an error that is both objops and meta ErrBucketNotFound, got %v", err)
	}
}
