package objops_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/internal/objops"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

// setupTestService spins up an in-memory-backed meta.DB and a temp-dir store,
// creates one account + one token with full actions, and returns the wired-up
// objops.Service along with the handles needed to arrange + assert state.
func setupTestService(t *testing.T) (*objops.Service, *meta.DB, *meta.Token, *meta.Bucket) {
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

	acc := &meta.Account{AccountID: uuid.New().String(), Name: "test", Status: "active"}
	if err := db.CreateAccount(acc); err != nil {
		t.Fatal(err)
	}

	tok := &meta.Token{
		TokenID:        "tok-1",
		AccountID:      acc.AccountID,
		Name:           "t",
		SecretHash:     "ignored",
		AllowedActions: meta.AllActions,
		Status:         "active",
	}
	if err := db.CreateToken(tok); err != nil {
		t.Fatal(err)
	}

	bkt := &meta.Bucket{
		ID:             uuid.New().String(),
		Name:           "bkt",
		OwnerAccountID: acc.AccountID,
		Visibility:     "private",
		Status:         "active",
	}
	if err := db.CreateBucket(bkt); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return objops.New(db, st, log), db, tok, bkt
}

func TestPutGetHeadDelete_RoundTrip(t *testing.T) {
	svc, _, tok, _ := setupTestService(t)
	ctx := context.Background()
	id := objops.Identity{TokenID: tok.TokenID, AccountID: tok.AccountID, SourceIP: "10.0.0.1"}

	// PUT
	putID := id
	putID.Action = meta.ActionObjectPut
	_, err := svc.PutObject(ctx, tok, "bkt", "hello.txt", "text/plain",
		bytes.NewReader([]byte("hello world")), objops.PutOptions{}, putID)
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	// HEAD
	headID := id
	headID.Action = meta.ActionObjectGet
	obj, err := svc.HeadObject(ctx, tok, "bkt", "hello.txt", headID)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if obj.SizeBytes != 11 {
		t.Fatalf("want size 11, got %d", obj.SizeBytes)
	}

	// GET (body stream)
	var buf bytes.Buffer
	getID := id
	getID.Action = meta.ActionObjectGet
	obj, err = svc.GetObject(ctx, tok, "bkt", "hello.txt", &buf, getID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if buf.String() != "hello world" {
		t.Fatalf("body mismatch: %q", buf.String())
	}
	if obj.ChecksumSHA256 == "" {
		t.Fatal("missing checksum")
	}

	// DELETE
	delID := id
	delID.Action = meta.ActionObjectDelete
	if err := svc.DeleteObject(ctx, tok, "bkt", "hello.txt", delID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// GET after delete → ErrObjectNotFound
	_, err = svc.HeadObject(ctx, tok, "bkt", "hello.txt", headID)
	if !errors.Is(err, objops.ErrObjectNotFound) {
		t.Fatalf("want ErrObjectNotFound, got %v", err)
	}

	// DELETE idempotent
	if err := svc.DeleteObject(ctx, tok, "bkt", "gone.txt", delID); err != nil {
		t.Fatalf("delete-noop: %v", err)
	}
}

func TestBucketPolicyDeny_BlocksGet(t *testing.T) {
	svc, db, tok, bkt := setupTestService(t)
	ctx := context.Background()

	// Attach a policy that denies GET for this token on prefix "secret/".
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
		t.Fatalf("attach policy: %v", err)
	}

	// PUT is allowed (policy only blocks GET).
	putID := objops.Identity{TokenID: tok.TokenID, AccountID: tok.AccountID, Action: meta.ActionObjectPut}
	if _, err := svc.PutObject(ctx, tok, "bkt", "secret/data.bin", "application/octet-stream",
		bytes.NewReader([]byte("classified")), objops.PutOptions{}, putID); err != nil {
		t.Fatalf("put: %v", err)
	}

	// GET must be denied by policy.
	getID := objops.Identity{TokenID: tok.TokenID, AccountID: tok.AccountID, Action: meta.ActionObjectGet}
	_, err := svc.GetObject(ctx, tok, "bkt", "secret/data.bin", io.Discard, getID)
	if !errors.Is(err, objops.ErrPolicyDenied) {
		t.Fatalf("want ErrPolicyDenied, got %v", err)
	}

	// GET on a non-matching prefix is still allowed.
	if _, err := svc.PutObject(ctx, tok, "bkt", "public/ok.bin", "application/octet-stream",
		bytes.NewReader([]byte("ok")), objops.PutOptions{}, putID); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := svc.GetObject(ctx, tok, "bkt", "public/ok.bin", &buf, getID); err != nil {
		t.Fatalf("allowed get: %v", err)
	}
	if buf.String() != "ok" {
		t.Fatalf("body mismatch: %q", buf.String())
	}
}

func TestBucketNotFound(t *testing.T) {
	svc, _, tok, _ := setupTestService(t)
	ctx := context.Background()
	id := objops.Identity{TokenID: tok.TokenID, Action: meta.ActionObjectGet}
	_, err := svc.HeadObject(ctx, tok, "no-such-bucket", "x", id)
	if !errors.Is(err, objops.ErrBucketNotFound) {
		t.Fatalf("want ErrBucketNotFound, got %v", err)
	}
}

func TestTokenMissingAction_Denied(t *testing.T) {
	svc, db, _, _ := setupTestService(t)
	ctx := context.Background()

	// A token that is explicitly NOT allowed to PUT.
	readTok := &meta.Token{
		TokenID:        "read-only",
		AccountID:      "acct-x",
		Name:           "ro",
		SecretHash:     "ignored",
		AllowedActions: []string{meta.ActionObjectGet},
		Status:         "active",
	}
	// Seed the token's account too — otherwise auth wouldn't care, but objops
	// doesn't re-check Account status (that's auth.validateToken's job). We
	// only need the token record present so objops.authorize runs its scope
	// checks.
	_ = db.CreateAccount(&meta.Account{AccountID: "acct-x", Name: "x", Status: "active"})
	if err := db.CreateToken(readTok); err != nil {
		t.Fatal(err)
	}

	id := objops.Identity{TokenID: readTok.TokenID, AccountID: readTok.AccountID, Action: meta.ActionObjectPut}
	_, err := svc.PutObject(ctx, readTok, "bkt", "x", "text/plain",
		bytes.NewReader([]byte("x")), objops.PutOptions{}, id)
	if !errors.Is(err, objops.ErrAccessDenied) {
		t.Fatalf("want ErrAccessDenied, got %v", err)
	}
}
