package meta

import (
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.SetSigningSecret("test-signing-secret-at-least-32-chars")
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestCreateAccountIfNotExists_Fresh(t *testing.T) {
	db := openTestDB(t)
	acc, created, err := db.CreateAccountIfNotExists("falco")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !created {
		t.Fatal("expected created=true on fresh insert")
	}
	if acc.Name != "falco" || acc.Status != "active" {
		t.Fatalf("bad account: %+v", acc)
	}
}

func TestCreateAccountIfNotExists_Idempotent(t *testing.T) {
	db := openTestDB(t)
	a1, _, _ := db.CreateAccountIfNotExists("falco")
	a2, created, err := db.CreateAccountIfNotExists("falco")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if created {
		t.Fatal("expected created=false on second call")
	}
	if a1.AccountID != a2.AccountID {
		t.Fatalf("account id changed: %s vs %s", a1.AccountID, a2.AccountID)
	}
}

func TestCreateTokenIfNotExists_Fresh(t *testing.T) {
	db := openTestDB(t)
	acc, _, _ := db.CreateAccountIfNotExists("falco")
	hash, _ := bcrypt.GenerateFromPassword([]byte("sekret"), bcrypt.DefaultCost)
	tok, status, err := db.CreateTokenIfNotExists("falco-native", acc.AccountID, "falco", string(hash), "sekret", []string{"*"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status != TokenSeedCreated {
		t.Fatalf("expected TokenSeedCreated, got %v", status)
	}
	if tok.TokenID != "falco-native" {
		t.Fatalf("wrong token id: %s", tok.TokenID)
	}
}

func TestCreateTokenIfNotExists_SameSecret(t *testing.T) {
	db := openTestDB(t)
	acc, _, _ := db.CreateAccountIfNotExists("falco")
	hash, _ := bcrypt.GenerateFromPassword([]byte("sekret"), bcrypt.DefaultCost)
	_, _, _ = db.CreateTokenIfNotExists("falco-native", acc.AccountID, "falco", string(hash), "sekret", []string{"*"})
	_, status, err := db.CreateTokenIfNotExists("falco-native", acc.AccountID, "falco", string(hash), "sekret", []string{"*"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status != TokenSeedReused {
		t.Fatalf("expected TokenSeedReused, got %v", status)
	}
}

func TestCreateTokenIfNotExists_SecretMismatch(t *testing.T) {
	db := openTestDB(t)
	acc, _, _ := db.CreateAccountIfNotExists("falco")
	hash1, _ := bcrypt.GenerateFromPassword([]byte("sekret"), bcrypt.DefaultCost)
	_, _, _ = db.CreateTokenIfNotExists("falco-native", acc.AccountID, "falco", string(hash1), "sekret", []string{"*"})

	hash2, _ := bcrypt.GenerateFromPassword([]byte("different"), bcrypt.DefaultCost)
	_, status, err := db.CreateTokenIfNotExists("falco-native", acc.AccountID, "falco", string(hash2), "different", []string{"*"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status != TokenSeedMismatch {
		t.Fatalf("expected TokenSeedMismatch, got %v", status)
	}
}

func TestListAccounts_ReturnsEveryAccountAndNothingElse(t *testing.T) {
	db := openTestDB(t)

	empty, err := db.ListAccounts()
	if err != nil {
		t.Fatalf("list on an empty store: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("an empty store listed %d accounts", len(empty))
	}

	want := map[string]string{}
	for _, name := range []string{"falco", "birdple", "colibri"} {
		a := &Account{AccountID: "id-" + name, Name: name}
		if err := db.CreateAccount(a); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		want[a.AccountID] = name
	}
	// A token is not an account: it lives in its own bucket and must not leak
	// into the listing.
	if err := db.CreateToken(&Token{TokenID: "tok", AccountID: "id-falco", Name: "t", SecretKey: "s",
		SecretHash: "h", AllowedActions: []string{"*"}}); err != nil {
		t.Fatalf("create token: %v", err)
	}

	got, err := db.ListAccounts()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("listed %d accounts, want %d: %+v", len(got), len(want), got)
	}
	for _, a := range got {
		if want[a.AccountID] != a.Name || a.Status != "active" || a.CreatedAt.IsZero() {
			t.Fatalf("listed %+v, want name %q, active, with a creation time", a, want[a.AccountID])
		}
		delete(want, a.AccountID)
	}
	if len(want) != 0 {
		t.Fatalf("accounts missing from the listing: %v", want)
	}
}
