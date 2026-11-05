package meta_test

// RekeyTokens is what cmd/jay-rekey runs after JAY_SIGNING_SECRET changes, and
// the documented way back from a rotation. A mistake here leaves every token
// unreadable, so these tests judge it the way a client would: by
// authenticating through auth, with the database read under one secret and
// then the other. extra_test.go covers the single-token round trip; this file
// covers what can go wrong.

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"uuid"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/meta"
	"golang.org/x/crypto/bcrypt"
)

const (
	rekeyOld   = "old-signing-secret-of-at-least-32-bytes"
	rekeyNew   = "new-signing-secret-of-at-least-32-bytes"
	rekeyThird = "a-third-secret-that-is-neither-of-them"
)

type rekeyFixture struct {
	db        *meta.DB
	accountID string
}

type seededToken struct{ id, secret string }

func newRekeyFixture(t *testing.T) *rekeyFixture {
	t.Helper()
	db, err := meta.Open(filepath.Join(t.TempDir(), "meta", "jay.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetSigningSecret(rekeyOld)

	acc := &meta.Account{AccountID: uuid.New().String(), Name: "rekey", Status: "active"}
	if err := db.CreateAccount(acc); err != nil {
		t.Fatalf("create account: %v", err)
	}
	return &rekeyFixture{db: db, accountID: acc.AccountID}
}

// seed creates n tokens encrypted under signingSecret.
func (f *rekeyFixture) seed(t *testing.T, signingSecret, prefix string, n int) []seededToken {
	t.Helper()
	f.db.SetSigningSecret(signingSecret)
	var out []seededToken
	for i := range n {
		tok := seededToken{id: prefix + "-" + strconv.Itoa(i), secret: prefix + "-secret-" + strconv.Itoa(i)}
		// Minimum bcrypt cost: the secret's hash is not what this tests, and
		// the default cost makes every check take seconds under -race.
		hash, err := bcrypt.GenerateFromPassword([]byte(tok.secret), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		if err := f.db.CreateToken(&meta.Token{
			TokenID: tok.id, AccountID: f.accountID, Name: tok.id,
			SecretHash: string(hash), SecretKey: tok.secret, AllowedActions: []string{"*"},
		}); err != nil {
			t.Fatalf("create token %s: %v", tok.id, err)
		}
		out = append(out, tok)
	}
	return out
}

// readable reports whether every token authenticates, and decrypts to its
// own secret, when the database is read under signingSecret. The decrypted
// secret is what SigV4 signs with; bearer auth fails too when it cannot be
// decrypted.
func (f *rekeyFixture) readable(t *testing.T, signingSecret string, toks []seededToken) (ok, failed []string) {
	t.Helper()
	f.db.SetSigningSecret(signingSecret)
	au := auth.New(f.db) // fresh: no cache from an earlier secret
	for _, tok := range toks {
		stored, err := f.db.GetToken(tok.id)
		if err == nil && stored.SecretKey != tok.secret {
			t.Fatalf("token %s decrypted to the wrong secret under %q", tok.id, signingSecret)
		}
		if err == nil {
			_, err = au.AuthenticateCredentials(tok.id, tok.secret)
		}
		if err != nil {
			failed = append(failed, tok.id)
		} else {
			ok = append(ok, tok.id)
		}
	}
	return ok, failed
}

func (f *rekeyFixture) requireReadable(t *testing.T, signingSecret, label string, toks []seededToken) {
	t.Helper()
	if _, failed := f.readable(t, signingSecret, toks); len(failed) > 0 {
		t.Fatalf("under the %s secret these tokens do not authenticate: %v", label, failed)
	}
}

func (f *rekeyFixture) requireUnreadable(t *testing.T, signingSecret, label string, toks []seededToken) {
	t.Helper()
	if ok, _ := f.readable(t, signingSecret, toks); len(ok) > 0 {
		t.Fatalf("under the %s secret these tokens still authenticate: %v", label, ok)
	}
}

func TestRekeyTokens_TokensMoveToTheNewSecretAndLeaveTheOld(t *testing.T) {
	f := newRekeyFixture(t)
	toks := f.seed(t, rekeyOld, "tok", 3)

	n, err := f.db.RekeyTokens(rekeyOld, rekeyNew)
	if err != nil {
		t.Fatalf("RekeyTokens: %v", err)
	}
	if n != len(toks) {
		t.Fatalf("rekeyed %d, want %d", n, len(toks))
	}
	f.requireReadable(t, rekeyNew, "new", toks)
	f.requireUnreadable(t, rekeyOld, "old", toks)
}

// A wrong old secret must fail before anything is written: a run that
// re-encrypted some tokens and not others would leave a database no single
// secret can read.
func TestRekeyTokens_AWrongOldSecretWritesNothing(t *testing.T) {
	f := newRekeyFixture(t)
	toks := f.seed(t, rekeyOld, "tok", 3)

	n, err := f.db.RekeyTokens(rekeyThird, rekeyNew)
	if err == nil {
		t.Fatal("RekeyTokens with the wrong old secret succeeded")
	}
	if n != 0 {
		t.Fatalf("reported %d rekeyed on failure", n)
	}
	f.requireReadable(t, rekeyOld, "real old", toks)
	f.requireUnreadable(t, rekeyNew, "new", toks)
}

// Same rule when only ONE token is unreadable and it is not the first one the
// scan meets: the tokens before it must not have been rewritten.
func TestRekeyTokens_OneUnreadableTokenAbortsTheWholeRun(t *testing.T) {
	f := newRekeyFixture(t)
	good := f.seed(t, rekeyOld, "a", 2)
	stray := f.seed(t, rekeyThird, "z", 1) // sorts after "a-*" in bbolt

	if _, err := f.db.RekeyTokens(rekeyOld, rekeyNew); err == nil {
		t.Fatal("RekeyTokens succeeded with a token that decrypts under neither secret")
	} else if !strings.Contains(err.Error(), stray[0].id) {
		t.Fatalf("the error does not name the token that stopped the run: %v", err)
	}
	f.requireReadable(t, rekeyOld, "old", good)
	f.requireUnreadable(t, rekeyNew, "new", good)
	f.requireReadable(t, rekeyThird, "third", stray)
}

// The documented contract is that a second run with the same arguments is
// harmless. It used to fail: every token was already under the new secret,
// so decrypting it with the old one errored.
func TestRekeyTokens_ASecondRunIsANoOp(t *testing.T) {
	f := newRekeyFixture(t)
	toks := f.seed(t, rekeyOld, "tok", 2)

	if _, err := f.db.RekeyTokens(rekeyOld, rekeyNew); err != nil {
		t.Fatalf("first run: %v", err)
	}
	n, err := f.db.RekeyTokens(rekeyOld, rekeyNew)
	if err != nil {
		t.Fatalf("second run with the same arguments: %v", err)
	}
	if n != 0 {
		t.Fatalf("second run rekeyed %d tokens, want 0", n)
	}
	f.requireReadable(t, rekeyNew, "new", toks)
}

// The likeliest way to need jay-rekey: the server was restarted with the new
// secret before the rekey ran, and a token was minted in between — so the
// database holds tokens under BOTH secrets. The rekey has to move the old ones
// and leave the new one, or the operator has no way back short of editing
// bbolt by hand (there is no endpoint that deletes a token record).
func TestRekeyTokens_RecoversADatabaseWrittenUnderBothSecrets(t *testing.T) {
	f := newRekeyFixture(t)
	before := f.seed(t, rekeyOld, "before", 2)
	after := f.seed(t, rekeyNew, "after", 1)

	n, err := f.db.RekeyTokens(rekeyOld, rekeyNew)
	if err != nil {
		t.Fatalf("RekeyTokens on a mixed database: %v", err)
	}
	if n != len(before) {
		t.Fatalf("rekeyed %d, want %d (only the tokens still under the old secret)", n, len(before))
	}
	f.requireReadable(t, rekeyNew, "new", append(before, after...))
}

// jay refuses to start with a JAY_SIGNING_SECRET under 32 bytes. Rekeying to a
// shorter one reports success and leaves a database the server cannot be
// started against.
func TestRekeyTokens_RefusesANewSecretTheServerWouldRefuse(t *testing.T) {
	f := newRekeyFixture(t)
	toks := f.seed(t, rekeyOld, "tok", 2)

	short := strings.Repeat("s", 31)
	if n, err := f.db.RekeyTokens(rekeyOld, short); err == nil || n != 0 {
		t.Fatalf("RekeyTokens to a %d-byte secret: n=%d err=%v, want a refusal", len(short), n, err)
	}
	f.requireReadable(t, rekeyOld, "old", toks)

	exact := strings.Repeat("s", 32)
	if n, err := f.db.RekeyTokens(rekeyOld, exact); err != nil || n != len(toks) {
		t.Fatalf("RekeyTokens to a 32-byte secret: n=%d err=%v", n, err)
	}
	f.requireReadable(t, exact, "32-byte", toks)
}
