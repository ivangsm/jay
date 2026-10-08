package admin

import (
	jsonv2 "encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

type listedAccount struct {
	AccountID string    `json:"account_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
}

func decodeAccounts(t *testing.T, w *httptest.ResponseRecorder) []listedAccount {
	t.Helper()
	requireStatus(t, w, http.StatusOK)
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var out []listedAccount
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("not a JSON array of accounts: %q: %v", w.Body.String(), err)
	}
	return out
}

// With no account at all the answer is "[]": a "null" would make every client
// special-case the one state a fresh install is in.
func TestListAccounts_NoAccountsIsAnEmptyArrayNotNull(t *testing.T) {
	dir := t.TempDir()
	db, err := meta.Open(filepath.Join(dir, "jay.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetSigningSecret(testSigningKey)
	t.Cleanup(func() { _ = db.Close() })
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(AdminConfig{
		DB: db, Store: st, Auth: auth.New(db), AdminToken: testAdminToken,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Metrics: maintenance.NewMetrics(),
		SigningSecret: testSigningKey,
	})
	t.Cleanup(func() { _ = h.Close() })

	req := httptest.NewRequest(http.MethodGet, "http://jay.test/_jay/accounts", nil)
	req.Header.Set("Authorization", adminBearer)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	requireStatus(t, w, http.StatusOK)
	if got := strings.TrimSpace(w.Body.String()); got != "[]" {
		t.Fatalf("body = %q, want []", got)
	}
}

// Oldest first, ties broken on the id. bbolt returns them in id order, which
// is random; without the sort the list would not be the same twice.
func TestListAccounts_OrderedByCreationThenID(t *testing.T) {
	f := newControlFixture(t)
	base := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	// Inserted in an order that is neither by time nor by id.
	for _, a := range []meta.Account{
		{AccountID: "zzz", Name: "late", CreatedAt: base.Add(time.Hour)},
		{AccountID: "bbb", Name: "tie-b", CreatedAt: base},
		{AccountID: "aaa-newest", Name: "newest", CreatedAt: base.Add(2 * time.Hour)},
		{AccountID: "aaa", Name: "tie-a", CreatedAt: base},
	} {
		if err := f.db.CreateAccount(&a); err != nil {
			t.Fatalf("create %s: %v", a.AccountID, err)
		}
	}

	got := decodeAccounts(t, f.as(t, http.MethodGet, "/_jay/accounts", ""))

	var order []string
	for _, a := range got {
		order = append(order, a.AccountID)
	}
	// The fixture's own account was created "now", so it sorts last.
	want := []string{"aaa", "bbb", "zzz", "aaa-newest", f.account.AccountID}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for _, a := range got {
		if a.Name == "" || a.Status != "active" || a.CreatedAt.IsZero() {
			t.Fatalf("incomplete row %+v", a)
		}
	}
}

// A read changes nothing and answers from bbolt: an account created through
// the API appears in the next listing.
func TestListAccounts_ShowsAnAccountCreatedThroughTheAPI(t *testing.T) {
	f := newControlFixture(t)
	w := f.as(t, http.MethodPost, "/_jay/accounts", `{"name":"via-api"}`)
	requireStatus(t, w, http.StatusCreated)
	var created listedAccount
	if err := jsonv2.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	before := f.dbDigest(t)
	var found bool
	for _, a := range decodeAccounts(t, f.as(t, http.MethodGet, "/_jay/accounts", "")) {
		if a.AccountID == created.AccountID && a.Name == "via-api" {
			found = true
		}
	}
	if !found {
		t.Fatalf("account %s created through the API is not in the listing", created.AccountID)
	}
	f.requireUnchanged(t, before, "listing accounts")
}

func TestListAccounts_ADatabaseFailureIsNotAnEmptyList(t *testing.T) {
	f := newControlFixture(t)
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	w := f.as(t, http.MethodGet, "/_jay/accounts", "")
	requireStatus(t, w, http.StatusInternalServerError)
	if msg := errorMessage(t, w); msg != "internal error" {
		t.Fatalf("error = %q", msg)
	}
}
