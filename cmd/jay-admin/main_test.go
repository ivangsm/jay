package main

// Two halves.
//
// Against a fake admin API that records what reached it: each subcommand has
// to send exactly the request it documents, never send one it refused to
// build, and never print a success line for a call the server refused.
//
// Against the real admin handler (the contract tests at the bottom): what the
// CLI sends has to be what the server accepts. A fake cannot catch drift
// between the two — it answers whatever it is told to — and drift is what two
// of these subcommands have.

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/ivangsm/jay/admin"
	"github.com/ivangsm/jay/api"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
	"golang.org/x/crypto/bcrypt"
)

const cliToken = "cli-admin-token-for-the-tests"

type recordedRequest struct {
	method, path, rawQuery, authorization, contentType string
	body                                               []byte
}

// fakeAdmin records every request and answers each one with status and reply.
type fakeAdmin struct {
	mu     sync.Mutex
	reqs   []recordedRequest
	status int
	reply  string
	url    string
}

func newFakeAdmin(t *testing.T, status int, reply string) *fakeAdmin {
	t.Helper()
	f := &fakeAdmin{status: status, reply: reply}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, recordedRequest{
			method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery,
			authorization: r.Header.Get("Authorization"), contentType: r.Header.Get("Content-Type"),
			body: body,
		})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, f.reply)
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

func (f *fakeAdmin) requests() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedRequest(nil), f.reqs...)
}

// runCLI runs jay-admin with exactly the environment given: nothing leaks in
// from the test process.
func runCLI(t *testing.T, env map[string]string, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, func(k string) string { return env[k] }, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

// against runs one subcommand against url with the test admin token.
func against(url string, args ...string) []string {
	return append([]string{"-addr", url, "-token", cliToken}, args...)
}

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

// A policy with its own spacing and key order, so a re-encoding would show.
const policyDocument = "{\n  \"statements\": [ {\"subjects\":[\"*\"], \"effect\":\"deny\", \"actions\":[\"object:delete\"]} ]\n}\n"

type requestCase struct {
	name     string
	args     []string
	stdin    string
	method   string
	path     string
	jsonBody map[string]any // decoded body; nil when no JSON body is expected
	rawBody  string         // exact bytes, for the policy document
}

func requestCases(t *testing.T) []requestCase {
	policyFile := writePolicyFile(t, policyDocument)
	return []requestCase{
		{name: "create-account", args: []string{"create-account", "-name", "acme"},
			method: http.MethodPost, path: "/_jay/accounts", jsonBody: map[string]any{"name": "acme"}},
		{name: "create-token", args: []string{"create-token", "-account", "acc-1", "-name", "deploy", "-actions", "object:get, object:put"},
			method: http.MethodPost, path: "/_jay/tokens", jsonBody: map[string]any{
				"account_id": "acc-1", "name": "deploy", "allowed_actions": []any{"object:get", "object:put"},
			}},
		{name: "create-token every flag", args: []string{"create-token", "-account", "acc-1", "-actions", "*",
			"-bucket-scope", "photos,thumbs", "-prefix-scope", "public/", "-expires-at", "2030-01-02T15:04:05Z"},
			method: http.MethodPost, path: "/_jay/tokens", jsonBody: map[string]any{
				"account_id": "acc-1", "name": "", "allowed_actions": []any{"*"},
				"bucket_scope": []any{"photos", "thumbs"}, "prefix_scope": []any{"public/"},
				"expires_at": "2030-01-02T15:04:05Z",
			}},
		{name: "list-tokens", args: []string{"list-tokens"}, method: http.MethodGet, path: "/_jay/tokens"},
		{name: "revoke-token", args: []string{"revoke-token", "-id", "tok-1"}, method: http.MethodDelete, path: "/_jay/tokens/tok-1"},
		{name: "metrics", args: []string{"metrics"}, method: http.MethodGet, path: "/_jay/metrics"},
		// expires_seconds is a JSON number: the server's strict decoder refuses
		// a string there. The optional fields are only sent when given.
		{name: "presign defaults", args: []string{"presign", "-bucket", "b", "-key", "k", "-token-id", "tok-1"},
			method: http.MethodPost, path: "/_jay/presign", jsonBody: map[string]any{
				"token_id": "tok-1", "method": "GET", "bucket": "b", "key": "k", "expires_seconds": float64(3600),
			}},
		{name: "presign every flag", args: []string{"presign", "-bucket", "b", "-key", "k", "-token-id", "tok-1",
			"-method", "PUT", "-expires", "60", "-style", "aws", "-host", "s3.example.com", "-region", "eu-west-1"},
			method: http.MethodPost, path: "/_jay/presign", jsonBody: map[string]any{
				"token_id": "tok-1", "method": "PUT", "bucket": "b", "key": "k", "expires_seconds": float64(60),
				"style": "aws", "host": "s3.example.com", "region": "eu-west-1",
			}},
		{name: "quarantine-list", args: []string{"quarantine-list"}, method: http.MethodGet, path: "/_jay/quarantine"},
		{name: "quarantine-revalidate", args: []string{"quarantine-revalidate", "-bucket-id", "bid", "-key", "k"},
			method: http.MethodPost, path: "/_jay/quarantine/revalidate", jsonBody: map[string]any{"bucket_id": "bid", "key": "k"}},
		{name: "quarantine-purge", args: []string{"quarantine-purge"},
			method: http.MethodDelete, path: "/_jay/quarantine", jsonBody: map[string]any{"mode": "all"}},
		{name: "quarantine-purge one object", args: []string{"quarantine-purge", "-bucket-id", "bid", "-key", "k"},
			method: http.MethodDelete, path: "/_jay/quarantine", jsonBody: map[string]any{"bucket_id": "bid", "key": "k"}},
		{name: "get-bucket", args: []string{"get-bucket", "-bucket", "photos"}, method: http.MethodGet, path: "/_jay/buckets/photos"},
		{name: "set-bucket-policy from a file", args: []string{"set-bucket-policy", "-bucket", "photos", "-file", policyFile},
			method: http.MethodPut, path: "/_jay/buckets/photos/policy", rawBody: policyDocument},
		{name: "set-bucket-policy from stdin", args: []string{"set-bucket-policy", "-bucket", "photos", "-file", "-"},
			stdin: policyDocument, method: http.MethodPut, path: "/_jay/buckets/photos/policy", rawBody: policyDocument},
		{name: "delete-bucket-policy", args: []string{"delete-bucket-policy", "-bucket", "photos"},
			method: http.MethodDelete, path: "/_jay/buckets/photos/policy"},
		{name: "set-bucket-visibility", args: []string{"set-bucket-visibility", "-bucket", "photos", "-visibility", "public-read"},
			method: http.MethodPut, path: "/_jay/buckets/photos/visibility", jsonBody: map[string]any{"visibility": "public-read"}},
	}
}

func TestRun_EachCommandSendsTheRequestItDocuments(t *testing.T) {
	for _, c := range requestCases(t) {
		t.Run(c.name, func(t *testing.T) {
			fake := newFakeAdmin(t, http.StatusOK, `{"purged":0,"failed":[]}`)
			code, _, stderr := runCLI(t, nil, c.stdin, against(fake.url, c.args...)...)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, stderr)
			}

			reqs := fake.requests()
			if len(reqs) != 1 {
				t.Fatalf("%d requests reached the server, want 1", len(reqs))
			}
			got := reqs[0]
			if got.method != c.method || got.path != c.path || got.rawQuery != "" {
				t.Fatalf("request = %s %s?%s, want %s %s", got.method, got.path, got.rawQuery, c.method, c.path)
			}
			if got.authorization != "Bearer "+cliToken {
				t.Fatalf("Authorization = %q", got.authorization)
			}

			switch {
			case c.rawBody != "":
				if string(got.body) != c.rawBody {
					t.Fatalf("the policy was not sent byte for byte:\n got %q\nwant %q", got.body, c.rawBody)
				}
				if got.contentType != "application/json" {
					t.Fatalf("Content-Type = %q", got.contentType)
				}
			case c.jsonBody != nil:
				var body map[string]any
				if err := jsonv2.Unmarshal(got.body, &body); err != nil {
					t.Fatalf("body is not a JSON object: %q: %v", got.body, err)
				}
				if !reflect.DeepEqual(body, c.jsonBody) {
					t.Fatalf("body = %v, want %v", body, c.jsonBody)
				}
				if got.contentType != "application/json" {
					t.Fatalf("Content-Type = %q", got.contentType)
				}
			default:
				if len(got.body) != 0 || got.contentType != "" {
					t.Fatalf("a bodiless command sent %q (Content-Type %q)", got.body, got.contentType)
				}
			}
		})
	}
}

func TestRun_PrintsWhatTheServerAnswered(t *testing.T) {
	// Pretty-printed, in the server's key order.
	fake := newFakeAdmin(t, http.StatusCreated, `{"b":1,"a":"x"}`)
	code, stdout, _ := runCLI(t, nil, "", against(fake.url, "create-account", "-name", "acme")...)
	if want := "{\n  \"b\": 1,\n  \"a\": \"x\"\n}\n"; code != 0 || stdout != want {
		t.Fatalf("exit %d, stdout %q, want %q", code, stdout, want)
	}

	// Something that is not JSON is printed as it came.
	fake = newFakeAdmin(t, http.StatusOK, "not json")
	if code, stdout, _ := runCLI(t, nil, "", against(fake.url, "metrics")...); code != 0 || stdout != "not json\n" {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}

	// String escapes stay as the server wrote them: this is a pretty-print,
	// not a re-encode (prettyJSON's PreserveRawStrings). The backslash is
	// built at run time so no tool rewriting this file can fold the escape
	// into the character it stands for.
	bs := string(rune(0x5c))
	escaped := `{"a":"caf` + bs + `u00e9 ` + bs + `u003c","n":1.50}`
	fake = newFakeAdmin(t, http.StatusOK, escaped)
	want := "{\n  \"a\": \"caf" + bs + "u00e9 " + bs + "u003c\",\n  \"n\": 1.50\n}\n"
	if code, stdout, _ := runCLI(t, nil, "", against(fake.url, "metrics")...); code != 0 || stdout != want {
		t.Fatalf("escapes were not preserved: exit %d, stdout %q, want %q", code, stdout, want)
	}

	// The commands whose answer is a fixed line.
	fake = newFakeAdmin(t, http.StatusNoContent, "")
	for args, want := range map[string]string{
		"revoke-token -id t":                      "Token revoked.\n",
		"quarantine-purge -bucket-id b -key some": "Purged some from bucket b.\n",
		"delete-bucket-policy -bucket b":          "Bucket policy removed. The bucket is now reachable only by its owner account and by tokens scoped to it.\n",
	} {
		if code, stdout, stderr := runCLI(t, nil, "", against(fake.url, strings.Fields(args)...)...); code != 0 || stdout != want {
			t.Fatalf("%s: exit %d, stdout %q, stderr %q", args, code, stdout, stderr)
		}
	}

	// A whole-quarantine purge reports the count the server gave, not a
	// blanket "purged".
	fake = newFakeAdmin(t, http.StatusOK, `{"purged":3,"failed":[]}`)
	if code, stdout, stderr := runCLI(t, nil, "", against(fake.url, "quarantine-purge")...); code != 0 || stdout != "Purged 3 quarantined object(s).\n" {
		t.Fatalf("quarantine-purge: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	// An answer without the count is not taken as a success.
	fake = newFakeAdmin(t, http.StatusOK, `{}`)
	if code, stdout, _ := runCLI(t, nil, "", against(fake.url, "quarantine-purge")...); code != 1 || stdout != "" {
		t.Fatalf("quarantine-purge with no count in the answer: exit %d, stdout %q", code, stdout)
	}
}

// No command may print a success line — or anything on stdout — for a call
// the server refused. "Token revoked." after a 500 is exactly the confirmation
// with nothing behind it this repo does not ship.
func TestRun_ARefusedCallIsAFailureAndClaimsNothing(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError} {
		for _, c := range requestCases(t) {
			fake := newFakeAdmin(t, status, `{"error":"the server's reason"}`)
			code, stdout, stderr := runCLI(t, nil, c.stdin, against(fake.url, c.args...)...)
			if code != 1 {
				t.Fatalf("%s answered %d: exit %d, want 1", c.name, status, code)
			}
			if stdout != "" {
				t.Fatalf("%s answered %d but stdout says %q", c.name, status, stdout)
			}
			if !strings.Contains(stderr, "server error ("+strconv.Itoa(status)+")") {
				t.Fatalf("%s answered %d: stderr %q does not carry the status", c.name, status, stderr)
			}
			if !strings.Contains(stderr, "the server's reason") {
				t.Fatalf("%s answered %d: stderr %q drops the server's reason", c.name, status, stderr)
			}
		}
	}
}

func TestRun_AnUnreachableServerIsAFailure(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // the address now refuses connections

	code, stdout, stderr := runCLI(t, nil, "", against(url, "list-tokens")...)
	if code != 1 || stdout != "" || !strings.HasPrefix(stderr, "Error: ") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestRun_AddressAndTokenComeFromFlagsOrTheEnvironment(t *testing.T) {
	fake := newFakeAdmin(t, http.StatusOK, `{}`)

	// Environment only.
	env := map[string]string{"JAY_ADMIN_ADDR": fake.url, "JAY_ADMIN_TOKEN": "from-the-env"}
	if code, _, stderr := runCLI(t, env, "", "metrics"); code != 0 {
		t.Fatalf("env only: exit %d: %s", code, stderr)
	}
	// Flags win over the environment.
	env = map[string]string{"JAY_ADMIN_ADDR": "http://127.0.0.1:1", "JAY_ADMIN_TOKEN": "from-the-env"}
	if code, _, stderr := runCLI(t, env, "", "-token", "from-the-flag", "-addr", fake.url, "metrics"); code != 0 {
		t.Fatalf("flags over env: exit %d: %s", code, stderr)
	}
	// An address without a scheme gets http://.
	if code, _, stderr := runCLI(t, nil, "", "-addr", strings.TrimPrefix(fake.url, "http://"), "-token", "bare", "metrics"); code != 0 {
		t.Fatalf("schemeless address: exit %d: %s", code, stderr)
	}

	var auths []string
	for _, r := range fake.requests() {
		auths = append(auths, r.authorization)
	}
	if want := []string{"Bearer from-the-env", "Bearer from-the-flag", "Bearer bare"}; !reflect.DeepEqual(auths, want) {
		t.Fatalf("Authorization headers = %v, want %v", auths, want)
	}
}

// The help lists the actions -actions takes. It is prose, so it is checked
// against the real set: an action added to meta and not to the help is one
// nobody finds.
func TestUsage_ListsEveryAction(t *testing.T) {
	_, _, stderr := runCLI(t, nil, "")
	for _, action := range meta.AllActions {
		if !strings.Contains(stderr, action) {
			t.Errorf("the usage does not mention %s", action)
		}
	}
}

// Every refusal the CLI makes on its own happens before the network: nothing
// reaches the server, and the exit code says it failed.
func TestRun_RefusesBeforeSendingAnything(t *testing.T) {
	fake := newFakeAdmin(t, http.StatusOK, `{}`)
	emptyPolicy := writePolicyFile(t, " \n\t\n")
	missingPolicy := filepath.Join(t.TempDir(), "no-such-policy.json")

	for _, c := range []struct {
		name    string
		env     map[string]string
		stdin   string
		args    []string
		wantErr string
	}{
		{name: "no command", args: []string{"-addr", fake.url, "-token", cliToken}, wantErr: "Usage: jay-admin"},
		{name: "no token", env: map[string]string{"JAY_ADMIN_ADDR": fake.url}, args: []string{"metrics"}, wantErr: "admin token required"},
		{name: "unknown command", args: against(fake.url, "delete-everything"), wantErr: "Unknown command: delete-everything"},
		{name: "create-account without -name", args: against(fake.url, "create-account"), wantErr: "usage: create-account"},
		{name: "create-token without -account", args: against(fake.url, "create-token", "-name", "x", "-actions", "*"), wantErr: "usage: create-token"},
		{name: "create-token without -actions", args: against(fake.url, "create-token", "-account", "a"), wantErr: "usage: create-token"},
		{name: "create-token with only commas in -actions", args: against(fake.url, "create-token", "-account", "a", "-actions", " , ,"), wantErr: "usage: create-token"},
		{name: "create-token with an unknown action", args: against(fake.url, "create-token", "-account", "a", "-actions", "object:get,object:read"), wantErr: `unknown action "object:read"`},
		{name: "quarantine-purge with -key only", args: against(fake.url, "quarantine-purge", "-key", "k"), wantErr: "usage: quarantine-purge"},
		{name: "quarantine-purge with -bucket-id only", args: against(fake.url, "quarantine-purge", "-bucket-id", "b"), wantErr: "usage: quarantine-purge"},
		{name: "revoke-token without -id", args: against(fake.url, "revoke-token"), wantErr: "usage: revoke-token"},
		{name: "presign without -bucket", args: against(fake.url, "presign", "-token-id", "t"), wantErr: "usage: presign"},
		{name: "presign without -token-id", args: against(fake.url, "presign", "-bucket", "b"), wantErr: "usage: presign"},
		{name: "presign with a word for -expires", args: against(fake.url, "presign", "-bucket", "b", "-token-id", "t", "-expires", "soon"), wantErr: "-expires must be a positive number"},
		{name: "presign with zero -expires", args: against(fake.url, "presign", "-bucket", "b", "-token-id", "t", "-expires", "0"), wantErr: "-expires must be a positive number"},
		{name: "presign with negative -expires", args: against(fake.url, "presign", "-bucket", "b", "-token-id", "t", "-expires", "-5"), wantErr: "-expires must be a positive number"},
		{name: "quarantine-revalidate without -key", args: against(fake.url, "quarantine-revalidate", "-bucket-id", "b"), wantErr: "usage: quarantine-revalidate"},
		{name: "quarantine-revalidate without -bucket-id", args: against(fake.url, "quarantine-revalidate", "-key", "k"), wantErr: "usage: quarantine-revalidate"},
		{name: "get-bucket without -bucket", args: against(fake.url, "get-bucket"), wantErr: "usage: get-bucket"},
		{name: "set-bucket-policy without -file", args: against(fake.url, "set-bucket-policy", "-bucket", "b"), wantErr: "usage: set-bucket-policy"},
		{name: "set-bucket-policy with an empty file", args: against(fake.url, "set-bucket-policy", "-bucket", "b", "-file", emptyPolicy), wantErr: "the policy document is empty"},
		{name: "set-bucket-policy with an empty stdin", args: against(fake.url, "set-bucket-policy", "-bucket", "b", "-file", "-"), wantErr: "the policy document is empty"},
		{name: "set-bucket-policy with a missing file", args: against(fake.url, "set-bucket-policy", "-bucket", "b", "-file", missingPolicy), wantErr: "read policy document"},
		{name: "delete-bucket-policy without -bucket", args: against(fake.url, "delete-bucket-policy"), wantErr: "usage: delete-bucket-policy"},
		{name: "set-bucket-visibility without -visibility", args: against(fake.url, "set-bucket-visibility", "-bucket", "b"), wantErr: "usage: set-bucket-visibility"},
	} {
		code, stdout, stderr := runCLI(t, c.env, c.stdin, c.args...)
		if code != 1 || stdout != "" || !strings.Contains(stderr, c.wantErr) {
			t.Fatalf("%s: exit %d, stdout %q, stderr %q; want 1 and %q", c.name, code, stdout, stderr, c.wantErr)
		}
	}
	if n := len(fake.requests()); n != 0 {
		t.Fatalf("%d requests reached the server from commands that refused to run", n)
	}
}

// ---------------------------------------------------------------------------
// Contract: the CLI against the real admin handler
// ---------------------------------------------------------------------------

const contractSigningSecret = "contract-signing-secret-of-32-bytes!"

type realAdmin struct {
	url       string
	db        *meta.DB
	au        *auth.Auth
	s3        http.Handler // the S3 port, over the same database and store
	accountID string
	tokenID   string
	bucket    *meta.Bucket
}

// newRealAdmin serves the admin handler the way cmd/jay mounts it, over a
// bbolt with one account, one token, one bucket and one quarantined record.
func newRealAdmin(t *testing.T) *realAdmin {
	t.Helper()
	dir := t.TempDir()
	db, err := meta.Open(filepath.Join(dir, "meta", "jay.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetSigningSecret(contractSigningSecret)
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	acc := &meta.Account{AccountID: uuid.New().String(), Name: "contract", Status: "active"}
	if err := db.CreateAccount(acc); err != nil {
		t.Fatalf("create account: %v", err)
	}
	// Minimum bcrypt cost: nothing here authenticates with this secret.
	hash, err := bcrypt.GenerateFromPassword([]byte("contract-token-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	tok := &meta.Token{TokenID: "contract-token", AccountID: acc.AccountID, SecretHash: string(hash),
		SecretKey: "contract-token-secret", AllowedActions: []string{"*"}}
	if err := db.CreateToken(tok); err != nil {
		t.Fatalf("create token: %v", err)
	}
	bucket := &meta.Bucket{ID: uuid.New().String(), Name: "contract-bucket", OwnerAccountID: acc.AccountID,
		Visibility: meta.VisibilityPrivate, Status: "active"}
	if err := db.CreateBucket(bucket); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	if _, err := db.PutObjectMeta(&meta.Object{BucketID: bucket.ID, Key: "sick.txt", ObjectID: uuid.New().String(),
		LocationRef: "buckets/" + bucket.ID + "/objects/missing"}); err != nil {
		t.Fatalf("put object: %v", err)
	}
	if err := db.QuarantineObject(bucket.ID, "sick.txt"); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	au := auth.New(db)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	metrics := maintenance.NewMetrics()
	h := admin.NewHandler(admin.AdminConfig{
		DB: db, Store: st, Auth: au, AdminToken: cliToken, Log: log, Metrics: metrics,
		SigningSecret: contractSigningSecret, ListenAddr: "jay.test:9000",
	})
	t.Cleanup(func() { _ = h.Close() })
	mux := http.NewServeMux()
	mux.Handle("/_jay/", h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &realAdmin{
		url: srv.URL, db: db, au: au, s3: api.NewHandler(db, st, au, log, metrics, contractSigningSecret, nil),
		accountID: acc.AccountID, tokenID: tok.TokenID, bucket: bucket,
	}
}

func (r *realAdmin) objectState(t *testing.T, key string) string {
	t.Helper()
	obj, err := r.db.GetObjectMetaAny(r.bucket.ID, key)
	if errors.Is(err, meta.ErrObjectNotFound) {
		return ""
	}
	if err != nil {
		t.Fatalf("get object: %v", err)
	}
	return obj.State
}

func TestContract_CreateAccount(t *testing.T) {
	r := newRealAdmin(t)
	code, stdout, stderr := runCLI(t, nil, "", against(r.url, "create-account", "-name", "acme")...)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var acc meta.Account
	if err := jsonv2.Unmarshal([]byte(stdout), &acc); err != nil {
		t.Fatalf("stdout is not the account: %q: %v", stdout, err)
	}
	if stored, err := r.db.GetAccount(acc.AccountID); err != nil || stored.Name != "acme" {
		t.Fatalf("the printed account is not in the database: %+v, %v", stored, err)
	}
}

// create-token used to send no allowed_actions — it had no flag for them — so
// the server refused every call and the command could never mint a token.
func TestContract_CreateTokenMintsAWorkingToken(t *testing.T) {
	r := newRealAdmin(t)
	expires := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)

	code, stdout, stderr := runCLI(t, nil, "", against(r.url, "create-token", "-account", r.accountID, "-name", "reader",
		"-actions", "object:get,object:list", "-bucket-scope", r.bucket.Name, "-prefix-scope", "public/",
		"-expires-at", expires)...)
	if code != 0 {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	var created struct {
		TokenID   string `json:"token_id"`
		Secret    string `json:"secret"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := jsonv2.Unmarshal([]byte(stdout), &created); err != nil || created.Secret == "" {
		t.Fatalf("stdout is not the new token: %q (%v)", stdout, err)
	}

	tok, err := r.au.AuthenticateCredentials(created.TokenID, created.Secret)
	if err != nil {
		t.Fatalf("the printed secret does not authenticate: %v", err)
	}
	if !reflect.DeepEqual(tok.AllowedActions, []string{"object:get", "object:list"}) ||
		!reflect.DeepEqual(tok.BucketScope, []string{r.bucket.Name}) ||
		!reflect.DeepEqual(tok.PrefixScope, []string{"public/"}) ||
		tok.ExpiresAt == nil || tok.ExpiresAt.Format(time.RFC3339) != expires || created.ExpiresAt != expires {
		t.Fatalf("the stored token is not the one asked for: %+v (printed expiry %q)", tok, created.ExpiresAt)
	}
}

// installFlow is the "first token" section of install.md: the jay-admin
// commands it shows, in order, as the shell would split them.
func installFlow(t *testing.T) [][]string {
	t.Helper()
	cmds := documentedInvocations(t, "install.md")
	if len(cmds) != 2 || cmds[0][0] != "create-account" || cmds[1][0] != "create-token" {
		t.Fatalf("install.md no longer shows create-account then create-token (found %v); update this test "+
			"with the page", cmds)
	}
	return cmds
}

// The page that tells a new operator how to get the first token has to work,
// word for word, against the real handler — that page is where create-token
// was documented while it could not succeed. And the token has to do what the
// page says it is for: talk S3 on the data port.
func TestContract_TheInstallPageFlowWorks(t *testing.T) {
	r := newRealAdmin(t)
	cmds := installFlow(t)
	env := map[string]string{"JAY_ADMIN_ADDR": r.url, "JAY_ADMIN_TOKEN": cliToken}

	code, stdout, stderr := runCLI(t, env, "", cmds[0]...)
	if code != 0 {
		t.Fatalf("jay-admin %s: exit %d: %s", strings.Join(cmds[0], " "), code, stderr)
	}
	var account struct {
		AccountID string `json:"account_id"`
	}
	if err := jsonv2.Unmarshal([]byte(stdout), &account); err != nil || account.AccountID == "" {
		t.Fatalf("create-account printed %q (%v)", stdout, err)
	}

	tokenArgs := slices.Clone(cmds[1])
	for i, a := range tokenArgs {
		if a == "ACCOUNT_ID" {
			tokenArgs[i] = account.AccountID
		}
	}
	code, stdout, stderr = runCLI(t, env, "", tokenArgs...)
	if code != 0 {
		t.Fatalf("jay-admin %s: exit %d: %s", strings.Join(tokenArgs, " "), code, stderr)
	}
	var token struct {
		TokenID string `json:"token_id"`
		Secret  string `json:"secret"`
	}
	if err := jsonv2.Unmarshal([]byte(stdout), &token); err != nil || token.Secret == "" {
		t.Fatalf("create-token printed %q (%v)", stdout, err)
	}

	stored, err := r.au.AuthenticateCredentials(token.TokenID, token.Secret)
	if err != nil {
		t.Fatalf("the token from the install page does not authenticate: %v", err)
	}
	if want := splitList(parseFlag(tokenArgs, "-actions")); !reflect.DeepEqual(stored.AllowedActions, want) {
		t.Fatalf("stored actions %v, the page asked for %v", stored.AllowedActions, want)
	}

	// Create a bucket, write an object and read it back on the S3 port.
	bearer := "Bearer " + token.TokenID + ":" + token.Secret
	for _, step := range []struct {
		method, path, body string
	}{
		{http.MethodPut, "/first-bucket", ""},
		{http.MethodPut, "/first-bucket/hello.txt", "hola"},
		{http.MethodGet, "/first-bucket/hello.txt", ""},
	} {
		req := httptest.NewRequest(step.method, "http://jay.test"+step.path, strings.NewReader(step.body))
		req.Header.Set("Authorization", bearer)
		w := httptest.NewRecorder()
		r.s3.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s with the install-page token: %d %s", step.method, step.path, w.Code, w.Body.String())
		}
		if step.method == http.MethodGet && w.Body.String() != "hola" {
			t.Fatalf("read back %q", w.Body.String())
		}
	}
}

// documentedInvocations returns the jay-admin command lines in the fenced
// bash blocks of a docs page, continuation lines joined and split into
// arguments without the leading "jay-admin". Single quotes around an argument
// are removed, as the shell would.
func documentedInvocations(t *testing.T, page string) [][]string {
	t.Helper()
	path := filepath.Join("..", "..", "site", "src", "content", "docs", page)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var (
		out           [][]string
		inBlock, bash bool
		line          string
	)
	for raw := range strings.SplitSeq(string(data), "\n") {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "```") {
			inBlock, bash = !inBlock, !inBlock && trimmed == "```bash"
			continue
		}
		if !bash {
			continue
		}
		line += trimmed
		if strings.HasSuffix(line, "\\") {
			line = strings.TrimSuffix(line, "\\") + " "
			continue
		}
		fields := strings.Fields(line)
		line = ""
		if len(fields) < 2 || fields[0] != "jay-admin" {
			continue
		}
		args := fields[1:]
		for i, a := range args {
			args[i] = strings.Trim(a, "'")
		}
		out = append(out, args)
	}

	// Cross-check the parser against a plain count of the lines that start a
	// jay-admin command, so a parser that skips some cannot pass for one that
	// read the page.
	starts := 0
	for raw := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(raw), "jay-admin ") {
			starts++
		}
	}
	if starts != len(out) {
		t.Fatalf("%s has %d lines starting a jay-admin command, the parser found %d", page, starts, len(out))
	}
	return out
}

// Every jay-admin invocation the docs show is one the CLI accepts: it builds a
// request and sends it, instead of stopping at a usage error.
func TestDocs_EveryDocumentedInvocationRuns(t *testing.T) {
	policy := writePolicyFile(t, policyDocument)
	placeholders := map[string]string{
		"ACCOUNT_ID": "acc", "TOKEN_ID": "tok", "BUCKET_ID": "bid", "policy.json": policy,
	}

	for _, page := range []string{"reference/admin-api.md", "install.md"} {
		cmds := documentedInvocations(t, page)
		if len(cmds) < 2 {
			t.Fatalf("%s: found %d jay-admin invocations; the parser no longer sees the page", page, len(cmds))
		}
		for _, cmd := range cmds {
			args := slices.Clone(cmd)
			for i, a := range args {
				if v, ok := placeholders[a]; ok {
					args[i] = v
				}
			}
			fake := newFakeAdmin(t, http.StatusOK, `{"purged":0,"failed":[]}`)
			code, _, stderr := runCLI(t, nil, "", against(fake.url, args...)...)
			if code != 0 || len(fake.requests()) != 1 {
				t.Errorf("%s documents `jay-admin %s`, which exits %d after %d requests: %s",
					page, strings.Join(cmd, " "), code, len(fake.requests()), stderr)
			}
		}
	}
}

func TestContract_ListAndRevokeTokens(t *testing.T) {
	r := newRealAdmin(t)

	code, stdout, stderr := runCLI(t, nil, "", against(r.url, "list-tokens")...)
	if code != 0 || !strings.Contains(stdout, r.tokenID) || strings.Contains(stdout, "contract-token-secret") {
		t.Fatalf("list-tokens: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	code, stdout, stderr = runCLI(t, nil, "", against(r.url, "revoke-token", "-id", r.tokenID)...)
	if code != 0 || stdout != "Token revoked.\n" {
		t.Fatalf("revoke-token: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if stored, err := r.db.GetToken(r.tokenID); err != nil || stored.Status != "revoked" {
		t.Fatalf("the token is not revoked in the database: %+v, %v", stored, err)
	}

	code, stdout, stderr = runCLI(t, nil, "", against(r.url, "revoke-token", "-id", "no-such-token")...)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "server error (404)") || !strings.Contains(stderr, "token not found") {
		t.Fatalf("revoking an unknown token: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestContract_MetricsAndPresign(t *testing.T) {
	r := newRealAdmin(t)

	code, stdout, stderr := runCLI(t, nil, "", against(r.url, "metrics")...)
	var snap maintenance.MetricsSnapshot
	if code != 0 || jsonv2.Unmarshal([]byte(stdout), &snap) != nil {
		t.Fatalf("metrics: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	code, stdout, stderr = runCLI(t, nil, "", against(r.url, "presign", "-bucket", r.bucket.Name, "-key", "k", "-token-id", r.tokenID)...)
	var resp struct {
		URL string `json:"url"`
	}
	if code != 0 || jsonv2.Unmarshal([]byte(stdout), &resp) != nil || !strings.Contains(resp.URL, "X-Jay-Signature=") {
		t.Fatalf("presign: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestContract_Quarantine(t *testing.T) {
	r := newRealAdmin(t)

	code, stdout, stderr := runCLI(t, nil, "", against(r.url, "quarantine-list")...)
	if code != 0 || !strings.Contains(stdout, `"sick.txt"`) {
		t.Fatalf("quarantine-list: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	// The file is missing, so the record cannot be restored — and must not be.
	code, stdout, stderr = runCLI(t, nil, "", against(r.url, "quarantine-revalidate", "-bucket-id", r.bucket.ID, "-key", "sick.txt")...)
	if code != 0 || !strings.Contains(stdout, `"restored": false`) {
		t.Fatalf("quarantine-revalidate: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if got := r.objectState(t, "sick.txt"); got != "quarantined" {
		t.Fatalf("state after a failed revalidation = %q", got)
	}
}

// quarantine-purge used to send no body, and the server — which requires
// {"mode":"all"} — refused every call.
func TestContract_QuarantinePurge(t *testing.T) {
	r := newRealAdmin(t)
	for _, key := range []string{"sick-2.txt", "sick-3.txt"} {
		if _, err := r.db.PutObjectMeta(&meta.Object{BucketID: r.bucket.ID, Key: key, ObjectID: uuid.New().String(),
			LocationRef: "buckets/" + r.bucket.ID + "/objects/" + key}); err != nil {
			t.Fatalf("put %s: %v", key, err)
		}
		if err := r.db.QuarantineObject(r.bucket.ID, key); err != nil {
			t.Fatalf("quarantine %s: %v", key, err)
		}
	}

	code, stdout, stderr := runCLI(t, nil, "", against(r.url, "quarantine-purge", "-bucket-id", r.bucket.ID, "-key", "sick.txt")...)
	if code != 0 || stdout != "Purged sick.txt from bucket "+r.bucket.ID+".\n" {
		t.Fatalf("single purge: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if got := r.objectState(t, "sick.txt"); got != "" {
		t.Fatalf("the purged record is still there, state %q", got)
	}

	code, stdout, stderr = runCLI(t, nil, "", against(r.url, "quarantine-purge")...)
	if code != 0 || stdout != "Purged 2 quarantined object(s).\n" {
		t.Fatalf("purge all: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	for _, key := range []string{"sick-2.txt", "sick-3.txt"} {
		if got := r.objectState(t, key); got != "" {
			t.Fatalf("%s survived purge-all, state %q", key, got)
		}
	}

	// And the server's reason comes through when it refuses.
	code, stdout, stderr = runCLI(t, nil, "", against(r.url, "quarantine-purge", "-bucket-id", r.bucket.ID, "-key", "sick.txt")...)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "server error (404)") || !strings.Contains(stderr, "object not found") {
		t.Fatalf("purging a purged object: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestContract_BucketPolicyAndVisibility(t *testing.T) {
	r := newRealAdmin(t)
	name := r.bucket.Name
	policyFile := writePolicyFile(t, policyDocument)

	code, stdout, stderr := runCLI(t, nil, "", against(r.url, "set-bucket-policy", "-bucket", name, "-file", policyFile)...)
	if code != 0 || !strings.Contains(stdout, `"statements": 1`) {
		t.Fatalf("set-bucket-policy: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	// Stored compacted, but it is the file's document: same keys, same order.
	want := jsontext.Value(policyDocument)
	if err := want.Compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}
	stored, err := r.db.GetBucket(name)
	if err != nil || string(stored.PolicyJSON) != string(want) {
		t.Fatalf("the stored policy is not the file's document: %q, %v", stored.PolicyJSON, err)
	}

	code, stdout, stderr = runCLI(t, nil, "", against(r.url, "set-bucket-visibility", "-bucket", name, "-visibility", meta.VisibilityPublicRead)...)
	if code != 0 {
		t.Fatalf("set-bucket-visibility: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, stdout, stderr = runCLI(t, nil, "", against(r.url, "get-bucket", "-bucket", name)...)
	if code != 0 || !strings.Contains(stdout, `"visibility": "public-read"`) || !strings.Contains(stdout, `"object:delete"`) {
		t.Fatalf("get-bucket: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	code, _, stderr = runCLI(t, nil, "", against(r.url, "delete-bucket-policy", "-bucket", name)...)
	if code != 0 {
		t.Fatalf("delete-bucket-policy: exit %d: %s", code, stderr)
	}
	if stored, err := r.db.GetBucket(name); err != nil || len(stored.PolicyJSON) != 0 {
		t.Fatalf("the policy survived delete-bucket-policy: %q, %v", stored.PolicyJSON, err)
	}

	// A document the server refuses is an error, and the bucket keeps no policy.
	bad := writePolicyFile(t, `{"statements":[{"effect":"allow","actions":["object:read"],"subjects":["*"]}]}`)
	code, stdout, stderr = runCLI(t, nil, "", against(r.url, "set-bucket-policy", "-bucket", name, "-file", bad)...)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "object:read") {
		t.Fatalf("invalid policy: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if stored, err := r.db.GetBucket(name); err != nil || len(stored.PolicyJSON) != 0 {
		t.Fatalf("a refused policy was stored: %q, %v", stored.PolicyJSON, err)
	}
}
