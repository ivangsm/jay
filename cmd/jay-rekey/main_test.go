package main

// jay-rekey is the documented way back from a signing-secret rotation, and it
// runs once, by hand, usually under pressure. Every test here judges a run by
// what it left in the database — which secret the tokens authenticate under —
// and never by the line it printed alone.

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
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
	oldSecret   = "old-signing-secret-of-at-least-32-bytes"
	newSecret   = "new-signing-secret-of-at-least-32-bytes"
	wrongSecret = "a-signing-secret-nobody-ever-configured"
)

type seededToken struct{ id, secret string }

// seedDataDir creates <dir>/meta/jay.db, as the server lays it out, holding n
// tokens encrypted under signingSecret, and closes it again.
func seedDataDir(t *testing.T, signingSecret string, n int) (dataDir, dbPath string, toks []seededToken) {
	t.Helper()
	dataDir = t.TempDir()
	dbPath = filepath.Join(dataDir, "meta", "jay.db")

	db, err := meta.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	db.SetSigningSecret(signingSecret)

	acc := &meta.Account{AccountID: uuid.New().String(), Name: "rekey", Status: "active"}
	if err := db.CreateAccount(acc); err != nil {
		t.Fatalf("create account: %v", err)
	}
	for i := range n {
		tok := seededToken{id: "tok-" + strconv.Itoa(i), secret: "tok-secret-" + strconv.Itoa(i)}
		// Minimum bcrypt cost: the secret's hash is not what this tests, and
		// the default cost makes every check take seconds under -race.
		hash, err := bcrypt.GenerateFromPassword([]byte(tok.secret), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		if err := db.CreateToken(&meta.Token{
			TokenID: tok.id, AccountID: acc.AccountID, Name: tok.id,
			SecretHash: string(hash), SecretKey: tok.secret, AllowedActions: []string{"*"},
		}); err != nil {
			t.Fatalf("create token: %v", err)
		}
		toks = append(toks, tok)
	}
	return dataDir, dbPath, toks
}

// authenticating opens the database the way the server would with
// JAY_SIGNING_SECRET=signingSecret and returns the tokens that authenticate
// and decrypt to their own secret.
func authenticating(t *testing.T, dbPath, signingSecret string, toks []seededToken) []string {
	t.Helper()
	db, err := meta.Open(dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	db.SetSigningSecret(signingSecret)
	au := auth.New(db)

	var ok []string
	for _, tok := range toks {
		stored, err := db.GetToken(tok.id)
		if err != nil || stored.SecretKey != tok.secret {
			continue
		}
		if _, err := au.AuthenticateCredentials(tok.id, tok.secret); err == nil {
			ok = append(ok, tok.id)
		}
	}
	return ok
}

func requireAllUnder(t *testing.T, dbPath, signingSecret, label string, toks []seededToken) {
	t.Helper()
	if ok := authenticating(t, dbPath, signingSecret, toks); len(ok) != len(toks) {
		t.Fatalf("under the %s secret only %v of %d tokens authenticate", label, ok, len(toks))
	}
}

func requireNoneUnder(t *testing.T, dbPath, signingSecret, label string, toks []seededToken) {
	t.Helper()
	if ok := authenticating(t, dbPath, signingSecret, toks); len(ok) != 0 {
		t.Fatalf("under the %s secret these tokens still authenticate: %v", label, ok)
	}
}

// rekey runs the command with exactly the environment given: nothing leaks in
// from the test process.
func rekey(t *testing.T, env map[string]string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(append([]string{"jay-rekey"}, args...), func(k string) string { return env[k] }, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRun_RotatesEveryTokenFromTheEnvironment(t *testing.T) {
	dataDir, dbPath, toks := seedDataDir(t, oldSecret, 3)

	code, stdout, stderr := rekey(t, map[string]string{
		"JAY_DATA_DIR":           dataDir,
		"JAY_OLD_SIGNING_SECRET": oldSecret,
		"JAY_SIGNING_SECRET":     newSecret,
	})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if stdout != "Rekeyed 3 token(s) successfully.\n" {
		t.Fatalf("stdout = %q", stdout)
	}
	requireAllUnder(t, dbPath, newSecret, "new", toks)
	requireNoneUnder(t, dbPath, oldSecret, "old", toks)
}

func TestRun_FlagsOverrideTheEnvironment(t *testing.T) {
	_, dbPath, toks := seedDataDir(t, oldSecret, 2)
	elsewhere := filepath.Join(t.TempDir(), "not-the-data-dir")

	code, _, stderr := rekey(t, map[string]string{
		"JAY_DATA_DIR":           elsewhere,
		"JAY_OLD_SIGNING_SECRET": wrongSecret,
		"JAY_SIGNING_SECRET":     wrongSecret + "-too",
	}, "-data-dir", elsewhere, "-db", dbPath, "-old-secret", oldSecret, "-new-secret", newSecret)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	requireAllUnder(t, dbPath, newSecret, "new", toks)
	// -db won over -data-dir: nothing was created there.
	if _, err := os.Stat(elsewhere); !os.IsNotExist(err) {
		t.Fatalf("-data-dir was used although -db was given: %v", err)
	}
}

// The refusals that happen before the database is opened must not create
// one, and must leave an existing one exactly as it was.
func TestRun_RefusesWithoutTwoDistinctSecrets(t *testing.T) {
	for _, c := range []struct {
		name, old, new, wantErr string
	}{
		{"no old secret", "", newSecret, "old secret required"},
		{"no new secret", oldSecret, "", "new secret required"},
		{"identical secrets", oldSecret, oldSecret, "identical"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dataDir, dbPath, toks := seedDataDir(t, oldSecret, 2)
			code, stdout, stderr := rekey(t, map[string]string{
				"JAY_DATA_DIR": dataDir, "JAY_OLD_SIGNING_SECRET": c.old, "JAY_SIGNING_SECRET": c.new,
			})
			if code != 1 || !strings.Contains(stderr, c.wantErr) {
				t.Fatalf("exit %d, stderr %q; want 1 and %q", code, stderr, c.wantErr)
			}
			if stdout != "" {
				t.Fatalf("a refused run printed to stdout: %q", stdout)
			}
			requireAllUnder(t, dbPath, oldSecret, "old", toks)

			fresh := filepath.Join(t.TempDir(), "fresh")
			if code, _, _ := rekey(t, map[string]string{
				"JAY_DATA_DIR": fresh, "JAY_OLD_SIGNING_SECRET": c.old, "JAY_SIGNING_SECRET": c.new,
			}); code != 1 {
				t.Fatalf("exit %d against an empty data dir", code)
			}
			if _, err := os.Stat(fresh); !os.IsNotExist(err) {
				t.Fatalf("a refused run created %s: %v", fresh, err)
			}
		})
	}
}

// serverMinSecretLen reads minSecretLen out of the server's main.go: the
// length below which jay refuses to start with a JAY_SIGNING_SECRET. Rekeying
// to anything shorter leaves a database the server cannot be started against.
func serverMinSecretLen(t *testing.T) int {
	t.Helper()
	const source = "../jay/main.go"
	file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", source, err)
	}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if name.Name != "minSecretLen" || i >= len(vs.Values) {
					continue
				}
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.INT {
					n, err := strconv.Atoi(lit.Value)
					if err == nil {
						return n
					}
				}
			}
		}
	}
	t.Fatalf("no integer constant minSecretLen in %s; the test can no longer see the server's floor", source)
	return 0
}

func TestRun_RefusesANewSecretTheServerWouldRefuse(t *testing.T) {
	floor := serverMinSecretLen(t)
	dataDir, dbPath, toks := seedDataDir(t, oldSecret, 2)
	env := func(newSecret string) map[string]string {
		return map[string]string{
			"JAY_DATA_DIR": dataDir, "JAY_OLD_SIGNING_SECRET": oldSecret, "JAY_SIGNING_SECRET": newSecret,
		}
	}

	short := strings.Repeat("s", floor-1)
	code, stdout, stderr := rekey(t, env(short))
	if code != 1 {
		t.Fatalf("rekeying to a %d-byte secret exited %d (%q) — jay would refuse to start with it", len(short), code, stdout)
	}
	if !strings.Contains(stderr, strconv.Itoa(floor)) {
		t.Fatalf("the refusal does not say what length is needed: %q", stderr)
	}
	requireAllUnder(t, dbPath, oldSecret, "old", toks)

	exact := strings.Repeat("s", floor)
	if code, _, stderr := rekey(t, env(exact)); code != 0 {
		t.Fatalf("rekeying to a %d-byte secret exited %d: %s", floor, code, stderr)
	}
	requireAllUnder(t, dbPath, exact, "new", toks)
}

func TestRun_AWrongOldSecretLeavesEveryTokenAsItWas(t *testing.T) {
	dataDir, dbPath, toks := seedDataDir(t, oldSecret, 3)

	code, stdout, stderr := rekey(t, map[string]string{
		"JAY_DATA_DIR": dataDir, "JAY_OLD_SIGNING_SECRET": wrongSecret, "JAY_SIGNING_SECRET": newSecret,
	})
	if code != 1 {
		t.Fatalf("exit %d with the wrong old secret; stdout %q", code, stdout)
	}
	if !strings.Contains(stderr, "nothing was rekeyed") {
		t.Fatalf("stderr does not say the database was left alone: %q", stderr)
	}
	requireAllUnder(t, dbPath, oldSecret, "real old", toks)
	requireNoneUnder(t, dbPath, newSecret, "new", toks)
}

// bbolt takes an exclusive lock, so a running server keeps jay-rekey out.
// It has to fail — within meta.Open's one-second timeout, not hang — and
// leave the tokens alone.
func TestRun_RefusesWhileTheServerHoldsTheDatabase(t *testing.T) {
	dataDir, dbPath, toks := seedDataDir(t, oldSecret, 2)

	server, err := meta.Open(dbPath)
	if err != nil {
		t.Fatalf("open db as the server: %v", err)
	}
	code, stdout, stderr := rekey(t, map[string]string{
		"JAY_DATA_DIR": dataDir, "JAY_OLD_SIGNING_SECRET": oldSecret, "JAY_SIGNING_SECRET": newSecret,
	})
	if err := server.Close(); err != nil {
		t.Fatalf("close the server's handle: %v", err)
	}

	if code != 1 || stdout != "" {
		t.Fatalf("exit %d, stdout %q while the server held the database", code, stdout)
	}
	if !strings.Contains(stderr, "open database") || !strings.Contains(stderr, "timeout") {
		t.Fatalf("stderr does not say the database is held: %q", stderr)
	}
	requireAllUnder(t, dbPath, oldSecret, "old", toks)
}

// Running it again with the same arguments — because the first run's output
// scrolled away, or a deploy script runs it every time — must be harmless.
func TestRun_ASecondRunIsHarmless(t *testing.T) {
	dataDir, dbPath, toks := seedDataDir(t, oldSecret, 2)
	env := map[string]string{
		"JAY_DATA_DIR": dataDir, "JAY_OLD_SIGNING_SECRET": oldSecret, "JAY_SIGNING_SECRET": newSecret,
	}

	if code, _, stderr := rekey(t, env); code != 0 {
		t.Fatalf("first run: exit %d: %s", code, stderr)
	}
	code, stdout, stderr := rekey(t, env)
	if code != 0 {
		t.Fatalf("second run: exit %d: %s", code, stderr)
	}
	// Exact, because it is the line an operator reads to decide whether the
	// first run worked: "no encrypted tokens found" would say the tokens are
	// gone.
	if stdout != "No tokens under the old secret — nothing rekeyed.\n" {
		t.Fatalf("second run stdout = %q", stdout)
	}
	requireAllUnder(t, dbPath, newSecret, "new", toks)
}

// meta.Open creates the database it is pointed at. A data dir that does not
// hold one — a typo, or the ./data default run from the wrong directory — used
// to yield a brand new empty jay.db, "nothing rekeyed" and exit 0; the operator
// then started jay on the new secret and every real token was unreadable.
// jay-rekey never creates a database.
func TestRun_RefusesAMissingDatabase(t *testing.T) {
	root := t.TempDir()
	typo := filepath.Join(root, "dtaa")
	env := map[string]string{"JAY_OLD_SIGNING_SECRET": oldSecret, "JAY_SIGNING_SECRET": newSecret}

	for _, c := range []struct {
		name string
		args []string
		env  map[string]string
	}{
		{"a data dir that does not exist", []string{"-data-dir", typo}, env},
		{"the ./data default from the wrong directory", nil, env},
		{"a -db path that does not exist", []string{"-db", filepath.Join(typo, "jay.db")}, env},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.args == nil {
				t.Chdir(root)
			}
			code, stdout, stderr := rekey(t, c.env, c.args...)
			if code != 1 || stdout != "" || !strings.Contains(stderr, "no database at") {
				t.Fatalf("exit %d, stdout %q, stderr %q; want 1 and a refusal", code, stdout, stderr)
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatalf("read %s: %v", root, err)
			}
			if len(entries) != 0 {
				t.Fatalf("a refused run created %v under %s", entries[0].Name(), root)
			}
		})
	}
}

func TestRun_RefusesADirectoryAsTheDatabase(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := rekey(t, map[string]string{
		"JAY_OLD_SIGNING_SECRET": oldSecret, "JAY_SIGNING_SECRET": newSecret,
	}, "-db", dir)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "is a directory") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestRun_HelpAndBadFlags(t *testing.T) {
	code, _, stderr := rekey(t, nil, "-h")
	if code != 0 || !strings.Contains(stderr, "Usage of jay-rekey") || !strings.Contains(stderr, "-new-secret") {
		t.Fatalf("-h: exit %d, stderr %q", code, stderr)
	}

	code, _, stderr = rekey(t, nil, "-no-such-flag")
	if code != 2 || !strings.Contains(stderr, "no-such-flag") {
		t.Fatalf("unknown flag: exit %d, stderr %q; want 2, as flag.ExitOnError exits", code, stderr)
	}
}
