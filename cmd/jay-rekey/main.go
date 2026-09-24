// jay-rekey — offline tool to re-encrypt jay token secrets after a signing key rotation.
//
// Jay MUST be stopped before running this command. bbolt enforces an exclusive
// file lock; the command will fail with a timeout error if jay is still running.
//
// Usage:
//
//	jay-rekey [-data-dir DIR] [-db PATH] [-old-secret SECRET] [-new-secret SECRET]
//
// Environment variables (used as defaults if flags are omitted):
//
//	JAY_DATA_DIR          — base data directory (default: ./data)
//	JAY_OLD_SIGNING_SECRET — old value of JAY_SIGNING_SECRET
//	JAY_SIGNING_SECRET     — new value of JAY_SIGNING_SECRET
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/ivangsm/jay/meta"
)

func main() {
	os.Exit(run(os.Args, os.Getenv, os.Stdout, os.Stderr))
}

// run is main with its environment passed in, so every path — including the
// refusals — can be driven from a test. args includes the program name, as
// os.Args does. It returns the process exit code.
func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := flags.String("data-dir", envOr(getenv, "JAY_DATA_DIR", "./data"), "Jay data directory (contains meta/jay.db)")
	dbPath := flags.String("db", "", "Direct path to jay.db (overrides -data-dir)")
	oldSecret := flags.String("old-secret", getenv("JAY_OLD_SIGNING_SECRET"), "Old JAY_SIGNING_SECRET used to encrypt existing tokens")
	newSecret := flags.String("new-secret", getenv("JAY_SIGNING_SECRET"), "New JAY_SIGNING_SECRET to re-encrypt tokens with")
	if err := flags.Parse(args[1:]); err != nil {
		// The exit codes flag.ExitOnError uses: asking for help is not a failure.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	path := *dbPath
	if path == "" {
		path = filepath.Join(*dataDir, "meta", "jay.db")
	}

	if *oldSecret == "" {
		return fail(stderr, "old secret required — set JAY_OLD_SIGNING_SECRET or use -old-secret")
	}
	if *newSecret == "" {
		return fail(stderr, "new secret required — set JAY_SIGNING_SECRET or use -new-secret")
	}
	if *oldSecret == *newSecret {
		return fail(stderr, "old and new secrets are identical — nothing to do")
	}

	// meta.Open creates the database it is pointed at. Here that turned a typo
	// in -data-dir — or the ./data default, run from the wrong directory —
	// into a fresh empty jay.db and "nothing rekeyed" with exit 0, after which
	// the operator starts jay on the new secret and every real token is
	// unreadable. There is nothing to rekey in a database that does not exist.
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fail(stderr, "no database at %s — check -data-dir or -db (jay-rekey never creates one)", path)
	case err != nil:
		return fail(stderr, "stat %s: %v", path, err)
	case info.IsDir():
		return fail(stderr, "%s is a directory, not a jay.db", path)
	}

	db, err := meta.Open(path)
	if err != nil {
		return fail(stderr, "open database %s: %v", path, err)
	}
	defer func() { _ = db.Close() }()

	n, err := db.RekeyTokens(*oldSecret, *newSecret)
	if err != nil {
		return fail(stderr, "%v", err)
	}

	if n == 0 {
		// Either there are no encrypted tokens, or every one of them is already
		// under the new secret (a second run).
		_, _ = fmt.Fprintln(stdout, "No tokens under the old secret — nothing rekeyed.")
	} else {
		_, _ = fmt.Fprintf(stdout, "Rekeyed %d token(s) successfully.\n", n)
	}
	return 0
}

// fail prints the error the way the tool always has and returns exit code 1.
func fail(stderr io.Writer, format string, args ...any) int {
	_, _ = fmt.Fprintf(stderr, "jay-rekey: "+format+"\n", args...)
	return 1
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}
