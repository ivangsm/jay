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
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ivangsm/jay/meta"
)

func main() {
	dataDir := flag.String("data-dir", envOr("JAY_DATA_DIR", "./data"), "Jay data directory (contains meta/jay.db)")
	dbPath := flag.String("db", "", "Direct path to jay.db (overrides -data-dir)")
	oldSecret := flag.String("old-secret", os.Getenv("JAY_OLD_SIGNING_SECRET"), "Old JAY_SIGNING_SECRET used to encrypt existing tokens")
	newSecret := flag.String("new-secret", os.Getenv("JAY_SIGNING_SECRET"), "New JAY_SIGNING_SECRET to re-encrypt tokens with")
	flag.Parse()

	path := *dbPath
	if path == "" {
		path = filepath.Join(*dataDir, "meta", "jay.db")
	}

	if *oldSecret == "" {
		fatalf("old secret required — set JAY_OLD_SIGNING_SECRET or use -old-secret")
	}
	if *newSecret == "" {
		fatalf("new secret required — set JAY_SIGNING_SECRET or use -new-secret")
	}
	if *oldSecret == *newSecret {
		fatalf("old and new secrets are identical — nothing to do")
	}

	db, err := meta.Open(path)
	if err != nil {
		fatalf("open database %s: %v", path, err)
	}
	defer func() { _ = db.Close() }()

	n, err := db.RekeyTokens(*oldSecret, *newSecret)
	if err != nil {
		fatalf("%v", err)
	}

	if n == 0 {
		fmt.Println("No encrypted tokens found — nothing rekeyed.")
	} else {
		fmt.Printf("Rekeyed %d token(s) successfully.\n", n)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "jay-rekey: "+format+"\n", args...)
	os.Exit(1)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
