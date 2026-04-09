package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/meta"
)

func openSeedTestDB(t *testing.T) *meta.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := meta.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

func TestSeed_AllEmpty_NoOp(t *testing.T) {
	db := openSeedTestDB(t)
	cfg := Config{}
	if err := runSeed(cfg, db, newTestLogger()); err != nil {
		t.Fatalf("runSeed err: %v", err)
	}
	// No token should exist
	_, err := db.GetToken("falco-native")
	if err == nil {
		t.Fatal("expected token to not exist")
	}
}

func TestSeed_PartialEnv_FailsToStart(t *testing.T) {
	db := openSeedTestDB(t)
	cfg := Config{SeedTokenAccount: "falco"} // missing ID and Secret
	if err := runSeed(cfg, db, newTestLogger()); err == nil {
		t.Fatal("expected error for partial seed env")
	}
}

func TestSeed_FreshBoot_CreatesAccountAndToken(t *testing.T) {
	db := openSeedTestDB(t)
	cfg := Config{
		SeedTokenAccount: "falco",
		SeedTokenID:      "falco-native",
		SeedTokenSecret:  "sekret-value-32-chars-aaaaaaaaaa",
	}
	if err := runSeed(cfg, db, newTestLogger()); err != nil {
		t.Fatalf("runSeed err: %v", err)
	}
	tok, err := db.GetToken("falco-native")
	if err != nil {
		t.Fatalf("token not created: %v", err)
	}
	if tok.AccountID == "" {
		t.Fatal("token has no account id")
	}
}

func TestSeed_SecondBoot_Idempotent(t *testing.T) {
	db := openSeedTestDB(t)
	cfg := Config{
		SeedTokenAccount: "falco",
		SeedTokenID:      "falco-native",
		SeedTokenSecret:  "sekret-value-32-chars-aaaaaaaaaa",
	}
	if err := runSeed(cfg, db, newTestLogger()); err != nil {
		t.Fatalf("first runSeed: %v", err)
	}
	if err := runSeed(cfg, db, newTestLogger()); err != nil {
		t.Fatalf("second runSeed: %v", err)
	}
}

func TestSeed_MismatchedSecret_WarnsButStarts(t *testing.T) {
	db := openSeedTestDB(t)
	cfg1 := Config{
		SeedTokenAccount: "falco",
		SeedTokenID:      "falco-native",
		SeedTokenSecret:  "original-secret-32-chars-aaaaaa",
	}
	if err := runSeed(cfg1, db, newTestLogger()); err != nil {
		t.Fatalf("first runSeed: %v", err)
	}
	cfg2 := cfg1
	cfg2.SeedTokenSecret = "different-secret-32-chars-bbbbb"
	// Should NOT return an error — just warns
	if err := runSeed(cfg2, db, newTestLogger()); err != nil {
		t.Fatalf("mismatch should warn not error: %v", err)
	}
	// Original token is still there, hash unchanged
	tok, _ := db.GetToken("falco-native")
	if tok.SecretKey != "original-secret-32-chars-aaaaaa" {
		t.Fatalf("secret was overwritten: %s", tok.SecretKey)
	}
}

func TestSeed_TokenUsableForAuth(t *testing.T) {
	db := openSeedTestDB(t)
	cfg := Config{
		SeedTokenAccount: "falco",
		SeedTokenID:      "falco-native",
		SeedTokenSecret:  "sekret-value-32-chars-aaaaaaaaaa",
	}
	if err := runSeed(cfg, db, newTestLogger()); err != nil {
		t.Fatalf("runSeed: %v", err)
	}
	a := auth.New(db)
	tok, err := a.AuthenticateCredentials("falco-native", "sekret-value-32-chars-aaaaaaaaaa")
	if err != nil {
		t.Fatalf("AuthenticateCredentials: %v", err)
	}
	if tok.TokenID != "falco-native" {
		t.Fatalf("wrong token returned: %s", tok.TokenID)
	}
}
