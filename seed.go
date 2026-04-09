package main

import (
	"fmt"
	"log/slog"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/meta"
)

// runSeed creates an account+token from Config.SeedToken* fields if all three
// are set. Partial configuration returns an error. The token is created with
// wildcard permissions (AllAllowedActions="*") and no bucket/prefix scope —
// the operator is expected to narrow it via the admin API if needed.
//
// Behavior:
//   - All 3 empty                → no-op, returns nil
//   - Partial (1 or 2 set)       → returns error
//   - All 3 set, fresh DB        → creates account + token
//   - All 3 set, second boot     → reuses existing
//   - All 3 set, hash mismatch   → warns, leaves existing token untouched
func runSeed(cfg Config, db *meta.DB, log *slog.Logger) error {
	acc := cfg.SeedTokenAccount
	id := cfg.SeedTokenID
	sec := cfg.SeedTokenSecret

	emptyCount := 0
	if acc == "" {
		emptyCount++
	}
	if id == "" {
		emptyCount++
	}
	if sec == "" {
		emptyCount++
	}

	if emptyCount == 3 {
		log.Info("seed: disabled (JAY_SEED_TOKEN_* all empty)")
		return nil
	}
	if emptyCount != 0 {
		return fmt.Errorf("seed: JAY_SEED_TOKEN_ACCOUNT, JAY_SEED_TOKEN_ID and JAY_SEED_TOKEN_SECRET must all be set or all empty")
	}

	account, created, err := db.CreateAccountIfNotExists(acc)
	if err != nil {
		return fmt.Errorf("seed: create account: %w", err)
	}
	if created {
		log.Info("seed: account created", "name", acc, "account_id", account.AccountID)
	} else {
		log.Info("seed: account exists, reusing", "name", acc, "account_id", account.AccountID)
	}

	hash, err := auth.HashSecret(sec)
	if err != nil {
		return fmt.Errorf("seed: hash secret: %w", err)
	}

	_, status, err := db.CreateTokenIfNotExists(id, account.AccountID, acc, hash, sec, []string{"*"})
	if err != nil {
		return fmt.Errorf("seed: create token: %w", err)
	}

	switch status {
	case meta.TokenSeedCreated:
		log.Info("seed: token created", "token_id", id)
	case meta.TokenSeedReused:
		log.Info("seed: token already present, reusing", "token_id", id)
	case meta.TokenSeedMismatch:
		log.Warn("seed: token exists but secret does not match env; refusing to overwrite", "token_id", id)
	}

	return nil
}
