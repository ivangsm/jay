package api

import (
	"sync"
	"testing"

	"github.com/ivangsm/jay/auth"
)

// hashCache memoises bcrypt hashes per test secret. Every fixture in this
// package hashes the same handful of constant secrets, and bcrypt at
// DefaultCost is ~1s per call under -race on a CI runner: 146 tests times one
// or two hashes each is what pushed the package past go test's 10-minute
// default. A hash is a hash — reusing one across tests changes nothing they
// assert.
var hashCache sync.Map // secret → bcrypt hash

// testHash returns a bcrypt hash of secret, computing it at most once per
// process. It fails the test rather than returning "" on error, which the
// call sites it replaced used to ignore.
func testHash(t *testing.T, secret string) string {
	t.Helper()
	if h, ok := hashCache.Load(secret); ok {
		return h.(string)
	}
	h, err := auth.HashSecret(secret)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	hashCache.Store(secret, h)
	return h
}
