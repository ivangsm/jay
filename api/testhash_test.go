package api

import (
	"sync"
	"testing"

	"github.com/ivangsm/jay/auth"
)

// hashCache memoises bcrypt hashes per test secret. Every fixture in this
// package hashes the same handful of constant secrets, and bcrypt at
// DefaultCost under -race is slow enough to push the package past go test's
// default timeout. A hash is a hash — reusing one changes nothing a test asserts.
var hashCache sync.Map // secret → bcrypt hash

// testHash returns a bcrypt hash of secret, computing it at most once per
// process. It fails the test rather than returning "" on error.
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
