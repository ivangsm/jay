package auth

import (
	"errors"
	"testing"

	"github.com/ivangsm/jay/meta"
)

// AuthorizeBucketAccess is the whole cross-account decision (PND-0185). These
// cases pin the order of the three doors and, above all, that the default is
// deny — a bucket that says nothing about a stranger says no.

func ownedBucket(policy string) *meta.Bucket {
	b := &meta.Bucket{
		ID:             "bucket-id",
		Name:           "owned",
		OwnerAccountID: "account-a",
		Visibility:     "private",
		Status:         "active",
	}
	if policy != "" {
		b.PolicyJSON = []byte(policy)
	}
	return b
}

func foreignToken(bucketScope ...string) *meta.Token {
	return &meta.Token{
		TokenID:        "token-b",
		AccountID:      "account-b",
		AllowedActions: []string{"*"},
		BucketScope:    bucketScope,
		Status:         "active",
	}
}

func TestAuthorizeBucketAccess(t *testing.T) {
	owner := &meta.Token{TokenID: "token-a", AccountID: "account-a", AllowedActions: []string{"*"}, Status: "active"}

	publicBucket := ownedBucket("")
	publicBucket.Visibility = "public-read"

	unowned := ownedBucket("")
	unowned.OwnerAccountID = ""

	allowRead := ownedBucket(`{"statements":[{"effect":"allow","actions":["object:get"],"subjects":["*"]}]}`)
	allowByTokenID := ownedBucket(`{"statements":[{"effect":"allow","actions":["object:get"],"subjects":["token-b"]}]}`)
	allowOtherToken := ownedBucket(`{"statements":[{"effect":"allow","actions":["object:get"],"subjects":["token-z"]}]}`)
	allowFromLAN := ownedBucket(`{"statements":[{"effect":"allow","actions":["object:get"],"subjects":["*"],
	  "conditions":{"ip_whitelist":["10.0.0.0/8"]}}]}`)
	denyOnly := ownedBucket(`{"statements":[{"effect":"deny","actions":["object:get"],"subjects":["*"]}]}`)
	malformed := ownedBucket(`{"statements": [ not json at all`)

	cases := []struct {
		name    string
		token   *meta.Token
		bucket  *meta.Bucket
		action  string
		key     string
		ip      string
		granted bool
	}{
		{"owner reaches its own bucket", owner, ownedBucket(""), meta.ActionObjectGet, "k", "1.2.3.4", true},
		{"stranger is refused without a policy", foreignToken(), ownedBucket(""), meta.ActionObjectGet, "k", "1.2.3.4", false},
		{"stranger is refused for writes without a policy", foreignToken(), ownedBucket(""), meta.ActionObjectPut, "k", "1.2.3.4", false},
		{"an unowned legacy bucket stays reachable", foreignToken(), unowned, meta.ActionObjectPut, "k", "1.2.3.4", true},
		{"BucketScope delegation grants", foreignToken("owned"), ownedBucket(""), meta.ActionObjectPut, "k", "1.2.3.4", true},
		{"public-read grants a read", foreignToken(), publicBucket, meta.ActionObjectGet, "k", "1.2.3.4", true},
		{"public-read grants a listing", foreignToken(), publicBucket, meta.ActionObjectList, "", "1.2.3.4", true},
		{"public-read does not grant a write", foreignToken(), publicBucket, meta.ActionObjectPut, "k", "1.2.3.4", false},
		{"public-read does not grant bucket metadata", foreignToken(), publicBucket, meta.ActionBucketReadMeta, "", "1.2.3.4", false},
		{"an explicit allow grants", foreignToken(), allowRead, meta.ActionObjectGet, "k", "1.2.3.4", true},
		{"an allow does not spill to other actions", foreignToken(), allowRead, meta.ActionObjectDelete, "k", "1.2.3.4", false},
		{"an allow can name the token", foreignToken(), allowByTokenID, meta.ActionObjectGet, "k", "1.2.3.4", true},
		{"an allow for another token does not apply", foreignToken(), allowOtherToken, meta.ActionObjectGet, "k", "1.2.3.4", false},
		{"an allow honours its IP condition", foreignToken(), allowFromLAN, meta.ActionObjectGet, "k", "10.1.2.3", true},
		{"an allow outside its IP condition does not grant", foreignToken(), allowFromLAN, meta.ActionObjectGet, "k", "1.2.3.4", false},
		{"a deny-only policy grants nothing", foreignToken(), denyOnly, meta.ActionObjectGet, "k", "1.2.3.4", false},
		{"a malformed policy grants nothing", foreignToken(), malformed, meta.ActionObjectGet, "k", "1.2.3.4", false},
		{"a nil bucket is refused", foreignToken(), nil, meta.ActionObjectGet, "k", "1.2.3.4", false},
		{"an anonymous caller has no account to match", nil, ownedBucket(""), meta.ActionObjectGet, "k", "1.2.3.4", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := AuthorizeBucketAccess(tc.token, tc.bucket, tc.action, tc.key, tc.ip)
			if tc.granted && err != nil {
				t.Fatalf("want granted, got %v", err)
			}
			if !tc.granted {
				if err == nil {
					t.Fatal("want denied, got granted")
				}
				if !errors.Is(err, ErrAccessDenied) {
					t.Fatalf("want ErrAccessDenied, got %v", err)
				}
			}
		})
	}
}

// A prefix on an allow statement is part of the grant, not decoration.
func TestAuthorizeBucketAccess_AllowIsScopedByPrefix(t *testing.T) {
	bucket := ownedBucket(`{"statements":[{"effect":"allow","actions":["object:get"],"prefixes":["public/"],"subjects":["*"]}]}`)

	if err := AuthorizeBucketAccess(foreignToken(), bucket, meta.ActionObjectGet, "public/a.txt", "1.2.3.4"); err != nil {
		t.Fatalf("want the prefixed key granted, got %v", err)
	}
	if err := AuthorizeBucketAccess(foreignToken(), bucket, meta.ActionObjectGet, "private/a.txt", "1.2.3.4"); err == nil {
		t.Fatal("a grant on public/ reached private/")
	}
}

// ParsePolicy is the only decoder of a policy document, and an empty one is not
// an error — it is the absence of a policy, which callers read as "no grant".
func TestParsePolicy(t *testing.T) {
	p, err := ParsePolicy(nil)
	if err != nil || p != nil {
		t.Fatalf("nil policy: got (%v, %v), want (nil, nil)", p, err)
	}

	p, err = ParsePolicy([]byte(`{"statements":[{"effect":"allow","actions":["*"],"subjects":["*"],
	  "conditions":{"ip_whitelist":["10.0.0.0/8"]}}]}`))
	if err != nil {
		t.Fatalf("valid policy: %v", err)
	}
	if len(p.Statements) != 1 {
		t.Fatalf("statements = %d, want 1", len(p.Statements))
	}
	// Compile() must have run: otherwise the CIDR is never matched and the
	// condition silently passes for every address.
	if !EvaluatePolicyAllow(p, "any", "object:get", "k", "10.1.1.1") {
		t.Fatal("compiled IP condition did not match an address inside the CIDR")
	}
	if EvaluatePolicyAllow(p, "any", "object:get", "k", "192.168.1.1") {
		t.Fatal("IP condition matched an address outside the CIDR")
	}

	if _, err := ParsePolicy([]byte(`{ not json`)); err == nil {
		t.Fatal("malformed policy parsed without error")
	}
}
