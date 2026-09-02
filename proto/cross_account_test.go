package proto_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/proto/client"
)

// Cross-account isolation over the native protocol (PND-0185).
//
// falco is the only consumer in the monorepo and it talks this protocol, so the
// hole was here too — the HTTP surface is simply where it was measured. Every
// assertion reads the database after the attempt, never the returned error.

const (
	protoBucket  = "owned"
	protoKey     = "private/report.txt"
	protoContent = "the owner's bytes"
)

// intruderClient adds a second account with a wildcard, unscoped token and
// returns a client connected as that account.
func intruderClient(t *testing.T, env *testEnv) *client.Client {
	t.Helper()
	other := &meta.Account{AccountID: "intruder-account", Name: "intruder", Status: "active"}
	if err := env.db.CreateAccount(other); err != nil {
		t.Fatalf("create intruder account: %v", err)
	}

	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		t.Fatalf("rand: %v", err)
	}
	secret := hex.EncodeToString(secretBytes)
	hash, err := auth.HashSecret(secret)
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	if err := env.db.CreateToken(&meta.Token{
		TokenID:        "intruder-token",
		AccountID:      other.AccountID,
		Name:           "intruder",
		SecretHash:     hash,
		AllowedActions: []string{"*"},
		Status:         "active",
	}); err != nil {
		t.Fatalf("create intruder token: %v", err)
	}

	c, err := client.Dial(env.addr, "intruder-token", secret, 2)
	if err != nil {
		t.Fatalf("dial as intruder: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// seedOwnedBucket creates the owner's bucket with one object in it and returns
// its bucket id, so assertions can read the record straight from bbolt.
func seedOwnedBucket(t *testing.T, env *testEnv, owner *client.Client) string {
	t.Helper()
	if _, err := owner.CreateBucket(protoBucket); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	body := strings.NewReader(protoContent)
	if _, err := owner.PutObject(protoBucket, protoKey, body, int64(len(protoContent)), nil); err != nil {
		t.Fatalf("owner put: %v", err)
	}
	bkt, err := env.db.GetBucket(protoBucket)
	if err != nil {
		t.Fatalf("get bucket: %v", err)
	}
	return bkt.ID
}

func assertProtoObjectIntact(t *testing.T, env *testEnv, bucketID, what string) {
	t.Helper()
	obj, err := env.db.GetObjectMeta(bucketID, protoKey)
	if err != nil {
		t.Fatalf("%s: the owner's object is gone from the database: %v", what, err)
	}
	if obj.SizeBytes != int64(len(protoContent)) {
		t.Fatalf("%s: object size = %d, want %d — the bytes were replaced",
			what, obj.SizeBytes, len(protoContent))
	}
}

func TestProtoCrossAccount_ObjectOperationsRefused(t *testing.T) {
	env := setup(t)
	owner := dial(t, env)
	bucketID := seedOwnedBucket(t, env, owner)
	intruder := intruderClient(t, env)

	if res, err := intruder.GetObject(protoBucket, protoKey); err == nil {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(res.Body)
		_ = res.Body.Close()
		t.Fatalf("GetObject handed another account's bytes: %q", buf.String())
	}

	body := strings.NewReader("not mine")
	if _, err := intruder.PutObject(protoBucket, "injected.txt", body, int64(len("not mine")), nil); err == nil {
		t.Fatal("PutObject wrote into another account's bucket")
	}
	if _, err := env.db.GetObjectMeta(bucketID, "injected.txt"); err == nil {
		t.Fatal("injected.txt landed in another account's bucket")
	}

	_ = intruder.DeleteObject(protoBucket, protoKey)
	assertProtoObjectIntact(t, env, bucketID, "DeleteObject")

	if _, err := intruder.HeadObject(protoBucket, protoKey); err == nil {
		t.Fatal("HeadObject disclosed another account's object metadata")
	}
}

func TestProtoCrossAccount_ListAndMultipartRefused(t *testing.T) {
	env := setup(t)
	owner := dial(t, env)
	seedOwnedBucket(t, env, owner)
	intruder := intruderClient(t, env)

	if res, err := intruder.ListObjects(protoBucket, nil); err == nil {
		for _, o := range res.Objects {
			if o.Key == protoKey {
				t.Fatalf("ListObjects disclosed another account's keys: %v", res.Objects)
			}
		}
	}

	if id, err := intruder.CreateMultipartUpload(protoBucket, "sneak.bin", nil); err == nil {
		t.Fatalf("multipart upload %q started in another account's bucket", id)
	}
}

// The owner keeps full use of its own bucket — this is the path falco rides,
// with a seeded wildcard token on the account that owns everything.
func TestProtoCrossAccount_OwnerIsUnaffected(t *testing.T) {
	env := setup(t)
	owner := dial(t, env)
	bucketID := seedOwnedBucket(t, env, owner)

	res, err := owner.GetObject(protoBucket, protoKey)
	if err != nil {
		t.Fatalf("owner get: %v", err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	_ = res.Body.Close()
	if buf.String() != protoContent {
		t.Fatalf("owner read %q, want %q", buf.String(), protoContent)
	}

	list, err := owner.ListObjects(protoBucket, nil)
	if err != nil {
		t.Fatalf("owner list: %v", err)
	}
	if len(list.Objects) != 1 || list.Objects[0].Key != protoKey {
		t.Fatalf("owner listing = %v", list.Objects)
	}

	if err := owner.DeleteObject(protoBucket, protoKey); err != nil {
		t.Fatalf("owner delete: %v", err)
	}
	if _, err := env.db.GetObjectMeta(bucketID, protoKey); err == nil {
		t.Fatal("owner delete did not remove the object")
	}
}

// A bucket policy is the one way to open a bucket to another account, and it
// works the same over both transports.
func TestProtoCrossAccount_PolicyAllowGrantsRead(t *testing.T) {
	env := setup(t)
	owner := dial(t, env)
	seedOwnedBucket(t, env, owner)
	intruder := intruderClient(t, env)

	policy := `{"statements":[{"effect":"allow","actions":["object:get","object:list"],"subjects":["*"]}]}`
	if err := env.db.UpdateBucketPolicy(protoBucket, []byte(policy)); err != nil {
		t.Fatalf("update bucket policy: %v", err)
	}

	res, err := intruder.GetObject(protoBucket, protoKey)
	if err != nil {
		t.Fatalf("an explicit allow did not grant the read: %v", err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	_ = res.Body.Close()
	if buf.String() != protoContent {
		t.Fatalf("granted read returned %q, want %q", buf.String(), protoContent)
	}

	list, err := intruder.ListObjects(protoBucket, nil)
	if err != nil {
		t.Fatalf("an explicit allow did not grant the listing: %v", err)
	}
	if len(list.Objects) != 1 || list.Objects[0].Key != protoKey {
		t.Fatalf("granted listing = %v", list.Objects)
	}
}
