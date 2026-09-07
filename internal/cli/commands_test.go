package cli

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCpRoundTrip(t *testing.T) {
	env := newTestEnv(t)
	env.mustRun(t, "bucket", "mb", "images")

	want := randomBytes(t, 4096)
	src := env.writeFile(t, "src/photo.bin", want)

	env.mustRun(t, "cp", src, "jay://images/photos/photo.bin")

	if got := env.fetch(t, "images", "photos/photo.bin"); !bytes.Equal(got, want) {
		t.Fatalf("stored object differs: got %d bytes, want %d", len(got), len(want))
	}

	dst := env.path("out/photo.bin")
	env.mustRun(t, "cp", "jay://images/photos/photo.bin", dst)

	got, err := os.ReadFile(dst) //nolint:gosec // path built by the test
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("downloaded file differs from the uploaded bytes")
	}
}

func TestCpToPrefixAppendsBaseName(t *testing.T) {
	env := newTestEnv(t)
	env.mustRun(t, "bucket", "mb", "images")

	src := env.writeFile(t, "src/logo.png", []byte("png"))
	env.mustRun(t, "cp", src, "jay://images/brand/")

	if got := env.fetch(t, "images", "brand/logo.png"); string(got) != "png" {
		t.Fatalf("brand/logo.png = %q, want %q", got, "png")
	}
}

// Splitting is exercised with a lowered threshold: the assertion is that the
// reassembled object matches byte for byte, which is what a wrong part order
// or a dropped tail would break.
func TestCpMultipartReassemblesExactly(t *testing.T) {
	env := newTestEnv(t)
	env.mustRun(t, "bucket", "mb", "big")

	original := multipartThreshold
	multipartThreshold = 64 << 10 // 64 KiB
	defer func() { multipartThreshold = original }()

	want := randomBytes(t, 300<<10) // ~4.7 parts at a 64 KiB chunk
	src := env.writeFile(t, "src/big.bin", want)

	env.mustRun(t, "cp", src, "jay://big/big.bin")

	if got := env.fetch(t, "big", "big.bin"); !bytes.Equal(got, want) {
		t.Fatalf("multipart object differs: got %d bytes, want %d", len(got), len(want))
	}
}

func TestSyncSkipsUnchangedAndCopiesModified(t *testing.T) {
	env := newTestEnv(t)
	env.mustRun(t, "bucket", "mb", "assets")

	env.writeFile(t, "tree/a.txt", []byte("first"))
	env.writeFile(t, "tree/nested/b.txt", []byte("second"))
	tree := env.path("tree")

	env.mustRun(t, "sync", tree, "jay://assets/site")

	keys := env.keys(t, "assets")
	slices.Sort(keys)
	want := []string{"site/a.txt", "site/nested/b.txt"}
	if !slices.Equal(keys, want) {
		t.Fatalf("keys after sync = %v, want %v", keys, want)
	}

	// Second run: nothing changed, so nothing may be transferred.
	env.mustRun(t, "sync", tree, "jay://assets/site")
	if !strings.Contains(env.stdout.String(), "0 transferred") {
		t.Fatalf("second sync transferred something:\n%s", env.stdout)
	}

	// A changed file must actually reach the server, not just be reported.
	env.writeFile(t, "tree/a.txt", []byte("changed"))
	env.mustRun(t, "sync", tree, "jay://assets/site")
	if got := env.fetch(t, "assets", "site/a.txt"); string(got) != "changed" {
		t.Fatalf("site/a.txt = %q, want %q", got, "changed")
	}
}

func TestSyncDownloadRecreatesTree(t *testing.T) {
	env := newTestEnv(t)
	env.mustRun(t, "bucket", "mb", "assets")

	env.writeFile(t, "tree/a.txt", []byte("first"))
	env.writeFile(t, "tree/nested/b.txt", []byte("second"))
	env.mustRun(t, "sync", env.path("tree"), "jay://assets/site")

	out := env.path("restored")
	env.mustRun(t, "sync", "jay://assets/site", out)

	for rel, want := range map[string]string{
		"a.txt":        "first",
		"nested/b.txt": "second",
	} {
		got, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(rel))) //nolint:gosec // path built by the test
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}
}

// An unreadable file must make the command fail. A sync that skipped a file
// and still exited 0 would report success for work it did not do.
func TestSyncFailsWhenAFileCannotBeRead(t *testing.T) {
	env := newTestEnv(t)
	env.mustRun(t, "bucket", "mb", "assets")

	env.writeFile(t, "tree/good.txt", []byte("fine"))
	bad := env.writeFile(t, "tree/bad.txt", []byte("nope"))
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(bad, 0o600) }()

	if code := env.run("sync", env.path("tree"), "jay://assets/site"); code == 0 {
		t.Fatalf("sync with an unreadable file exited 0\nstdout: %s\nstderr: %s", env.stdout, env.stderr)
	}
	// The readable file still had to go up: a partial failure is not a reason
	// to abandon the rest of the tree.
	if got := env.fetch(t, "assets", "site/good.txt"); string(got) != "fine" {
		t.Fatalf("site/good.txt = %q, want %q", got, "fine")
	}
}

func TestRmRecursiveRemovesEveryKey(t *testing.T) {
	env := newTestEnv(t)
	env.mustRun(t, "bucket", "mb", "assets")

	env.writeFile(t, "tree/a.txt", []byte("a"))
	env.writeFile(t, "tree/nested/b.txt", []byte("b"))
	env.mustRun(t, "sync", env.path("tree"), "jay://assets/site")

	env.mustRun(t, "rm", "-r", "jay://assets/site")

	if keys := env.keys(t, "assets"); len(keys) != 0 {
		t.Fatalf("keys left after rm -r: %v", keys)
	}
}

func TestRmWholeBucketNeedsRecursive(t *testing.T) {
	env := newTestEnv(t)
	env.mustRun(t, "bucket", "mb", "assets")
	env.writeFile(t, "tree/a.txt", []byte("a"))
	env.mustRun(t, "sync", env.path("tree"), "jay://assets")

	if code := env.run("rm", "jay://assets"); code == 0 {
		t.Fatal("rm of a whole bucket without -r exited 0")
	}
	if keys := env.keys(t, "assets"); len(keys) != 1 {
		t.Fatalf("objects were deleted anyway: %v", keys)
	}
}

func TestUnknownCommandIsAUsageError(t *testing.T) {
	env := newTestEnv(t)
	if code := env.run("frobnicate"); code != 2 {
		t.Fatalf("unknown command: exit %d, want 2", code)
	}
	if !strings.Contains(env.stderr.String(), "unknown command") {
		t.Fatalf("stderr does not name the problem:\n%s", env.stderr)
	}
}

func TestIsCommand(t *testing.T) {
	// A typo must reach the CLI so it can be reported, while server flags must
	// not: `jay --config-file x.yml` still boots the server.
	for _, arg := range []string{"ls", "cp", "sync", "version", "help", "frobnicate", "-h", "--help"} {
		if !IsCommand(arg) {
			t.Errorf("IsCommand(%q) = false, want true", arg)
		}
	}
	for _, arg := range []string{"--config-file", "-config-file", "-v"} {
		if IsCommand(arg) {
			t.Errorf("IsCommand(%q) = true, want false", arg)
		}
	}
}

func TestCpBetweenTwoLocalPathsIsRefused(t *testing.T) {
	env := newTestEnv(t)
	if code := env.run("cp", env.path("a"), env.path("b")); code == 0 {
		t.Fatal("local-to-local cp exited 0")
	}
}

// A prefix must not swallow its siblings. "assets" and "assets2" are distinct
// trees, and a recursive delete or sync that treats the first as a plain string
// prefix reaches into the second — on rm -r that destroys data.
func TestRecursiveOperationsDoNotTouchSiblingPrefixes(t *testing.T) {
	env := newTestEnv(t)
	env.mustRun(t, "bucket", "mb", "images")

	env.writeFile(t, "site/a.txt", []byte("inside"))
	env.writeFile(t, "site2/b.txt", []byte("sibling"))
	env.mustRun(t, "sync", env.path("site"), "jay://images/assets")
	env.mustRun(t, "sync", env.path("site2"), "jay://images/assets2")

	t.Run("sync down", func(t *testing.T) {
		out := env.path("restored")
		env.mustRun(t, "sync", "jay://images/assets", out)

		entries, err := os.ReadDir(out)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		if !slices.Equal(names, []string{"a.txt"}) {
			t.Fatalf("downloaded %v, want just [a.txt]: the sibling prefix leaked in", names)
		}
	})

	t.Run("rm recursive", func(t *testing.T) {
		env.mustRun(t, "rm", "-r", "jay://images/assets")

		keys := env.keys(t, "images")
		slices.Sort(keys)
		if !slices.Equal(keys, []string{"assets2/b.txt"}) {
			t.Fatalf("keys after rm -r jay://images/assets = %v, want [assets2/b.txt]", keys)
		}
	})
}

// A stored key can contain "..", and joining it onto the destination would
// write above the directory the user named. The assertion is the absence of
// the file on disk, not the message the command printed.
func TestSyncDownloadRefusesKeyEscapingDestination(t *testing.T) {
	env := newTestEnv(t)
	env.mustRun(t, "bucket", "mb", "assets")
	env.putObject(t, "assets", "site/a.txt", []byte("fine"))
	env.putObject(t, "assets", "site/../../escaped.txt", []byte("escaped"))

	out := env.path("restored", "deep")
	code := env.run("sync", "jay://assets/site", out)

	escaped := env.path("escaped.txt")
	if _, err := os.Stat(escaped); err == nil {
		t.Fatalf("sync wrote %s, outside the destination %s", escaped, out)
	}
	if code == 0 {
		t.Errorf("sync exited 0 after skipping a key it could not place\nstderr: %s", env.stderr)
	}
	// The legitimate key still had to land: one hostile key is not a reason to
	// abandon the rest of the tree.
	got, err := os.ReadFile(filepath.Join(out, "a.txt")) //nolint:gosec // path built by the test
	if err != nil || string(got) != "fine" {
		t.Errorf("a.txt = %q, %v; want %q", got, err, "fine")
	}
}
