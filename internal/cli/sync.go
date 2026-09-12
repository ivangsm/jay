package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/ivangsm/jay/proto/client"
)

// defaultParallel bounds concurrent transfers. It matches the client pool so
// every worker can hold a connection without queueing behind another.
const defaultParallel = poolSize

// transferMode decides what happens to a file that exists on both sides.
type transferMode int

const (
	// modeCopy transfers everything, like cp -r.
	modeCopy transferMode = iota
	// modeSync skips a file whose SHA-256 already matches the other side.
	modeSync
)

func runSync(opts Options, args []string) error {
	fs := newFlagSet("sync", opts)
	bindConnFlags(fs, &opts)
	parallel := fs.Int("p", defaultParallel, "concurrent transfers")
	fs.Usage = func() {
		write(opts.errOut(), `usage: jay sync SRC DST

  jay sync ./assets jay://images/assets
  jay sync jay://images/assets ./assets

Files are compared by SHA-256, not by timestamp: jay stores a checksum for
every object, and a mtime says nothing about content.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	rest := fs.Args()
	if len(rest) != 2 {
		fs.Usage()
		return errUsage
	}

	src, err := ParseLocation(rest[0])
	if err != nil {
		return err
	}
	dst, err := ParseLocation(rest[1])
	if err != nil {
		return err
	}

	c, err := opts.dial()
	if err != nil {
		return err
	}
	defer closeClient(c, opts.errOut())

	return mirror(opts, c, src, dst, modeSync, *parallel)
}

// mirror walks one side and transfers into the other. It backs both `sync` and
// `cp -r`; the only difference is whether an already-matching file is skipped.
func mirror(opts Options, c *client.Client, src, dst Location, mode transferMode, parallel int) error {
	if parallel < 1 {
		parallel = 1
	}
	// Every worker writes progress and per-file lines, so both streams are
	// serialized for the duration of the walk.
	progress := progressTarget(opts.errOut(), parallel)
	opts.Stdout = newSyncWriter(opts.out())
	opts.Stderr = newSyncWriter(opts.errOut())
	switch {
	case !src.Remote && dst.Remote:
		return mirrorUp(opts, c, src, dst, mode, parallel, progress)
	case src.Remote && !dst.Remote:
		return mirrorDown(opts, c, src, dst, mode, parallel, progress)
	case src.Remote && dst.Remote:
		return fmt.Errorf("copying a whole prefix between buckets is not supported yet: %s -> %s", src, dst)
	default:
		return fmt.Errorf("both sides are local paths: %s -> %s", src, dst)
	}
}

// localFile is one entry of a local tree, keyed by its path relative to the root.
type localFile struct {
	rel  string
	abs  string
	size int64
}

// walkLocal lists every regular file under root. Symlinks are not followed:
// resolving them can escape the directory the user named.
func walkLocal(root string) ([]localFile, error) {
	var out []localFile
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		out = append(out, localFile{rel: filepath.ToSlash(rel), abs: p, size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].rel < out[j].rel })
	return out, nil
}

// remoteIndex maps each key under a prefix to its stored SHA-256. The prefix is
// normalized to a directory so a sibling like "assets2" is never pulled in.
func remoteIndex(ctx context.Context, c *client.Client, loc Location) (map[string]string, error) {
	index := map[string]string{}
	err := walkObjects(ctx, c, loc.Bucket, DirPrefix(loc.Key), "", func(page *client.ListResult) error {
		for _, o := range page.Objects {
			index[o.Key] = o.ChecksumSHA256
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return index, nil
}

func mirrorUp(opts Options, c *client.Client, src, dst Location, mode transferMode, parallel int, progress io.Writer) error {
	files, err := walkLocal(src.Path)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		printf(opts.out(), "nothing to copy: %s has no files\n", src.Path)
		return nil
	}

	var index map[string]string
	if mode == modeSync {
		if index, err = remoteIndex(opts.context(), c, dst); err != nil {
			return err
		}
	}

	var tally counter
	runParallel(parallel, len(files), func(i int) {
		f := files[i]
		key := path.Join(dst.Key, f.rel)

		if mode == modeSync {
			same, err := localMatches(f.abs, index[key])
			if err != nil {
				tally.failed.Add(1)
				printf(opts.errOut(), "checksum %s: %v\n", f.abs, err)
				return
			}
			if same {
				return
			}
		}

		target := Location{Remote: true, Bucket: dst.Bucket, Key: key}
		if _, err := upload(opts.context(), c, f.abs, target, progress); err != nil {
			tally.failed.Add(1)
			printf(opts.errOut(), "upload %s: %v\n", f.abs, err)
			return
		}
		tally.ok.Add(1)
		tally.bytes.Add(f.size)
		printf(opts.out(), "%s -> %s\n", f.abs, target)
	})

	return report(opts, &tally, len(files))
}

func mirrorDown(opts Options, c *client.Client, src, dst Location, mode transferMode, parallel int, progress io.Writer) error {
	index, err := remoteIndex(opts.context(), c, src)
	if err != nil {
		return err
	}
	if len(index) == 0 {
		printf(opts.out(), "nothing to copy: no objects under %s\n", src)
		return nil
	}

	keys := make([]string, 0, len(index))
	for k := range index {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var tally counter
	runParallel(parallel, len(keys), func(i int) {
		key := keys[i]
		rel := strings.TrimPrefix(key, DirPrefix(src.Key))
		target, err := localTarget(dst.Path, rel)
		if err != nil {
			tally.failed.Add(1)
			printf(opts.errOut(), "skip %s: %v\n", key, err)
			return
		}

		if mode == modeSync {
			same, err := localMatches(target, index[key])
			if err != nil {
				tally.failed.Add(1)
				printf(opts.errOut(), "checksum %s: %v\n", target, err)
				return
			}
			if same {
				return
			}
		}

		object := Location{Remote: true, Bucket: src.Bucket, Key: key}
		written, err := download(opts.context(), c, object, target, progress)
		if err != nil {
			tally.failed.Add(1)
			printf(opts.errOut(), "download %s: %v\n", object, err)
			return
		}
		tally.ok.Add(1)
		tally.bytes.Add(written)
		printf(opts.out(), "%s -> %s\n", object, target)
	})

	return report(opts, &tally, len(keys))
}

// localMatches reports whether the file at path already has the given SHA-256.
// A missing file is a mismatch, not an error: that is the normal case for
// anything not transferred yet.
func localMatches(path, want string) (bool, error) {
	if want == "" {
		return false, nil
	}
	sum, err := fileChecksum(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return sum == want, nil
}

// fileChecksum hashes a file in streaming fashion; it never holds the contents
// in memory, so it works on objects far larger than RAM.
func fileChecksum(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // the path comes from the tree the user named
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// progressTarget decides where transfer progress goes. A per-file bar is only
// meaningful when one file moves at a time: with several workers redrawing the
// same line with \r, the bars overwrite each other into noise.
func progressTarget(w io.Writer, parallel int) io.Writer {
	if parallel == 1 {
		return w
	}
	return io.Discard
}

// runParallel executes fn for indexes [0,n) with at most parallel goroutines in flight.
func runParallel(parallel, n int, fn func(int)) {
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}(i)
	}
	wg.Wait()
}

// report prints the tally and turns any failure into a non-zero exit. A
// transfer that skipped half its files must not look like a success.
func report(opts Options, tally *counter, total int) error {
	transferred := tally.ok.Load()
	failed := tally.failed.Load()
	skipped := int64(total) - transferred - failed

	printf(opts.out(), "\n%d transferred (%s), %d up to date, %d failed\n",
		transferred, humanBytes(tally.bytes.Load()), skipped, failed)

	if failed > 0 {
		return fmt.Errorf("%d of %d file(s) failed", failed, total)
	}
	return nil
}
