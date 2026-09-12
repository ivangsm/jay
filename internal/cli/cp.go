package cli

import (
	"fmt"
	"path"
	"strings"

	"github.com/ivangsm/jay/proto/client"
)

func runCp(opts Options, args []string) error {
	fs := newFlagSet("cp", opts)
	bindConnFlags(fs, &opts)
	recursive := fs.Bool("r", false, "copy a directory or prefix and everything under it")
	parallel := fs.Int("p", defaultParallel, "concurrent transfers when copying recursively")
	fs.Usage = func() {
		write(opts.errOut(), `usage: jay cp [-r] SRC DST

  jay cp ./photo.webp jay://images/users/1.webp
  jay cp jay://images/users/1.webp ./photo.webp
  jay cp -r ./assets jay://images/assets

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
	if !src.Remote && !dst.Remote {
		return fmt.Errorf("both sides are local paths; use cp(1) for %s -> %s", src, dst)
	}

	c, err := opts.dial()
	if err != nil {
		return err
	}
	defer closeClient(c, opts.errOut())

	if *recursive {
		return mirror(opts, c, src, dst, modeCopy, *parallel)
	}
	return copyOne(opts, c, src, dst)
}

// copyOne handles the three single-object directions. The destination key is
// completed from the source name when the user gave a prefix, matching what
// cp(1) does with a directory destination.
func copyOne(opts Options, c *client.Client, src, dst Location) error {
	switch {
	case !src.Remote && dst.Remote:
		target := dst
		target.Key = resolveKey(dst.Key, src.Path)
		sum, err := upload(opts.context(), c, src.Path, target, opts.errOut())
		if err != nil {
			return err
		}
		printf(opts.out(), "%s -> %s  sha256:%s\n", src.Path, target, shortChecksum(sum))
		return nil

	case src.Remote && !dst.Remote:
		target := resolveLocalPath(dst.Path, src.Key)
		if _, err := download(opts.context(), c, src, target, opts.errOut()); err != nil {
			return err
		}
		printf(opts.out(), "%s -> %s\n", src, target)
		return nil

	default:
		target := dst
		target.Key = resolveKey(dst.Key, src.Key)
		if err := remoteCopy(opts.context(), c, src, target, opts.errOut()); err != nil {
			return err
		}
		printf(opts.out(), "%s -> %s\n", src, target)
		return nil
	}
}

// resolveKey completes a destination key. An empty key, or one ending in "/",
// is a prefix: the source's base name is appended instead of overwriting the
// prefix itself with a single object.
func resolveKey(dstKey, srcName string) string {
	base := baseName(srcName)
	switch {
	case dstKey == "":
		return base
	case strings.HasSuffix(dstKey, "/"):
		return dstKey + base
	default:
		return dstKey
	}
}

// resolveLocalPath completes a local destination the same way: a path ending
// in a separator, or an existing directory, receives the object's base name.
func resolveLocalPath(dstPath, srcKey string) string {
	if dstPath == "" {
		return baseName(srcKey)
	}
	if strings.HasSuffix(dstPath, "/") || isDir(dstPath) {
		return path.Join(dstPath, baseName(srcKey))
	}
	return dstPath
}
