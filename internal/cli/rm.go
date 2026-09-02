package cli

import (
	"fmt"

	"github.com/ivangsm/jay/proto/client"
)

func runRm(opts Options, args []string) error {
	fs := newFlagSet("rm", opts)
	bindConnFlags(fs, &opts)
	recursive := fs.Bool("r", false, "delete every object under the prefix")
	fs.Usage = func() {
		write(opts.errOut(), "usage: jay rm [-r] jay://BUCKET/KEY\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fs.Usage()
		return errUsage
	}

	loc, err := ParseLocation(rest[0])
	if err != nil {
		return err
	}
	if !loc.Remote {
		return fmt.Errorf("rm takes a %sBUCKET/KEY location, got a local path: %s", Scheme, loc.Path)
	}
	if loc.Key == "" && !*recursive {
		return fmt.Errorf("refusing to delete every object in %s without -r", loc)
	}

	c, err := opts.dial()
	if err != nil {
		return err
	}
	defer closeClient(c, opts.errOut())

	if !*recursive {
		if err := c.DeleteObject(loc.Bucket, loc.Key); err != nil {
			return err
		}
		printf(opts.out(), "deleted %s\n", loc)
		return nil
	}

	return removePrefix(opts, c, loc)
}

// removePrefix deletes every key under a prefix. Keys are collected first
// because deleting while paging moves the cursor out from under the listing.
func removePrefix(opts Options, c *client.Client, loc Location) error {
	var keys []string
	err := walkObjects(c, loc.Bucket, DirPrefix(loc.Key), "", func(page *client.ListResult) error {
		for _, o := range page.Objects {
			keys = append(keys, o.Key)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		printf(opts.out(), "no objects under %s\n", loc)
		return nil
	}

	var failed int
	for _, key := range keys {
		if err := c.DeleteObject(loc.Bucket, key); err != nil {
			failed++
			printf(opts.errOut(), "delete %s%s/%s: %v\n", Scheme, loc.Bucket, key, err)
			continue
		}
		printf(opts.out(), "deleted %s%s/%s\n", Scheme, loc.Bucket, key)
	}

	// A partial delete must not exit 0: the caller's next step is usually
	// "the prefix is gone now".
	if failed > 0 {
		return fmt.Errorf("%d of %d object(s) could not be deleted", failed, len(keys))
	}
	return nil
}
