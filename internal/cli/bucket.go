package cli

import (
	"errors"
	"fmt"

	"github.com/ivangsm/jay/proto/client"
)

func runBucket(opts Options, args []string) error {
	fs := newFlagSet("bucket", opts)
	bindConnFlags(fs, &opts)
	fs.Usage = func() {
		write(opts.errOut(), "usage: jay bucket ls | mb NAME | rb NAME\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return errUsage
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return errUsage
	}

	c, err := opts.dial()
	if err != nil {
		return err
	}
	defer closeClient(c, opts.errOut())

	switch rest[0] {
	case "ls":
		return listBuckets(opts, c)
	case "mb":
		return oneBucket(rest, "mb", func(name string) error {
			if _, err := c.CreateBucket(name); err != nil {
				return err
			}
			printf(opts.out(), "created %s%s\n", Scheme, name)
			return nil
		})
	case "rb":
		return oneBucket(rest, "rb", func(name string) error {
			if err := c.DeleteBucket(name); err != nil {
				return err
			}
			printf(opts.out(), "deleted %s%s\n", Scheme, name)
			return nil
		})
	default:
		fs.Usage()
		return errUsage
	}
}

// oneBucket validates the single-name argument shape shared by mb and rb.
func oneBucket(args []string, verb string, do func(string) error) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: jay bucket %s NAME", verb)
	}
	name := args[1]
	// jay://images and images both name the same bucket; accepting only one
	// of the two spellings is a needless trap.
	if loc, err := ParseLocation(name); err == nil && loc.Remote {
		if loc.Key != "" {
			return errors.New("bucket " + verb + " takes a bucket, not a key")
		}
		name = loc.Bucket
	}
	return do(name)
}

func listBuckets(opts Options, c *client.Client) error {
	buckets, err := c.ListBuckets()
	if err != nil {
		return err
	}
	for _, b := range buckets {
		printf(opts.out(), "%s  %s\n", b.CreatedAt, b.Name)
	}
	return nil
}
