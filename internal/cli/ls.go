package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ivangsm/jay/proto/client"
)

// listPageSize is the per-request key budget. Listing pages until the server
// stops reporting truncation, so a large bucket is fully walked rather than
// silently cut at the first page.
const listPageSize = 1000

func runLs(opts Options, args []string) error {
	fs := newFlagSet("ls", opts)
	bindConnFlags(fs, &opts)
	recursive := fs.Bool("r", false, "descend into every prefix instead of collapsing at /")
	long := fs.Bool("l", false, "show size, checksum and content type")
	fs.Usage = func() {
		write(opts.errOut(), "usage: jay ls [-r] [-l] jay://BUCKET[/PREFIX]\n\n")
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
		return fmt.Errorf("ls takes a %sBUCKET location, got a local path: %s", Scheme, loc.Path)
	}

	c, err := opts.dial()
	if err != nil {
		return err
	}
	defer closeClient(c, opts.errOut())

	delimiter := "/"
	if *recursive {
		delimiter = ""
	}

	var objects, bytes int64
	err = walkObjects(c, loc.Bucket, loc.Key, delimiter, func(page *client.ListResult) error {
		for _, p := range page.CommonPrefixes {
			printf(opts.out(), "%29s %s\n", "PRE", p)
		}
		for _, o := range page.Objects {
			objects++
			bytes += o.Size
			if *long {
				printf(opts.out(), "%s %10s  %s  %s  %s\n",
					o.LastModified, humanBytes(o.Size), shortChecksum(o.ChecksumSHA256), o.ContentType, o.Key)
				continue
			}
			printf(opts.out(), "%s %10s  %s\n", o.LastModified, humanBytes(o.Size), o.Key)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if objects > 0 {
		printf(opts.out(), "\n%d object(s), %s\n", objects, humanBytes(bytes))
	}
	return nil
}

// walkObjects pages through a listing, calling visit once per page. Paging is
// the caller's only correct option: ListObjects caps a response, and stopping
// at the first page would under-report every bucket over listPageSize keys.
func walkObjects(c *client.Client, bucket, prefix, delimiter string, visit func(*client.ListResult) error) error {
	startAfter := ""
	for {
		page, err := c.ListObjects(bucket, &client.ListOptions{
			Prefix:     prefix,
			Delimiter:  delimiter,
			StartAfter: startAfter,
			MaxKeys:    listPageSize,
		})
		if err != nil {
			return err
		}
		if err := visit(page); err != nil {
			return err
		}
		if !page.IsTruncated {
			return nil
		}
		next := page.NextStartAfter
		if next == "" || next == startAfter {
			// A truncated page with no usable cursor would loop forever;
			// reporting it beats spinning or silently returning a partial list.
			return fmt.Errorf("listing %s: server reported more results but no cursor after %q", bucket, startAfter)
		}
		startAfter = next
	}
}

// shortChecksum trims a SHA-256 to something scannable by eye. Full values are
// what sync compares; this column is for a human.
func shortChecksum(sum string) string {
	if len(sum) <= 12 {
		return sum
	}
	return sum[:12]
}

var byteUnits = []string{"B", "KiB", "MiB", "GiB", "TiB"}

// humanBytes formats a byte count for display only.
func humanBytes(n int64) string {
	if n < 1024 {
		return strconv.FormatInt(n, 10) + " B"
	}
	value := float64(n)
	unit := 0
	for value >= 1024 && unit < len(byteUnits)-1 {
		value /= 1024
		unit++
	}
	return strings.TrimSuffix(strconv.FormatFloat(value, 'f', 1, 64), ".0") + " " + byteUnits[unit]
}
