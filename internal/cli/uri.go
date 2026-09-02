// Package cli implements jay's client-side subcommands: bucket, ls, cp, rm and
// sync. They talk to a running jay over the native binary protocol, which is
// why they live in the server binary instead of a fourth executable — the
// image already ships it, and `jay` with no subcommand still starts the server.
package cli

import (
	"errors"
	"strings"
)

// Scheme prefixes a remote location: jay://bucket/key.
const Scheme = "jay://"

// Location is one side of a copy: either a local path or a remote object.
// Bucket and Key are only meaningful when Remote is true, and Path only when
// it is false.
type Location struct {
	Remote bool
	Bucket string
	Key    string
	Path   string
}

// ErrEmptyBucket is returned for a jay:// URI with no bucket name.
var ErrEmptyBucket = errors.New("jay:// URI needs a bucket name, e.g. jay://images/key")

// ParseLocation reads one command-line argument as a location. Anything that
// does not start with the jay:// scheme is a local path, including strings
// carrying some other scheme: guessing that "s3://x" means a remote object
// would silently talk to the wrong store.
func ParseLocation(s string) (Location, error) {
	if s == "" {
		return Location{}, errors.New("empty path")
	}
	if !strings.HasPrefix(s, Scheme) {
		return Location{Path: s}, nil
	}

	rest := strings.TrimPrefix(s, Scheme)
	bucket, key, _ := strings.Cut(rest, "/")
	if bucket == "" {
		return Location{}, ErrEmptyBucket
	}
	return Location{Remote: true, Bucket: bucket, Key: key}, nil
}

// String renders the location back into the form the user typed.
func (l Location) String() string {
	if !l.Remote {
		return l.Path
	}
	if l.Key == "" {
		return Scheme + l.Bucket
	}
	return Scheme + l.Bucket + "/" + l.Key
}

// DirPrefix turns a key into the prefix of the tree under it, which is what a
// recursive operation must list. Without the trailing slash, "assets" also
// matches "assets2/b.txt": on sync that pulls a stranger's files into the
// destination, and on rm -r it deletes them.
//
// An empty key stays empty — that is the whole bucket, not a directory.
func DirPrefix(key string) string {
	if key == "" || strings.HasSuffix(key, "/") {
		return key
	}
	return key + "/"
}
