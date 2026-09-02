package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/ivangsm/jay/proto/client"
)

// defaultNativeAddr matches the server's own default listen address.
const defaultNativeAddr = "localhost:4444"

// poolSize is the client connection pool. Uploads and downloads run
// concurrently in cp -r and sync, and each in-flight transfer holds one
// connection for the duration of its body.
const poolSize = 8

// errNoCredentials is returned when no token is configured. The CLI refuses to
// run rather than falling back to an anonymous connection: a command that
// quietly does nothing is worse than one that fails.
var errNoCredentials = errors.New(
	"no credentials: set JAY_TOKEN_ID and JAY_TOKEN_SECRET (or client.token_id / client.token_secret in the YAML config), or pass --token-id and --token-secret")

// bindConnFlags registers the connection flags on fs, defaulting to opts.
// Every subcommand accepts them so a one-off endpoint does not require
// exporting environment variables.
func bindConnFlags(fs *flag.FlagSet, opts *Options) {
	fs.StringVar(&opts.Addr, "addr", opts.Addr, "native protocol address (host:port)")
	fs.StringVar(&opts.TokenID, "token-id", opts.TokenID, "token ID")
	fs.StringVar(&opts.TokenSecret, "token-secret", opts.TokenSecret, "token secret")
}

// newFlagSet builds a FlagSet that reports usage errors through the command's
// own stderr instead of the process-wide default.
func newFlagSet(name string, opts Options) *flag.FlagSet {
	fs := flag.NewFlagSet("jay "+name, flag.ContinueOnError)
	fs.SetOutput(opts.errOut())
	return fs
}

// dial opens a pooled connection to the native protocol.
func (o Options) dial() (*client.Client, error) {
	if o.TokenID == "" || o.TokenSecret == "" {
		return nil, errNoCredentials
	}
	addr := normalizeAddr(o.Addr)
	c, err := client.Dial(addr, o.TokenID, o.TokenSecret, poolSize)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	return c, nil
}

// normalizeAddr turns a listen address into a dial address. JAY_NATIVE_ADDR is
// written from the server's point of view (":4444"), and dialing that verbatim
// fails, so a bare port is completed with localhost.
func normalizeAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	switch {
	case addr == "":
		return defaultNativeAddr
	case strings.HasPrefix(addr, ":"):
		return "localhost" + addr
	default:
		return addr
	}
}

// closeClient reports a close failure without masking the command's own error.
func closeClient(c *client.Client, w io.Writer) {
	if err := c.Close(); err != nil {
		printf(w, "jay: closing connection: %v\n", err)
	}
}
