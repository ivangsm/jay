package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ivangsm/jay/internal/version"
)

// Options carries what every subcommand needs: where jay is, which token to
// use, and where to write. The caller resolves them from the same config
// pipeline the server uses (env > YAML > defaults) so the CLI never reads the
// environment behind bindings()' back.
type Options struct {
	Addr        string
	TokenID     string
	TokenSecret string

	Stdout io.Writer
	Stderr io.Writer

	// ctx bounds every network operation the command makes. Run installs one
	// that ends on SIGINT/SIGTERM, so Ctrl-C aborts an in-flight transfer
	// instead of waiting for the socket deadline; tests leave it nil and get
	// context.Background.
	ctx context.Context
}

func (o Options) context() context.Context {
	if o.ctx == nil {
		return context.Background()
	}
	return o.ctx
}

func (o Options) out() io.Writer {
	if o.Stdout == nil {
		return os.Stdout
	}
	return o.Stdout
}

func (o Options) errOut() io.Writer {
	if o.Stderr == nil {
		return os.Stderr
	}
	return o.Stderr
}

// commands is the dispatch table. It is also what IsCommand consults, so a new
// subcommand becomes reachable from the server binary by adding one entry.
var commands = map[string]func(Options, []string) error{
	"bucket":  runBucket,
	"ls":      runLs,
	"cp":      runCp,
	"rm":      runRm,
	"sync":    runSync,
	"version": runVersion,
}

// IsCommand reports whether arg should be handled by the client CLI. Anything
// that is not a flag counts, including a misspelling: dispatching only on
// known names meant `jay lss` fell through and booted a server instead of
// reporting the typo. `jay` with no arguments, or with only flags like
// --config-file, still starts the server — the container ENTRYPOINT needs it.
func IsCommand(arg string) bool {
	if arg == "-h" || arg == "--help" {
		return true
	}
	return !strings.HasPrefix(arg, "-")
}

// Run executes one subcommand and returns the process exit code. Errors are
// reported on stderr; a non-zero code means the work did not happen.
func Run(opts Options, args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		usage(opts.out())
		return 0
	}

	name := args[0]
	cmd, ok := commands[name]
	if !ok {
		printf(opts.errOut(), "jay: unknown command %q\n\n", name)
		usage(opts.errOut())
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	opts.ctx = ctx

	if err := cmd(opts, args[1:]); err != nil {
		if errors.Is(err, errUsage) {
			return 2
		}
		printf(opts.errOut(), "jay %s: %v\n", name, err)
		return 1
	}
	return 0
}

// errUsage marks an error whose message was already printed as usage text.
var errUsage = errors.New("usage")

func runVersion(opts Options, _ []string) error {
	printf(opts.out(), "jay %s (%s)\n", version.Version, version.Commit)
	return nil
}

func usage(w io.Writer) {
	write(w, `jay — S3-compatible object storage server and client.

Running the server:
  jay [--config-file path.yml]      Start the server (default with no subcommand)

Working with objects:
  jay ls jay://BUCKET[/PREFIX]      List objects
  jay cp SRC DST                    Copy a file to, from, or between buckets
  jay rm jay://BUCKET/KEY           Delete an object
  jay sync SRC DST                  Mirror a directory to or from a bucket
  jay bucket ls|mb|rb [NAME]        List, create or delete buckets
  jay version                       Print the build version

Locations are local paths or jay://BUCKET/KEY URIs.

Connection (flags override the environment):
  --addr HOST:PORT                  Native protocol address   (JAY_NATIVE_ADDR)
  --token-id ID                     Token ID                  (JAY_TOKEN_ID)
  --token-secret SECRET             Token secret              (JAY_TOKEN_SECRET)

Run 'jay COMMAND -h' for the flags of a single command.
`)
}
