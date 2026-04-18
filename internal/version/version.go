// Package version holds build-time version information.
// Overridden at build time via ldflags:
//
//	go build -ldflags "-X github.com/ivangsm/jay/internal/version.Version=1.2.3 \
//	                   -X github.com/ivangsm/jay/internal/version.Commit=abc1234"
package version

var (
	// Version is the semantic version of the service.
	Version = "0.3.0"
	// Commit is the short git SHA baked in at build time.
	Commit = "dev"
)
