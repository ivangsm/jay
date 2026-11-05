// Package console is the backend of jay's web console: a session layer, two
// in-process proxies (one to the admin API, one to the S3 handler) and the
// embedded single-page UI, all served from the admin listener under /console/.
//
// The console owns no authorization of its own. Admin calls carry the admin
// token the server injects; object calls are signed as a token the operator
// picks ("browse as"), so the S3 handler decides exactly what it would decide
// for any client. The package imports neither admin nor api: everything it
// needs from them arrives through Config, wired in cmd/jay.
package console

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ivangsm/jay/internal/accesslog"
	"github.com/ivangsm/jay/meta"
)

// LoginResult is the outcome of checking an admin token at sign-in.
type LoginResult int

const (
	// LoginAccepted means the candidate is the admin token.
	LoginAccepted LoginResult = iota
	// LoginRejected means it is not; the attempt was counted.
	LoginRejected
	// LoginLockedOut means the caller's address used up its failures.
	LoginLockedOut
)

// TokenSource is the slice of *meta.DB the S3 proxy reads to explain a refusal
// before the S3 handler makes it. *meta.DB satisfies it.
type TokenSource interface {
	GetToken(id string) (*meta.Token, error)
	GetAccount(id string) (*meta.Account, error)
}

// Info is what the UI is told about the server it talks to.
type Info struct {
	Version, Commit string
	TLS             bool // admin listener serves TLS: Secure + __Host- cookie
	S3ListenAddr    string
	MaxObjectSize   int64 // 0 = unlimited
	Actions         []string
}

// Config wires a Handler. With Enabled false nothing else is read.
type Config struct {
	Enabled bool
	// AdminAPI serves /_jay/*.
	AdminAPI http.Handler
	// S3 is the real S3 handler.
	S3 http.Handler
	// AdminToken is injected as the bearer on proxied admin calls.
	AdminToken string
	// Authenticate checks a login candidate against the admin token, sharing
	// the admin API's per-address backoff.
	Authenticate func(r *http.Request, candidate string) LoginResult
	// SignS3 authorizes r as tokenID for a short window.
	SignS3 func(r *http.Request, tokenID string) error
	Tokens TokenSource
	// Ready reports whether startup recovery has finished.
	Ready func() bool
	Info  Info
	Log   *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// Assets is the UI tree; nil means the embedded static/ tree.
	Assets fs.FS
}

// minAdminTokenLen mirrors the server's own floor for JAY_ADMIN_TOKEN.
const minAdminTokenLen = 32

// Handler serves everything under /console.
type Handler struct {
	enabled bool

	adminAPI     http.Handler
	s3           http.Handler
	adminToken   string
	authenticate func(r *http.Request, candidate string) LoginResult
	signS3       func(r *http.Request, tokenID string) error
	tokens       TokenSource
	ready        func() bool
	info         Info
	log          *slog.Logger
	now          func() time.Time

	sessions   *sessionStore
	cookieName string
	assets     assetSet
}

// New validates cfg. With Enabled false it needs nothing else and serves only
// the disabled answer. With Enabled true every field except Now and Assets is
// required (Info needs Version, S3ListenAddr and Actions), and AdminToken must
// be at least 32 bytes; a missing one is an error, never a console that half
// works.
func New(cfg Config) (*Handler, error) {
	if !cfg.Enabled {
		return &Handler{}, nil
	}
	var missing []string
	if cfg.AdminAPI == nil {
		missing = append(missing, "AdminAPI")
	}
	if cfg.S3 == nil {
		missing = append(missing, "S3")
	}
	if cfg.Authenticate == nil {
		missing = append(missing, "Authenticate")
	}
	if cfg.SignS3 == nil {
		missing = append(missing, "SignS3")
	}
	if cfg.Tokens == nil {
		missing = append(missing, "Tokens")
	}
	if cfg.Ready == nil {
		missing = append(missing, "Ready")
	}
	if cfg.Log == nil {
		missing = append(missing, "Log")
	}
	if cfg.Info.Version == "" {
		missing = append(missing, "Info.Version")
	}
	if cfg.Info.S3ListenAddr == "" {
		missing = append(missing, "Info.S3ListenAddr")
	}
	if len(cfg.Info.Actions) == 0 {
		missing = append(missing, "Info.Actions")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("console: missing required config: %s", strings.Join(missing, ", "))
	}
	if len(cfg.AdminToken) < minAdminTokenLen {
		return nil, errors.New("console: AdminToken must be at least 32 bytes")
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	assetsFS := cfg.Assets
	if assetsFS == nil {
		var err error
		assetsFS, err = embeddedAssets()
		if err != nil {
			return nil, err
		}
	}
	assets, err := loadAssets(assetsFS, cfg.Info.Version)
	if err != nil {
		return nil, err
	}

	name := cookieName
	if cfg.Info.TLS {
		name = cookieNameHost
	}
	return &Handler{
		enabled:      true,
		adminAPI:     cfg.AdminAPI,
		s3:           cfg.S3,
		adminToken:   cfg.AdminToken,
		authenticate: cfg.Authenticate,
		signS3:       cfg.SignS3,
		tokens:       cfg.Tokens,
		ready:        cfg.Ready,
		info:         cfg.Info,
		log:          cfg.Log,
		now:          now,
		sessions:     newSessionStore(),
		cookieName:   name,
		assets:       assets,
	}, nil
}

const (
	pathConsole = "/console"
	pathRoot    = "/console/"
	pathStatic  = "/console/static/"
	pathAPI     = "/console/api/"
	pathSession = "/console/api/session"
	pathAdmin   = "/console/api/admin/"
	pathS3      = "/console/api/s3"
)

// ServeHTTP routes a request under /console.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setCommonHeaders(w.Header())
	if !h.enabled {
		serveDisabled(w, r)
		return
	}

	p := r.URL.Path
	if strings.HasPrefix(p, pathAPI) {
		// Every API call, login included, passes the browser's own
		// cross-site signals before anything else looks at it.
		if !checkFetchMetadata(r) || !checkOrigin(r) {
			refuseCrossSite(w)
			return
		}
		if !strings.HasPrefix(p, pathS3+"/") {
			w.Header().Set("Content-Security-Policy", cspLocked)
			w.Header().Set("Cache-Control", "no-store")
		}
	}

	switch {
	case p == pathConsole:
		if !safeMethod(r.Method) {
			methodNotAllowed(w, "GET, HEAD")
			return
		}
		http.Redirect(w, r, pathRoot, http.StatusMovedPermanently)
	case p == pathRoot:
		h.serveIndex(w, r)
	case strings.HasPrefix(p, pathStatic):
		h.serveAsset(w, r)
	case p == pathSession:
		h.serveSession(w, r)
	case strings.HasPrefix(p, pathAdmin):
		h.serveAdminProxy(w, r)
	case strings.HasPrefix(p, pathS3+"/"):
		h.serveS3Proxy(w, r)
	default:
		writeJSONError(w, http.StatusNotFound, "not found")
	}
}

// RootRedirect answers exactly "/" with 302 -> /console/. Mount it only when
// enabled: a disabled console leaves "/" a 404, as it always was.
func (h *Handler) RootRedirect() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.enabled || r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, pathRoot, http.StatusFound)
	})
}

// audit writes the trail line of a console operation. The shape matches the
// admin listener's audit lines (request_id, action, remote_ip first) so one
// grep finds both.
func (h *Handler) audit(r *http.Request, action string, attrs ...slog.Attr) {
	line := make([]slog.Attr, 0, 3+len(attrs))
	line = append(line,
		slog.String("request_id", accesslog.RequestID(r.Context())),
		slog.String("action", action),
		slog.String("remote_ip", accesslog.PeerIP(r)),
	)
	h.log.LogAttrs(r.Context(), slog.LevelInfo, "audit", append(line, attrs...)...)
}
