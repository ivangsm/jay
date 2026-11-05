package main

import (
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ivangsm/jay/admin"
	"github.com/ivangsm/jay/api"
	"github.com/ivangsm/jay/internal/console"
	"github.com/ivangsm/jay/internal/version"
	"github.com/ivangsm/jay/meta"
)

// consoleSigningTTL is how long the URL the console mints for one proxied S3
// request stays valid. The request is dispatched in-process right after, so
// this only has to outlive a slow upload that starts verifying late.
const consoleSigningTTL = 60 * time.Second

// buildConsole wires the web console to the admin handler, the S3 handler and
// the metadata DB. Disabled, it still returns a handler: the one that says so.
func buildConsole(
	cfg Config, adminHandler *admin.Handler, s3 http.Handler, db *meta.DB,
	hc *HealthChecker, log *slog.Logger,
) (*console.Handler, error) {
	return console.New(console.Config{
		Enabled:    cfg.ConsoleEnabled,
		AdminAPI:   adminHandler,
		S3:         s3,
		AdminToken: cfg.AdminToken,
		Authenticate: func(r *http.Request, candidate string) console.LoginResult {
			switch adminHandler.AuthenticateAdminToken(r, candidate) {
			case admin.CredentialAccepted:
				return console.LoginAccepted
			case admin.CredentialLockedOut:
				return console.LoginLockedOut
			default:
				return console.LoginRejected
			}
		},
		SignS3: func(r *http.Request, tokenID string) error {
			return api.PresignRequest(r, cfg.SigningSecret, tokenID, consoleSigningTTL)
		},
		Tokens: db,
		Ready:  hc.IsReady,
		Info: console.Info{
			Version:       version.Version,
			Commit:        version.Commit,
			TLS:           cfg.TLSCert != "" && cfg.TLSKey != "",
			S3ListenAddr:  cfg.ListenAddr,
			MaxObjectSize: cfg.MaxObjectSize,
			Actions:       meta.AllActions,
		},
		Log: log,
	})
}

// consoleExposureWarning decides whether the console is being served in a way
// that sends the admin token across a network in the clear: enabled, no TLS,
// and an admin address that is empty or not loopback. It returns the "detail"
// to log.
func consoleExposureWarning(cfg Config) (string, bool) {
	if !cfg.ConsoleEnabled || (cfg.TLSCert != "" && cfg.TLSKey != "") {
		return "", false
	}
	host, _, err := net.SplitHostPort(cfg.AdminAddr)
	if err != nil {
		host = cfg.AdminAddr
	}
	if host == "localhost" {
		return "", false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return "", false
	}
	return "the admin token crosses the network in the clear at sign-in; bind JAY_ADMIN_ADDR to loopback, set JAY_TLS_CERT/JAY_TLS_KEY, or put a TLS proxy in front", true
}

// announceConsole logs the console's state at startup. Disabled, it says
// nothing: a console nobody asked for is not news.
func announceConsole(cfg Config, log *slog.Logger) {
	if !cfg.ConsoleEnabled {
		return
	}
	log.Info("web console enabled", "path", "/console/", "admin_addr", cfg.AdminAddr)
	if detail, warn := consoleExposureWarning(cfg); warn {
		log.Warn("web console served over plain HTTP on a non-loopback address",
			"admin_addr", cfg.AdminAddr, "detail", detail)
	}
}
