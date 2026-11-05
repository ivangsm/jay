package main

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/ivangsm/jay/internal/version"
	"github.com/ivangsm/jay/maintenance"
)

// checkMetricsAccess refuses a GET /metrics configuration that grants more
// than it says, before anything opens or binds.
//
//   - metrics.public together with metrics.token is two opposite answers to
//     "who may scrape"; picking either would be a guess about an access
//     control setting, so the boot stops and asks.
//   - The metrics token is a secret and follows JAY_ADMIN_TOKEN's floor: no
//     default, at least minSecretLen bytes when set.
//   - A metrics token equal to the admin token IS the admin token: every
//     scraper that holds it can mint credentials, which is the one thing the
//     metrics token exists to avoid.
func checkMetricsAccess(cfg Config) error {
	switch {
	case cfg.MetricsPublic && cfg.MetricsToken != "":
		return errors.New("metrics.public (JAY_METRICS_PUBLIC) and metrics.token (JAY_METRICS_TOKEN) " +
			"are mutually exclusive: set the token to require it, or public to require nothing")
	case cfg.MetricsToken == "":
		return nil
	case len(cfg.MetricsToken) < minSecretLen:
		return fmt.Errorf("JAY_METRICS_TOKEN (or metrics.token in YAML) must be at least %d chars when set", minSecretLen)
	case cfg.MetricsToken == cfg.AdminToken:
		return errors.New("JAY_METRICS_TOKEN must differ from JAY_ADMIN_TOKEN: " +
			"a scraper holding the admin token can mint credentials")
	}
	return nil
}

// announceMetricsAccess says at startup who can read GET /metrics — but only
// when the answer is "anyone". The other two cases are the safe ones and would
// be one more line per boot that teaches people to skip the startup log.
func announceMetricsAccess(cfg Config, log *slog.Logger) {
	if !cfg.MetricsPublic {
		return
	}
	log.Warn("metrics endpoint serves without authentication",
		"path", "/metrics",
		"admin_addr", cfg.AdminAddr,
		"detail", "JAY_METRICS_PUBLIC is true: anyone who can reach the admin listener can scrape it; "+
			"keep that listener on a private network, or set JAY_METRICS_TOKEN instead")
}

// buildInfoFamily is jay_build_info: always 1, carrying the version and commit
// as labels. It is the Prometheus-side answer to "which binary is running",
// which otherwise only the startup log line knows.
func buildInfoFamily() maintenance.MetricFamily {
	return maintenance.MetricFamily{
		Name: "jay_build_info",
		Help: "Always 1. The labels name the running build.",
		Type: maintenance.GaugeType,
		Samples: []maintenance.Sample{{
			Labels: []maintenance.Label{
				{Name: "version", Value: version.Version},
				{Name: "commit", Value: version.Commit},
			},
			Value: 1,
		}},
	}
}
