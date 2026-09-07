package main

import (
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// envVarPattern matches ${VAR} and ${VAR:-default} occurrences in a string.
// Group 1 = VAR name; group 2 = ":-default" suffix (optional, including the
// `:-` literal); group 3 = the default value (empty if no `:-default`).
var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}`)

// yamlKeyMapping is the canonical ordered list of flat-path → env var →
// setter. The flat path matches what ReadYAMLFile returns (snake_case,
// dotted for nested namespaces). The setter mutates a Config directly.
//
// Keeping everything in one table avoids duplicating knowledge between the
// YAML overlay, the env overlay, and the conflict-detection step.
type yamlKeyBinding struct {
	path   string // e.g. "scrub.interval_hours"
	envVar string // e.g. "JAY_SCRUB_INTERVAL_HOURS"
	// applyYAML applies the YAML value (already interpolated for strings) to
	// cfg. Returns the canonical string form used for conflict logging when a
	// non-empty YAML value is later overridden by the env var.
	applyYAML func(cfg *Config, raw any, log *slog.Logger) (string, bool, error)
	// applyEnv applies the env var value to cfg. Returns true if the env var
	// was set (regardless of parse success).
	applyEnv func(cfg *Config, value string, log *slog.Logger) bool
	// emptyIsValue marks a key whose empty value is a setting, not an absence.
	// See emptyMeansUnset for why it defaults to false.
	emptyIsValue bool
}

// withEmptyAsValue marks a binding whose empty value MEANS something, so the
// overlays apply it instead of falling back to the default.
//
// Only native_addr carries it. An empty JAY_NATIVE_ADDR is the documented off
// switch for the native protocol (main.go binds no listener when it is empty),
// and before this flag existed only the YAML door honoured it: the env var was
// discarded as "unset" and the listener came up on the :4444 default, so a
// deployment that believed it had turned the native protocol off had the port
// open — with a protocol that carries the token secret in the clear and is not
// meant to face the internet.
func withEmptyAsValue(b yamlKeyBinding) yamlKeyBinding {
	b.emptyIsValue = true
	return b
}

// emptyMeansUnset reports whether an empty value for this binding must be
// ignored, leaving the default (or an earlier layer) in place.
//
// The default answer is yes, for every key but the one above, and that is a
// deliberate refusal to make "empty" mean "empty" everywhere. Config arrives
// through templates that produce an empty string for an unset variable —
// `JAY_LISTEN_ADDR: ${JAY_LISTEN_ADDR}` in a compose file, `${VAR}` inside the
// YAML — so an empty value is nearly always "nobody configured this", not a
// choice. Honouring it literally would make an unset variable move the store
// (data_dir "") or serve on port 80 (net/http reads an empty Addr as ":http"),
// and would turn an empty numeric variable into an "invalid JAY_*" error line
// on every boot.
//
// The rule is applied identically to the YAML overlay and the env overlay. An
// asymmetry there is not a fix, it is the same defect through the other door.
func emptyMeansUnset(b yamlKeyBinding) bool { return !b.emptyIsValue }

// LoadConfigFromSources loads config from a YAML file (optional) merged with
// env vars. Precedence: env vars > YAML > defaults. If yamlPath == "", the
// YAML step is skipped and the result is equivalent to the legacy env-only
// behaviour.
//
// A slog.Warn is emitted for every detected conflict where the YAML provides
// a non-empty value and the env var also provides a (different) non-empty
// value that overrides it.
func LoadConfigFromSources(yamlPath string, log *slog.Logger) (Config, error) {
	if log == nil {
		log = slog.Default()
	}

	// 1. Start with defaults (matches legacy LoadConfig).
	cfg := defaultConfig()

	// 2. Overlay YAML values (if a path was provided).
	var yamlMap map[string]any
	if yamlPath != "" {
		parsed, err := ReadYAMLFile(yamlPath)
		if err != nil {
			return Config{}, fmt.Errorf("read yaml config: %w", err)
		}
		yamlMap = parsed
		if err := applyYAMLOverlay(&cfg, yamlMap, log); err != nil {
			return Config{}, err
		}
	}

	// 3. Overlay env var values, warning when they override a non-empty YAML
	//    value.
	applyEnvOverlay(&cfg, yamlMap, log)

	// 4. Resolve derived defaults. BackupDir defaults to <DataDir>/backups,
	//    which must be computed AFTER overlays so an overridden DataDir moves
	//    the default backup location with it.
	if cfg.BackupDir == "" {
		cfg.BackupDir = filepath.Join(cfg.DataDir, "backups")
	}

	return cfg, nil
}

// defaultConfig returns the baseline Config the monorepo ships with. All
// secrets start empty — validation of their presence/length happens in
// main() after LoadConfigFromSources returns.
func defaultConfig() Config {
	return Config{
		DataDir:          "./data",
		ListenAddr:       ":9000",
		AdminAddr:        ":9001",
		NativeAddr:       ":4444",
		LogLevel:         "info",
		RateLimit:        100,
		RateBurst:        200,
		ScrubInterval:    6 * time.Hour,
		ScrubBytesPerSec: int64(50 << 20),
		ScrubMaxPerRun:   100,
		// BackupDir is left empty here; LoadConfigFromSources resolves it to
		// <DataDir>/backups after all overlays are applied.
		MinFreeBytes:  int64(500 << 20), // 500 MiB
		MaxObjectSize: int64(5 << 30),   // 5 GiB
	}
}

// bindings returns the canonical list of YAML/env bindings. It's a function
// (not a package-level var) because it captures helper closures over Config
// fields — keeping it local means the compiler catches field renames.
func bindings() []yamlKeyBinding {
	return []yamlKeyBinding{
		bindString("data_dir", "JAY_DATA_DIR", func(c *Config) *string { return &c.DataDir }),
		bindString("listen_addr", "JAY_LISTEN_ADDR", func(c *Config) *string { return &c.ListenAddr }),
		bindString("admin_addr", "JAY_ADMIN_ADDR", func(c *Config) *string { return &c.AdminAddr }),
		// Empty disables the native listener — from YAML and from the
		// environment alike. See withEmptyAsValue.
		withEmptyAsValue(bindString("native_addr", "JAY_NATIVE_ADDR", func(c *Config) *string { return &c.NativeAddr })),
		bindString("admin_token", "JAY_ADMIN_TOKEN", func(c *Config) *string { return &c.AdminToken }),
		bindString("signing_secret", "JAY_SIGNING_SECRET", func(c *Config) *string { return &c.SigningSecret }),
		bindString("log_level", "JAY_LOG_LEVEL", func(c *Config) *string { return &c.LogLevel }),
		bindString("tls_cert", "JAY_TLS_CERT", func(c *Config) *string { return &c.TLSCert }),
		bindString("tls_key", "JAY_TLS_KEY", func(c *Config) *string { return &c.TLSKey }),
		bindString("native_tls_cert", "JAY_NATIVE_TLS_CERT", func(c *Config) *string { return &c.NativeTLSCert }),
		bindString("native_tls_key", "JAY_NATIVE_TLS_KEY", func(c *Config) *string { return &c.NativeTLSKey }),
		bindFloat("rate_limit", "JAY_RATE_LIMIT", func(c *Config) *float64 { return &c.RateLimit }),
		bindPositiveInt("rate_burst", "JAY_RATE_BURST", func(c *Config) *int { return &c.RateBurst }),
		bindBool("trust_proxy_headers", "JAY_TRUST_PROXY_HEADERS", func(c *Config) *bool { return &c.TrustProxyHeaders }),

		bindScrubIntervalHours(),
		bindScrubBytesPerSec(),
		bindScrubMaxPerRun(),

		bindString("backup.dir", "JAY_BACKUP_DIR", func(c *Config) *string { return &c.BackupDir }),
		bindMinFreeBytes(),
		bindMaxObjectSize(),

		bindString("seed_token.account", "JAY_SEED_TOKEN_ACCOUNT", func(c *Config) *string { return &c.SeedTokenAccount }),
		bindString("seed_token.id", "JAY_SEED_TOKEN_ID", func(c *Config) *string { return &c.SeedTokenID }),
		bindString("seed_token.secret", "JAY_SEED_TOKEN_SECRET", func(c *Config) *string { return &c.SeedTokenSecret }),

		bindString("client.token_id", "JAY_TOKEN_ID", func(c *Config) *string { return &c.ClientTokenID }),
		bindString("client.token_secret", "JAY_TOKEN_SECRET", func(c *Config) *string { return &c.ClientTokenSecret }),
	}
}

func applyYAMLOverlay(cfg *Config, yamlMap map[string]any, log *slog.Logger) error {
	for _, b := range bindings() {
		raw, ok := yamlMap[b.path]
		if !ok {
			continue
		}
		// `key:` with no value and `key: ""` are the same statement; both
		// reach the binding as an empty string when the key admits one.
		if isEmptyYAMLValue(raw) {
			if emptyMeansUnset(b) {
				reportIgnoredEmpty(b, cfg, log, "config: empty YAML value ignored, key treated as unset",
					"key", b.path)
				continue
			}
			raw = ""
		}
		if _, _, err := b.applyYAML(cfg, raw, log); err != nil {
			return fmt.Errorf("yaml key %q: %w", b.path, err)
		}
	}
	return nil
}

// isEmptyYAMLValue reports whether a decoded YAML value carries nothing: an
// explicit empty string, or a key written with no value at all.
func isEmptyYAMLValue(raw any) bool {
	if raw == nil {
		return true
	}
	s, ok := raw.(string)
	return ok && s == ""
}

// discardLog swallows what a probing call would otherwise print.
var discardLog = slog.New(slog.DiscardHandler)

// reportIgnoredEmpty logs msg only when dropping the empty value actually
// decided something — that is, when the value in place is not already the
// empty one.
//
// The silent half matters as much as the loud half: the config file this repo
// documents is written as `tls_cert: ${JAY_TLS_CERT:-}`, `backup.dir:
// ${JAY_BACKUP_DIR:-}`, `seed_token.*`, `client.*` — keys that interpolate to
// an empty string on every ordinary boot and whose default is empty anyway.
// Warning about those would put seven lines of noise in front of every
// operator until they learned to skip config warnings, which is how the one
// that matters (`listen_addr: ${JAY_LISTEN_ADDR}` with the variable unset,
// silently keeping :9000) gets skipped too.
func reportIgnoredEmpty(b yamlKeyBinding, cfg *Config, log *slog.Logger, msg string, args ...any) {
	if !applyingEmptyWouldChange(b, cfg) {
		return
	}
	log.Warn(msg, args...)
}

// applyingEmptyWouldChange reports whether an empty value would move the
// config away from what it holds right now. A binding that cannot represent an
// empty value at all (every number and bool) answers yes: the key was written
// and will do nothing, which is worth one line.
func applyingEmptyWouldChange(b yamlKeyBinding, cfg *Config) bool {
	probe := *cfg
	if _, _, err := b.applyYAML(&probe, "", discardLog); err != nil {
		return true
	}
	return probe != *cfg
}

func applyEnvOverlay(cfg *Config, yamlMap map[string]any, log *slog.Logger) {
	for _, b := range bindings() {
		v, ok := os.LookupEnv(b.envVar)
		if !ok {
			continue
		}
		if v == "" && emptyMeansUnset(b) {
			// Same rule as the YAML overlay, and reported the same way: the
			// two doors must not disagree about what an empty value means.
			reportIgnoredEmpty(b, cfg, log, "config: empty env var ignored, treated as unset",
				"key", b.path, "env_var", b.envVar)
			continue
		}
		// Detect conflict: YAML had a non-empty value for this key.
		if yamlMap != nil {
			if yamlRaw, had := yamlMap[b.path]; had {
				yamlStr := stringify(yamlRaw)
				if yamlStr != "" && yamlStr != v {
					log.Warn(
						"config: env var overrides YAML value",
						"key", b.path,
						"env_var", b.envVar,
						"yaml_value", yamlStr,
						"env_value", v,
					)
				}
			}
		}
		b.applyEnv(cfg, v, log)
	}
}

// --- Helpers: string bindings ------------------------------------------------

func bindString(path, env string, ptr func(*Config) *string) yamlKeyBinding {
	return yamlKeyBinding{
		path:   path,
		envVar: env,
		applyYAML: func(cfg *Config, raw any, log *slog.Logger) (string, bool, error) {
			s, ok := raw.(string)
			if !ok {
				return "", false, fmt.Errorf("expected string, got %T", raw)
			}
			*ptr(cfg) = s
			return s, s != "", nil
		},
		applyEnv: func(cfg *Config, value string, _ *slog.Logger) bool {
			*ptr(cfg) = value
			return true
		},
	}
}

func bindFloat(path, env string, ptr func(*Config) *float64) yamlKeyBinding {
	return yamlKeyBinding{
		path:   path,
		envVar: env,
		applyYAML: func(cfg *Config, raw any, log *slog.Logger) (string, bool, error) {
			f, err := toFloat64(raw)
			if err != nil {
				return "", false, err
			}
			*ptr(cfg) = f
			return strconv.FormatFloat(f, 'f', -1, 64), true, nil
		},
		applyEnv: func(cfg *Config, value string, log *slog.Logger) bool {
			parsed, err := strconv.ParseFloat(value, 64)
			if err != nil {
				log.Error("invalid "+env+", keeping previous value", "value", value, "err", err)
				return true
			}
			*ptr(cfg) = parsed
			return true
		},
	}
}

// bindPositiveInt binds an int key that has no meaning at or below zero.
//
// The range check is not decoration. Its only user is rate_burst, and
// `rate.NewLimiter` with a burst of zero or less rejects EVERY request: a
// `rate_burst: -1` typo used to be accepted in silence and turned the rate
// limiter into a total outage. The upper bound exists because `int` is not
// int64 on every platform, so the YAML value has to be proven to fit before
// the conversion rather than after it.
func bindPositiveInt(path, env string, ptr func(*Config) *int) yamlKeyBinding {
	return yamlKeyBinding{
		path:   path,
		envVar: env,
		applyYAML: func(cfg *Config, raw any, log *slog.Logger) (string, bool, error) {
			n, err := toInt64(raw)
			if err != nil {
				return "", false, err
			}
			if n <= 0 || n > math.MaxInt32 {
				return "", false, fmt.Errorf("must be between 1 and %d, got %d", math.MaxInt32, n)
			}
			*ptr(cfg) = int(n)
			return strconv.FormatInt(n, 10), true, nil
		},
		applyEnv: func(cfg *Config, value string, log *slog.Logger) bool {
			parsed, err := strconv.ParseInt(value, 10, 32)
			if err != nil || parsed <= 0 {
				log.Error("invalid "+env+", keeping previous value", "value", value, "err", err)
				return true
			}
			*ptr(cfg) = int(parsed)
			return true
		},
	}
}

func bindBool(path, env string, ptr func(*Config) *bool) yamlKeyBinding {
	return yamlKeyBinding{
		path:   path,
		envVar: env,
		applyYAML: func(cfg *Config, raw any, log *slog.Logger) (string, bool, error) {
			b, err := toBool(raw)
			if err != nil {
				return "", false, err
			}
			*ptr(cfg) = b
			return strconv.FormatBool(b), true, nil
		},
		applyEnv: func(cfg *Config, value string, _ *slog.Logger) bool {
			// Match parseBoolEnv semantics: only "1"/"true" variants are true.
			switch value {
			case "1", "true", "TRUE", "True":
				*ptr(cfg) = true
			default:
				*ptr(cfg) = false
			}
			return true
		},
	}
}

// --- Helpers: scrub-specific bindings (extra validation) ---------------------

func bindScrubIntervalHours() yamlKeyBinding {
	const env = "JAY_SCRUB_INTERVAL_HOURS"
	return yamlKeyBinding{
		path:   "scrub.interval_hours",
		envVar: env,
		applyYAML: func(cfg *Config, raw any, log *slog.Logger) (string, bool, error) {
			n, err := toInt64(raw)
			if err != nil {
				return "", false, err
			}
			if n <= 0 {
				log.Error("invalid scrub.interval_hours in YAML (must be > 0), ignoring", "value", n)
				return "", false, nil
			}
			cfg.ScrubInterval = time.Duration(n) * time.Hour
			return strconv.FormatInt(n, 10), true, nil
		},
		applyEnv: func(cfg *Config, value string, log *slog.Logger) bool {
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed <= 0 {
				log.Error("invalid "+env+", keeping previous value", "value", value, "err", err)
				return true
			}
			cfg.ScrubInterval = time.Duration(parsed) * time.Hour
			return true
		},
	}
}

func bindScrubBytesPerSec() yamlKeyBinding {
	const env = "JAY_SCRUB_BYTES_PER_SEC"
	return yamlKeyBinding{
		path:   "scrub.bytes_per_sec",
		envVar: env,
		applyYAML: func(cfg *Config, raw any, log *slog.Logger) (string, bool, error) {
			n, err := toInt64(raw)
			if err != nil {
				return "", false, err
			}
			cfg.ScrubBytesPerSec = n
			return strconv.FormatInt(n, 10), true, nil
		},
		applyEnv: func(cfg *Config, value string, log *slog.Logger) bool {
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				log.Error("invalid "+env+", keeping previous value", "value", value, "err", err)
				return true
			}
			cfg.ScrubBytesPerSec = parsed
			return true
		},
	}
}

func bindScrubMaxPerRun() yamlKeyBinding {
	const env = "JAY_SCRUB_MAX_PER_RUN"
	return yamlKeyBinding{
		path:   "scrub.max_per_run",
		envVar: env,
		applyYAML: func(cfg *Config, raw any, log *slog.Logger) (string, bool, error) {
			n, err := toInt64(raw)
			if err != nil {
				return "", false, err
			}
			if n <= 0 || n > math.MaxInt32 {
				log.Error("invalid scrub.max_per_run in YAML (must be between 1 and 2147483647), ignoring", "value", n)
				return "", false, nil
			}
			cfg.ScrubMaxPerRun = int(n)
			return strconv.FormatInt(n, 10), true, nil
		},
		applyEnv: func(cfg *Config, value string, log *slog.Logger) bool {
			parsed, err := strconv.ParseInt(value, 10, 32)
			if err != nil || parsed <= 0 {
				log.Error("invalid "+env+", keeping previous value", "value", value, "err", err)
				return true
			}
			cfg.ScrubMaxPerRun = int(parsed)
			return true
		},
	}
}

func bindMinFreeBytes() yamlKeyBinding {
	const env = "JAY_MIN_FREE_BYTES"
	return yamlKeyBinding{
		path:   "min_free_bytes",
		envVar: env,
		applyYAML: func(cfg *Config, raw any, log *slog.Logger) (string, bool, error) {
			n, err := toInt64(raw)
			if err != nil {
				return "", false, err
			}
			if n < 0 {
				log.Error("invalid min_free_bytes in YAML (must be >= 0), ignoring", "value", n)
				return "", false, nil
			}
			cfg.MinFreeBytes = n
			return strconv.FormatInt(n, 10), true, nil
		},
		applyEnv: func(cfg *Config, value string, log *slog.Logger) bool {
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed < 0 {
				log.Error("invalid "+env+" (must be >= 0), keeping previous value", "value", value, "err", err)
				return true
			}
			cfg.MinFreeBytes = parsed
			return true
		},
	}
}

// bindMaxObjectSize binds the maximum accepted object size (in bytes). 0 means
// unlimited; negative values are invalid and are ignored (previous value kept).
func bindMaxObjectSize() yamlKeyBinding {
	const env = "JAY_MAX_OBJECT_SIZE"
	return yamlKeyBinding{
		path:   "max_object_size",
		envVar: env,
		applyYAML: func(cfg *Config, raw any, log *slog.Logger) (string, bool, error) {
			n, err := toInt64(raw)
			if err != nil {
				return "", false, err
			}
			if n < 0 {
				log.Error("invalid max_object_size in YAML (must be >= 0), ignoring", "value", n)
				return "", false, nil
			}
			cfg.MaxObjectSize = n
			return strconv.FormatInt(n, 10), true, nil
		},
		applyEnv: func(cfg *Config, value string, log *slog.Logger) bool {
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed < 0 {
				log.Error("invalid "+env+" (must be >= 0), keeping previous value", "value", value, "err", err)
				return true
			}
			cfg.MaxObjectSize = parsed
			return true
		},
	}
}

// --- YAML reading ------------------------------------------------------------

// ReadYAMLFile reads and parses a YAML file, performing ${VAR} and
// ${VAR:-default} interpolation on string values using os.Getenv. Returns a
// flat map keyed by snake_case paths (e.g. "scrub.interval_hours"); nested
// namespaces are flattened with a single dot.
func ReadYAMLFile(path string) (map[string]any, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(bytes, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if raw == nil {
		return map[string]any{}, nil
	}
	flat := map[string]any{}
	if err := flatten("", raw, flat); err != nil {
		return nil, fmt.Errorf("flatten %s: %w", path, err)
	}
	return flat, nil
}

// flatten walks a nested YAML map and writes leaf values into dst keyed by
// dotted paths. String values are interpolated against env vars.
func flatten(prefix string, src map[string]any, dst map[string]any) error {
	for k, v := range src {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch t := v.(type) {
		case map[string]any:
			if err := flatten(key, t, dst); err != nil {
				return err
			}
		case map[any]any:
			// yaml.v3 shouldn't produce this for string keys, but handle it
			// defensively in case a future map type leaks through.
			converted := map[string]any{}
			for kk, vv := range t {
				ks, ok := kk.(string)
				if !ok {
					return fmt.Errorf("non-string key in YAML map under %q: %v", key, kk)
				}
				converted[ks] = vv
			}
			if err := flatten(key, converted, dst); err != nil {
				return err
			}
		case string:
			dst[key] = InterpolateEnvVars(t)
		default:
			dst[key] = v
		}
	}
	return nil
}

// InterpolateEnvVars substitutes ${VAR} and ${VAR:-default} in a string.
//
//	${VAR}           → os.Getenv("VAR"), or "" if not set
//	${VAR:-default}  → os.Getenv("VAR") if set, else "default"
//
// Any literal text is preserved as-is. Multiple substitutions per string are
// supported.
func InterpolateEnvVars(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		groups := envVarPattern.FindStringSubmatch(match)
		// groups: [whole, VAR, ":-default" (or ""), default]
		name := groups[1]
		hasDefault := groups[2] != ""
		defaultVal := groups[3]
		v, present := os.LookupEnv(name)
		if present {
			return v
		}
		if hasDefault {
			return defaultVal
		}
		return ""
	})
}

// --- YAML value coercion -----------------------------------------------------

func toFloat64(raw any) (float64, error) {
	switch v := raw.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("expected number, got %T", raw)
	}
}

func toInt64(raw any) (int64, error) {
	switch v := raw.(type) {
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case float64:
		// Accept whole floats ("100") but reject fractional.
		if v != float64(int64(v)) {
			return 0, fmt.Errorf("expected integer, got fractional %v", v)
		}
		return int64(v), nil
	case string:
		return strconv.ParseInt(v, 10, 64)
	default:
		return 0, fmt.Errorf("expected integer, got %T", raw)
	}
}

func toBool(raw any) (bool, error) {
	switch v := raw.(type) {
	case bool:
		return v, nil
	case string:
		return strconv.ParseBool(v)
	default:
		return false, fmt.Errorf("expected bool, got %T", raw)
	}
}

// stringify returns the canonical string form of a YAML value, used for
// conflict logging. It must match the formats produced by the binding
// functions so "true" from YAML compares correctly against "true" from env.
func stringify(raw any) string {
	switch v := raw.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case int:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}
