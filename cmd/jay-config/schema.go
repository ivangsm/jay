package main

type fieldType int

const (
	typeString fieldType = iota
	typeInt
	typeFloat
	typeBool
)

type fieldSpec struct {
	yamlKey  string
	yamlPath []string
	envKey   string
	kind     fieldType
}

var fieldSpecs = []fieldSpec{
	{yamlKey: "data_dir", yamlPath: []string{"data_dir"}, envKey: "JAY_DATA_DIR", kind: typeString},
	{yamlKey: "listen_addr", yamlPath: []string{"listen_addr"}, envKey: "JAY_LISTEN_ADDR", kind: typeString},
	{yamlKey: "admin_addr", yamlPath: []string{"admin_addr"}, envKey: "JAY_ADMIN_ADDR", kind: typeString},
	{yamlKey: "native_addr", yamlPath: []string{"native_addr"}, envKey: "JAY_NATIVE_ADDR", kind: typeString},
	{yamlKey: "admin_token", yamlPath: []string{"admin_token"}, envKey: "JAY_ADMIN_TOKEN", kind: typeString},
	{yamlKey: "signing_secret", yamlPath: []string{"signing_secret"}, envKey: "JAY_SIGNING_SECRET", kind: typeString},
	{yamlKey: "log_level", yamlPath: []string{"log_level"}, envKey: "JAY_LOG_LEVEL", kind: typeString},
	{yamlKey: "tls_cert", yamlPath: []string{"tls_cert"}, envKey: "JAY_TLS_CERT", kind: typeString},
	{yamlKey: "tls_key", yamlPath: []string{"tls_key"}, envKey: "JAY_TLS_KEY", kind: typeString},
	{yamlKey: "rate_limit", yamlPath: []string{"rate_limit"}, envKey: "JAY_RATE_LIMIT", kind: typeFloat},
	{yamlKey: "rate_burst", yamlPath: []string{"rate_burst"}, envKey: "JAY_RATE_BURST", kind: typeInt},
	{yamlKey: "trust_proxy_headers", yamlPath: []string{"trust_proxy_headers"}, envKey: "JAY_TRUST_PROXY_HEADERS", kind: typeBool},

	{yamlKey: "scrub.interval_hours", yamlPath: []string{"scrub", "interval_hours"}, envKey: "JAY_SCRUB_INTERVAL_HOURS", kind: typeInt},
	{yamlKey: "scrub.sample_rate", yamlPath: []string{"scrub", "sample_rate"}, envKey: "JAY_SCRUB_SAMPLE_RATE", kind: typeFloat},
	{yamlKey: "scrub.bytes_per_sec", yamlPath: []string{"scrub", "bytes_per_sec"}, envKey: "JAY_SCRUB_BYTES_PER_SEC", kind: typeInt},
	{yamlKey: "scrub.max_per_run", yamlPath: []string{"scrub", "max_per_run"}, envKey: "JAY_SCRUB_MAX_PER_RUN", kind: typeInt},

	{yamlKey: "seed_token.account", yamlPath: []string{"seed_token", "account"}, envKey: "JAY_SEED_TOKEN_ACCOUNT", kind: typeString},
	{yamlKey: "seed_token.id", yamlPath: []string{"seed_token", "id"}, envKey: "JAY_SEED_TOKEN_ID", kind: typeString},
	{yamlKey: "seed_token.secret", yamlPath: []string{"seed_token", "secret"}, envKey: "JAY_SEED_TOKEN_SECRET", kind: typeString},
}

func specByEnvKey(key string) (fieldSpec, bool) {
	for _, s := range fieldSpecs {
		if s.envKey == key {
			return s, true
		}
	}
	return fieldSpec{}, false
}

var topLevelKnownKeys = map[string]bool{
	"data_dir":            true,
	"listen_addr":         true,
	"admin_addr":          true,
	"native_addr":         true,
	"admin_token":         true,
	"signing_secret":      true,
	"log_level":           true,
	"tls_cert":            true,
	"tls_key":             true,
	"rate_limit":          true,
	"rate_burst":          true,
	"trust_proxy_headers": true,
	"scrub":               true,
	"seed_token":          true,
}

var scrubKnownKeys = map[string]bool{
	"interval_hours": true,
	"sample_rate":    true,
	"bytes_per_sec":  true,
	"max_per_run":    true,
}

var seedTokenKnownKeys = map[string]bool{
	"account": true,
	"id":      true,
	"secret":  true,
}
