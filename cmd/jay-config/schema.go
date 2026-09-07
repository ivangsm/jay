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
	{yamlKey: "native_tls_cert", yamlPath: []string{"native_tls_cert"}, envKey: "JAY_NATIVE_TLS_CERT", kind: typeString},
	{yamlKey: "native_tls_key", yamlPath: []string{"native_tls_key"}, envKey: "JAY_NATIVE_TLS_KEY", kind: typeString},
	{yamlKey: "rate_limit", yamlPath: []string{"rate_limit"}, envKey: "JAY_RATE_LIMIT", kind: typeFloat},
	{yamlKey: "rate_burst", yamlPath: []string{"rate_burst"}, envKey: "JAY_RATE_BURST", kind: typeInt},
	{yamlKey: "trust_proxy_headers", yamlPath: []string{"trust_proxy_headers"}, envKey: "JAY_TRUST_PROXY_HEADERS", kind: typeBool},

	{yamlKey: "scrub.interval_hours", yamlPath: []string{"scrub", "interval_hours"}, envKey: "JAY_SCRUB_INTERVAL_HOURS", kind: typeInt},
	{yamlKey: "scrub.bytes_per_sec", yamlPath: []string{"scrub", "bytes_per_sec"}, envKey: "JAY_SCRUB_BYTES_PER_SEC", kind: typeInt},
	{yamlKey: "scrub.max_per_run", yamlPath: []string{"scrub", "max_per_run"}, envKey: "JAY_SCRUB_MAX_PER_RUN", kind: typeInt},

	// backup.dir is the deprecated spelling of metadata_backup.dir. It stays in
	// the schema for as long as the server keeps honouring it: dropping it here
	// would make yaml-to-env warn "unknown YAML key" and silently discard a
	// directory the server still reads.
	{yamlKey: "backup.dir", yamlPath: []string{"backup", "dir"}, envKey: "JAY_BACKUP_DIR", kind: typeString},
	{yamlKey: "metadata_backup.dir", yamlPath: []string{"metadata_backup", "dir"}, envKey: "JAY_METADATA_BACKUP_DIR", kind: typeString},
	{yamlKey: "min_free_bytes", yamlPath: []string{"min_free_bytes"}, envKey: "JAY_MIN_FREE_BYTES", kind: typeInt},
	{yamlKey: "max_object_size", yamlPath: []string{"max_object_size"}, envKey: "JAY_MAX_OBJECT_SIZE", kind: typeInt},

	{yamlKey: "seed_token.account", yamlPath: []string{"seed_token", "account"}, envKey: "JAY_SEED_TOKEN_ACCOUNT", kind: typeString},
	{yamlKey: "seed_token.id", yamlPath: []string{"seed_token", "id"}, envKey: "JAY_SEED_TOKEN_ID", kind: typeString},
	{yamlKey: "seed_token.secret", yamlPath: []string{"seed_token", "secret"}, envKey: "JAY_SEED_TOKEN_SECRET", kind: typeString},

	// Client credentials: unused by the server, read by the `jay` subcommands.
	{yamlKey: "client.token_id", yamlPath: []string{"client", "token_id"}, envKey: "JAY_TOKEN_ID", kind: typeString},
	{yamlKey: "client.token_secret", yamlPath: []string{"client", "token_secret"}, envKey: "JAY_TOKEN_SECRET", kind: typeString},
}

func specByEnvKey(key string) (fieldSpec, bool) {
	for _, s := range fieldSpecs {
		if s.envKey == key {
			return s, true
		}
	}
	return fieldSpec{}, false
}

// The accepted YAML shape is derived from fieldSpecs, never written twice.
// A second hand-maintained list is what let backup.dir, min_free_bytes and
// max_object_size sit in the server's bindings for months while yaml-to-env
// warned "unknown YAML key" and dropped them on the floor.
var (
	topLevelKnownKeys = derivedTopLevelKeys()
	nestedKnownKeys   = derivedNestedKeys()
)

func derivedTopLevelKeys() map[string]bool {
	out := map[string]bool{}
	for _, s := range fieldSpecs {
		out[s.yamlPath[0]] = true
	}
	return out
}

// derivedNestedKeys maps a section name to the keys allowed inside it.
func derivedNestedKeys() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, s := range fieldSpecs {
		if len(s.yamlPath) != 2 {
			continue
		}
		section := s.yamlPath[0]
		if out[section] == nil {
			out[section] = map[string]bool{}
		}
		out[section][s.yamlPath[1]] = true
	}
	return out
}
