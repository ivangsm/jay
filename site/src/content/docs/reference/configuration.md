---
title: Configuration
description: Every variable Jay reads, the YAML file, and the precedence rules between them.
---

Jay takes configuration from environment variables, a YAML file, or both. When
both set the same key, **the environment wins** and the conflict is logged at
`WARN`.

## Variables

| Variable | Default | Description |
|---|---|---|
| `JAY_CONFIG_FILE` | *(optional)* | Path to a YAML config file. Also settable with `--config-file`, which takes precedence |
| `JAY_DATA_DIR` | `./data` | Data directory for objects and metadata |
| `JAY_LISTEN_ADDR` | `:9000` | S3 API listen address |
| `JAY_ADMIN_ADDR` | `:9001` | Admin API listen address |
| `JAY_NATIVE_ADDR` | `:4444` | Native protocol listen address; **empty disables the listener** |
| `JAY_ADMIN_TOKEN` | *(required)* | Bearer token for the admin API; at least 32 characters |
| `JAY_SIGNING_SECRET` | *(required)* | AES-GCM key for presigned URLs and token secrets; at least 32 characters |
| `JAY_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `JAY_TLS_CERT` | *(optional)* | Path to a TLS certificate |
| `JAY_TLS_KEY` | *(optional)* | Path to a TLS private key |
| `JAY_RATE_LIMIT` | `100` | Requests/sec per token (`0` disables) |
| `JAY_RATE_BURST` | `200` | Rate limit burst size; must be at least `1` — a burst of `0` rejects every request, so turn the limiter off with `JAY_RATE_LIMIT=0` instead |
| `JAY_TRUST_PROXY_HEADERS` | `false` | Trust `X-Forwarded-For` / `X-Real-IP` |
| `JAY_SCRUB_INTERVAL_HOURS` | `6` | Scrubber interval |
| `JAY_SCRUB_BYTES_PER_SEC` | `52428800` | Scrubber read throttle (`0` = unlimited) |
| `JAY_SCRUB_MAX_PER_RUN` | `100` | Objects visited per bucket per scrub tick |
| `JAY_BACKUP_DIR` | `<data_dir>/backups` | Where hourly bbolt snapshots go; point at a separate volume for real DR |
| `JAY_MIN_FREE_BYTES` | `524288000` | Readiness fails below this free space (`0` disables) |
| `JAY_MAX_OBJECT_SIZE` | `5368709120` | Largest accepted body and multipart part (`0` disables) |
| `JAY_SEED_TOKEN_ACCOUNT` | *(optional)* | See [Seed token](/jay/reference/seed-token/) |
| `JAY_SEED_TOKEN_ID` | *(optional)* | Seed token ID |
| `JAY_SEED_TOKEN_SECRET` | *(optional)* | Seed token secret, bcrypt-hashed before storage |
| `JAY_TOKEN_ID` | *(optional)* | Credentials for the `jay` subcommands; the server ignores them |
| `JAY_TOKEN_SECRET` | *(optional)* | Same |

## The two required secrets

`JAY_ADMIN_TOKEN` and `JAY_SIGNING_SECRET` have no defaults and no development
fallback. If either is missing or shorter than 32 characters, Jay exits **before
opening the database and before binding a listener**.

`JAY_SIGNING_SECRET` is the AES-GCM key that encrypts token secrets in bbolt.
**Losing it makes every stored token unreadable.** To change it, use
`jay-rekey`, which re-encrypts the stored secrets — do not just set a new value.

## YAML file

Point Jay at a file with `--config-file path/to/config.yml` or
`JAY_CONFIG_FILE`:

```yaml
data_dir: ./data
listen_addr: ":9000"
admin_addr: ":9001"
native_addr: ":4444"

# Secrets can reference env vars via ${VAR} interpolation, so this file can be
# committed to git while the secrets stay in .env.
admin_token: ${JAY_ADMIN_TOKEN}
signing_secret: ${JAY_SIGNING_SECRET}

log_level: info
rate_limit: 100
rate_burst: 200
trust_proxy_headers: false

# ${VAR:-default} provides a fallback.
tls_cert: ${JAY_TLS_CERT:-}
tls_key: ${JAY_TLS_KEY:-}

scrub:
  interval_hours: 6
  bytes_per_sec: 52428800
  max_per_run: 100

backup:
  dir: ${JAY_BACKUP_DIR:-}
min_free_bytes: 524288000
max_object_size: 5368709120

seed_token:
  account: ${JAY_SEED_TOKEN_ACCOUNT:-}
  id: ${JAY_SEED_TOKEN_ID:-}
  secret: ${JAY_SEED_TOKEN_SECRET:-}

# Credentials for the `jay` subcommands. The server never reads these.
client:
  token_id: ${JAY_TOKEN_ID:-}
  token_secret: ${JAY_TOKEN_SECRET:-}
```

## Rules

**Precedence** is environment variable > YAML > built-in default. A conflict
logs `WARN` at startup but does not fail.

**An empty value means "not configured".** `key: ""` in YAML and `JAY_KEY=""` in
the environment are both discarded, and the default stands.

That is deliberate. An empty value almost always comes from a template whose
variable was never set — `listen_addr: ${JAY_LISTEN_ADDR}`, or a compose file
passing a variable straight through — and applying it literally would move the
data directory or serve on port 80, because Go's `net/http` reads an empty
`Addr` as `:http`.

**The one exception is `native_addr`**, whose empty value is the documented off
switch for the native listener.

When discarding an empty value actually overrides something, it is logged at
`WARN`. When the key would have been empty anyway — `tls_cert`, `backup.dir`,
`seed_token.*`, `client.*` above — it is not, because seven lines of noise per
startup is what teaches people to ignore the one that matters.

**Interpolation** resolves `${VAR}` and `${VAR:-default}` against the
environment, on string values only. If neither is set the value ends up empty,
which then trips the secret-length check if it was `admin_token` or
`signing_secret`.

## jay-config

`jay-config` ships in the release archives and the container image.

```bash
# YAML → .env (stdout if --output is omitted)
jay-config yaml-to-env --input config.yml --output .env

# .env → YAML
jay-config env-to-yaml --input .env --output config.yml

# Check required secrets, seed-token atomicity and value ranges
jay-config validate --input config.yml
```

`${VAR}` interpolation is preserved literally during conversion. The tool moves
keys between formats; it never resolves an environment variable.
