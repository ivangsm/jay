# Jay

[![CI](https://github.com/ivangsm/jay/actions/workflows/ci.yml/badge.svg)](https://github.com/ivangsm/jay/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ivangsm/jay/graph/badge.svg)](https://codecov.io/gh/ivangsm/jay)
[![Go Report Card](https://goreportcard.com/badge/github.com/ivangsm/jay)](https://goreportcard.com/report/github.com/ivangsm/jay)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ivangsm/jay)](https://github.com/ivangsm/jay/blob/main/go.mod)
[![Release](https://img.shields.io/github/v/release/ivangsm/jay?sort=semver)](https://github.com/ivangsm/jay/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/ivangsm/jay/blob/main/LICENSE)

S3-compatible object storage with a native binary protocol, written in Go.

Metadata lives in one bbolt file, object bytes live on the filesystem, and the
whole state of the server is one directory. There is no database to provision,
no broker to point it at and no cache to warm — four direct dependencies and one
static binary.

Two protocols share the same storage and the same authorization layer: an
**S3-compatible HTTP API**, so the AWS CLI and the AWS SDKs work unchanged, and a
**binary protocol** with a Go client for callers that would rather not pay for
HTTP framing, XML and a per-request signature.

**📖 Documentation: <https://ivangsm.github.io/jay/>**

---

## Install

```bash
# Docker
docker run -d --name jay \
  -p 9000:9000 -p 127.0.0.1:9001:9001 \
  -v jay_data:/data \
  -e JAY_ADMIN_TOKEN=$(openssl rand -base64 32) \
  -e JAY_SIGNING_SECRET=$(openssl rand -base64 32) \
  ghcr.io/ivangsm/jay:latest

# Go
go install github.com/ivangsm/jay@latest
go install github.com/ivangsm/jay/cmd/jay-admin@latest
go install github.com/ivangsm/jay/cmd/jay-config@latest
go install github.com/ivangsm/jay/cmd/jay-rekey@latest

# Source
git clone https://github.com/ivangsm/jay.git && cd jay && go build -o jay .
```

Prebuilt archives for `linux/amd64`, `linux/arm64` and `darwin/arm64` are on the
[releases page](https://github.com/ivangsm/jay/releases); each contains the
server plus the three auxiliary CLIs. There is no Windows build.

Full options: [Install](https://ivangsm.github.io/jay/install/).

## Quickstart

Both secrets are required and must be at least 32 characters. Jay refuses to
start without them.

```bash
export JAY_ADMIN_TOKEN=$(openssl rand -base64 32)
export JAY_SIGNING_SECRET=$(openssl rand -base64 32)
./jay &

ACCOUNT=$(curl -fsS -X POST http://localhost:9001/_jay/accounts \
  -H "Authorization: Bearer $JAY_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"myapp"}' | jq -r .account_id)

curl -fsS -X POST http://localhost:9001/_jay/tokens \
  -H "Authorization: Bearer $JAY_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d "{\"account_id\":\"$ACCOUNT\",\"name\":\"deploy\",
       \"allowed_actions\":[\"bucket:write-meta\",\"object:put\",\"object:get\",\"object:list\"]}"
```

Then point the AWS CLI at `http://localhost:9000` with `token_id` as the access
key and the secret as the secret key.

Step by step: [Quickstart](https://ivangsm.github.io/jay/quickstart/).

## Ports

| Port | Purpose | Exposure |
|---|---|---|
| `:9000` | S3-compatible API | The only one meant for untrusted networks |
| `:9001` | Admin API and health probes | Internal — it creates accounts and tokens |
| `:4444` | Native binary protocol | Internal — the token secret travels in the clear |

Set `JAY_NATIVE_ADDR` to empty to disable the native listener entirely.

## Documentation

| | |
|---|---|
| [What Jay is](https://ivangsm.github.io/jay/what-jay-is/) | Scope, and what it deliberately does not do |
| [Configuration](https://ivangsm.github.io/jay/reference/configuration/) | Every `JAY_*` variable, the YAML file, precedence |
| [Authentication](https://ivangsm.github.io/jay/reference/authentication/) | Accounts, tokens, scopes, SigV4, presigned URLs, bucket policies |
| [S3 compatibility](https://ivangsm.github.io/jay/reference/s3-compatibility/) | The complete operation list and what answers `501` |
| [Native protocol](https://ivangsm.github.io/jay/reference/native-protocol/) | Frame layout, opcodes, the Go client |
| [Deploying Jay](https://ivangsm.github.io/jay/guides/deployment/) | TLS, reverse proxies, disk, backups |
| [Performance](https://ivangsm.github.io/jay/internals/performance/) | Measured benchmarks and the design behind them |
| [Architecture](https://ivangsm.github.io/jay/internals/architecture/) | The write path, recovery, scrubbing, GC, backups |
| [Limits](https://ivangsm.github.io/jay/internals/limits/) | No versioning, no replication, no events |

## One compatibility caveat

minio-go clients (`mc`, `warp`) **cannot upload over plain HTTP**. They sign
non-TLS uploads with SigV4's streaming mode, which frames the body in
`aws-chunked`, and Jay refuses that framing with `501` rather than storing the
frames as if they were your file. Over HTTPS the same clients work completely.

aws-cli, the AWS SDKs and boto3 work over both.
[The full explanation](https://ivangsm.github.io/jay/reference/s3-compatibility/).

## Development

```bash
make check        # fmt + vet + lint + test + build — the commit gate
make conformance  # S3 conformance against real aws-cli, mc and warp
```

`make check` proves Jay agrees with itself. `make conformance` proves it agrees
with clients it did not write — and a run where every client group was skipped
exits non-zero with `NOTHING WAS PROVEN`, because a green exit that tested
nothing is the failure mode this project cares about most.

The documentation site lives in [`site/`](site/) and is built with Astro
Starlight:

```bash
cd site && bun install && bun run dev
```

## License

MIT © Iván Salazar
