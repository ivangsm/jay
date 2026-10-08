# Changelog

Notes for people upgrading, one section per published version. The commit list
is appended automatically to every GitHub release; this file is the part a
human writes, and the release workflow refuses to publish a tag that has no
section here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions are [SemVer](https://semver.org/) and jay is pre-1.0: a breaking
change bumps the minor version and is called out as such below.

## [Unreleased]

## [0.19.0] - 2026-10-08

### Highlights

- **A web console.** The admin listener can serve a browser UI for accounts,
  tokens, buckets and objects. It is off by default.
- **The admin API can list accounts and manage buckets**, and `jay-admin`
  gains matching commands.

### Added

- **A web console**, served by the admin listener under `/console/`: accounts,
  tokens, buckets, bucket policy and visibility, quarantine, and an object
  browser with upload, download and preview. **Off by default**: set
  `JAY_CONSOLE_ENABLED=true` (`console.enabled` in YAML). You sign in with
  `JAY_ADMIN_TOKEN`; objects are browsed as one of your tokens, so the S3
  handler makes every access decision. See the
  [guide](https://ivangsm.github.io/jay/guides/console/). `make console-smoke`
  drives it end to end against a real jay.
- **Four admin endpoints**: `GET /_jay/accounts`, `GET /_jay/buckets`,
  `POST /_jay/buckets` and `DELETE /_jay/buckets/{name}`, with `jay-admin`
  commands `list-accounts`, `list-buckets`, `create-bucket` and `delete-bucket`.
  Creating or deleting a bucket writes a `bucket.create` / `bucket.delete`
  audit line.

### Changed

- Creating and deleting a bucket over S3 now share one implementation with the
  admin endpoints above. The S3 behavior is unchanged.

### Upgrade notes

- No data migration. The console stays off unless `JAY_CONSOLE_ENABLED` is
  set; the bundled `docker-compose.yml` and `docker-compose.dev.yml` set it,
  and the dev compose now publishes the admin port on `127.0.0.1` only.
- The console is served from the admin port: keep that port off untrusted
  networks, or put TLS in front of it.

## [0.18.0] - 2026-09-23

### Highlights

**`aws-chunked` uploads are decoded and verified.** SigV4's streaming mode —
what minio-go (`mc`, `warp`) sends on every plain-HTTP upload, and what the AWS
CLI sends on every HTTPS upload — used to be refused with `501`. Jay now decodes
the framing on `PutObject` and `UploadPart`, verifies every chunk signature
(chained from the request signature, final empty chunk included), the declared
length and any trailing checksum, and commits the object only after all of it
has verified. A tampered, truncated or mis-sized body writes nothing.

**The admin API's quarantine purge no longer deletes live objects**, and the
control plane (`admin/`, `jay-admin`, `jay-rekey`) is now tested on its error
paths — which is how a dozen defects in it were found and fixed; see *Fixed*.

**The native listener's back-pressure knobs are configurable.** The connection
cap is no longer a constant, a per-token byte-rate cap exists, and an upload the
server refuses without reading it gets its answer before the connection closes.

**Prometheus can scrape Jay, and the admin port leaves a trail.** `GET /metrics`
on the admin port serves every counter in the Prometheus text format — with its
own read-only credential, so a scraper never holds the admin token — plus free
disk and metadata-database health. Every admin request now gets a request ID and
an access line, and every change an `audit` line naming what was created,
revoked or purged: creating an account or a token used to write nothing at all.

### Breaking changes

- `jay-admin create-token` requires `-actions` (`-actions '*'` reproduces a
  wildcard token). It could not create a token at all before — it sent no
  `allowed_actions`, which the server requires — so no working script breaks.
- The admin API refuses what it used to accept and ignore: `POST /_jay/accounts`
  without a `name` and `POST /_jay/tokens` with an action outside the documented
  list are `400`; a method a path does not serve is `405` with `Allow`, not
  `404`; a quarantine operation on an object that is not quarantined is `409`.
- `DELETE /_jay/quarantine` with `mode: all` answers
  `{"purged": N, "failed": [...]}`, and a purge that left objects behind is a
  `500` naming each one with its reason.
- `proto.NewServer` takes the rate limit as `float64`.

### Added

- `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`,
  `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` and
  `STREAMING-UNSIGNED-PAYLOAD-TRAILER` on `PutObject` and `UploadPart`, under a
  SigV4 `Authorization` header. A trailing
  `x-amz-checksum-{crc32,crc32c,crc64nvme,sha1,sha256}` is verified against the
  bytes before the commit and echoed in the response, like a header-declared
  one.
- `JAY_NATIVE_MAX_CONNS` / `native_max_conns` (default 1000): the native
  connection cap, until now a constant. `proto.Server.SetMaxConns`.
- `JAY_NATIVE_TOKEN_BYTES_PER_SEC` / `native_token_bytes_per_sec` (default 0,
  off): a per-token cap on object body bytes over the native protocol, uploads
  and downloads together, shared across the token's connections. It delays,
  never refuses, and its waits do not count against the server's deadlines.
  `proto.Server.SetTokenBytesPerSec`. The S3 API is unaffected.
- `proto.RateLimitDrainSize` (10 MiB, equal to `MaxDrainSize`): how much of a
  rate-limited body the server reads out to keep the connection. Both are now
  contract, pinned by the golden tests. Clients older than this release rely on
  its being 10 MiB; clients from this release on assume only `MaxMetaSize`
  (1 MiB), so it can come down to that once the older ones are gone.
- `jay-admin create-token` takes `-bucket-scope`, `-prefix-scope` and
  `-expires-at`; `jay-admin quarantine-purge` takes `-bucket-id`/`-key` for a
  single object and prints how many objects it purged.
- `scripts/conformance.sh`: `mc` uploads over plain HTTP (small, 20 MiB
  multipart, CRC32C trailer) compared byte for byte, `warp put`/`get` and
  signed-trailer `warp put --checksum` over HTTP, and an `aws-cli-tls` group.
  Every framed check asserts, from the client's own debug trace, which
  `STREAMING-*` mode it actually sent. `FuzzChunkedReader` runs in the CI fuzz
  job.
- `GET /metrics` on the admin port: every counter in the Prometheus text
  exposition format (0.0.4), written without a client-library dependency, plus
  `jay_data_dir_free_bytes`, `jay_metadata_db_up`,
  `jay_metadata_db_ping_seconds`, `jay_start_time_seconds` and
  `jay_build_info`. Operation counters are one family,
  `jay_operations_total{op="put_object"|…}`.
- `JAY_METRICS_TOKEN` / `metrics.token`: a read-only bearer that opens
  `/metrics` and nothing else on the admin port. It must be at least 32
  characters and differ from `JAY_ADMIN_TOKEN`, or Jay refuses to start.
- `JAY_METRICS_PUBLIC` / `metrics.public`: opt-in to scraping `/metrics`
  without authentication. Warns on every startup; combining it with
  `JAY_METRICS_TOKEN` aborts startup.
- The admin port leaves a trail. Every request on it — `/_jay`, `/metrics`,
  pprof, health probes — gets an `x-amz-request-id` header and an
  `admin request` access line (method, path without query string, status,
  bytes, duration, `remote_ip`, `request_id`). Every change also writes an
  `audit` line with the same request ID, the `action` (`account.create`,
  `token.create`, `token.revoke`, `presign.issue`, `quarantine.revalidate`,
  `quarantine.purge`, `quarantine.purge_all`, `bucket.policy.put`,
  `bucket.policy.delete`, `bucket.visibility.put`) and the IDs it touched.
  Token secrets, presigned URLs and signatures are never logged; a failed
  operation writes no audit line.
- Authentication failures on the admin port are counted:
  `jay_auth_failures_total{surface="admin"}` in Prometheus,
  `admin_auth_failures` in `GET /_jay/metrics`.

### Changed

- A refused `aws-chunked` body answers `403 SignatureDoesNotMatch` (chunk or
  trailer signature), `400 IncompleteBody` (length mismatch),
  `400 InvalidRequest` (malformed framing, missing or invalid
  `x-amz-decoded-content-length`) or `400 BadDigest` (trailing checksum
  mismatch), and writes nothing. Still `501`: SigV4a streaming
  (`STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD*`), framing under a bearer token or
  a presigned URL, and framing on any operation other than `PutObject` and
  `UploadPart`.
- A rate-limited native frame whose body is over 10 MiB is answered
  `RateLimitExceeded` before the connection closes, and none of it is read. It
  used to be closed without an answer, after its metadata was read. Bodies up
  to 10 MiB are drained and keep the connection, as before.
- A refused native upload with more than 10 MiB left unread gets its answer
  (`AccessDenied`, `NoSuchBucket`, `EntityTooLarge`…) before the connection
  closes, instead of a bare close.
- Over-limit native connections are refused off the accept loop (at most 64 in
  flight, 2 s each) and closed with a half-close, so the `ServerBusy` status is
  not lost to a TCP reset.
- Go client: when an upload's write fails because the server closed the
  connection, it returns the server's answer (`*client.Error` with its code)
  instead of `broken pipe`, and it does not pool a connection the server may
  have closed after an error answer. That includes any rate-limited upload
  over 1 MiB, although this server keeps those connections: the threshold is
  meant to come down to 1 MiB, and a client that trusted today's 10 MiB would
  then pool connections the server closed. Against this server it costs one
  reconnect.
- Every admin API error body is served as `application/json`.
- A request that carries both a jay presigned query (`X-Jay-*`) and an
  `Authorization` header is authenticated by the header, as the SigV4 presigned
  form already was. The two credentials are never tried in turn.
- Health probes are logged at `DEBUG` while they answer `200` and at `WARN`
  when they do not, so a probing orchestrator no longer floods the log at the
  default level.
- A panic in an admin-port handler is answered with a JSON `500` carrying the
  request ID, logged as `panic recovered`, and counted in `panics_recovered`.
- The `bucket policy installed`, `bucket policy removed` and
  `bucket visibility changed` log lines are replaced by `audit` lines
  (`bucket.policy.put`, `bucket.policy.delete`, `bucket.visibility.put`) that
  carry the request ID.

### Fixed

- **The AWS CLI could not upload over HTTPS.** Current versions (checked with
  2.37) frame every HTTPS upload as `STREAMING-UNSIGNED-PAYLOAD-TRAILER` with a
  CRC64NVME trailer, which was answered `501`; the README claimed aws-cli worked
  over both transports because the conformance harness only ran it over HTTP.
  `mc` and `warp` can now upload over plain HTTP too.
- **Admin API: the quarantine purge no longer deletes live objects.** Naming an
  active object in `DELETE /_jay/quarantine` deleted its file and record with a
  `204`. Purge and revalidate now act only on quarantined objects, checked in
  the same bbolt transaction as the write; revalidate no longer reports an
  active object as `"restored": true`.
- **Quarantine purge: a file that cannot be removed fails the purge** and
  leaves the object in quarantine, listed and retryable. The error used to be
  ignored and the record deleted anyway, reporting as purged bytes that were
  still on disk.
- **Admin API: `expires_at` on `POST /_jay/tokens` is honoured.** It was
  accepted and dropped, so the token never expired. It must be a future
  RFC 3339 timestamp (`400` otherwise), and the response echoes it.
- Admin API: revoking an unknown token is `404`, not `500`; a failed database
  read in `POST /_jay/tokens` and `POST /_jay/presign` — including a token that
  cannot be decrypted under the configured `JAY_SIGNING_SECRET` — is a `500`,
  not `400 account not found` / `400 token not found`.
- Admin auth backoff: crossing the 10 000-source cap evicted the failure just
  recorded instead of the oldest one.
- `jay-admin quarantine-purge` could never succeed (it sent no body), and
  `revoke-token` and `quarantine-purge` dropped the server's reason from their
  errors.
- **`jay-rekey` no longer creates a database.** A missing data dir or `-db` (a
  typo, or the `./data` default from the wrong directory) produced an empty
  `jay.db`, "nothing rekeyed" and exit 0. A second run is now a no-op instead
  of a decrypt error; a database holding tokens under both the old and the new
  secret can be rekeyed; and a new secret shorter than 32 bytes is refused
  before anything is written.
- Native TLS listener at its connection cap: a peer that connected and never
  sent a ClientHello stalled the accept loop; no other connection was accepted
  until it left.
- `JAY_RATE_LIMIT` below 1 (e.g. `0.5`) disabled the native rate limiter
  (`int(0.5) == 0`) while the S3 API applied it.
- A rate-limited native frame declaring more than 1 MiB of metadata was drained
  to the end instead of closing the connection; a body sent with a native
  operation that takes none was parsed as the next frame header.
- `jay-config validate` rejected quoted scalars the server accepts
  (`trust_proxy_headers: "true"`, `rate_burst: "50"`, `rate_limit: "0.5"`) and
  whole floats for integer keys (`rate_burst: 50.0`).
- The observability docs described `checksum_failures` as a client digest
  mismatch; it counts objects the scrubber found corrupt on disk.

### Upgrade notes

- No data migration and no wire-format change.
- Native clients older than this release (falco pins 0.16.0) see no change on
  a rate-limited upload of up to 10 MiB: `RateLimitExceeded`, and a connection
  that keeps working. Above 10 MiB they still get a transport error
  (`broken pipe`, `connection reset by peer`) instead of the code, as before:
  the server now writes `RateLimitExceeded` before closing, but an older client
  does not read behind a failed write. Measured with the 0.12.0 and 0.16.0
  clients against this release and against 0.16.0, 50 refusals per size, on
  macOS and Linux.
- Update native clients to this `proto/client` anyway: it reports the code in
  that case too, and a later release is meant to lower `RateLimitDrainSize` to
  1 MiB. After that, an older client rate-limited on an upload between 1 and
  10 MiB gets `broken pipe` instead of `RateLimitExceeded`, and may fail its
  next request once on the connection the server closed.
- A native byte cap below 1 MiB/s per concurrent transfer can make the Go
  client time out its own large transfers; lower `client.Timeouts.BytesPerSec`
  to match.
- Scripts that call the admin API may see new `4xx` answers where they used to
  get a silent success; see *Breaking changes*.
- `mc cp --checksum` of a file above the part size still fails: the parts are
  accepted, but `CompleteMultipartUpload` carries a whole-object checksum Jay
  does not verify, and answers `501`.
- `/metrics` requires the admin token by default. Set `JAY_METRICS_TOKEN`
  before pointing Prometheus at it.
- `GET /_jay/metrics` gains one key, `admin_auth_failures`; every existing key
  is unchanged.
- Log queries on the old bucket-policy messages must switch to
  `"msg":"audit"` and the `action` field.

## [0.17.1] - 2026-09-21

### Fixed

- `scripts/release-notes.sh` matched the version heading as a regular
  expression, so a `.` or a `+` in the tag stood for any character, and it
  left a blank line at the top of the extracted section. The heading is now
  compared literally and the section is trimmed on both ends before it
  becomes the release header.

### Upgrade notes

- No change in the server, the library or the client: the rest of this
  release is comment rewrites. Nothing to do.

## [0.17.0] - 2026-09-17

### Highlights

**GitHub releases now carry real upgrade notes.** The release workflow reads
the `CHANGELOG.md` section for the tag being published and puts it at the top
of the release body, above the commit list goreleaser already generated. A tag
whose section is missing or empty fails CI before anything is built.

### Added

- `scripts/release-notes.sh` extracts one version's section from
  `CHANGELOG.md`. The release workflow runs it twice: once as a guard (fails
  the pipeline with no section or an empty one) and once to produce the
  `--release-header` passed to goreleaser.
- The changelog's generated commit list now groups by type (Breaking changes,
  Features, Fixes, Other) and drops `chore: bump version` in addition to the
  existing `docs:`/`test:` exclusions — including their scoped forms
  (`docs(site): …` used to slip through).

### Upgrade notes

- No data migration, no API or protocol change. Purely release tooling.

## [0.16.0] - 2026-09-12

This release folds in 0.13, 0.14 and 0.15, none of which were published.

### Highlights

**jay is now a Go library as well as a server.** `jay.Open(dir)` opens a data
directory in-process — the same bbolt metadata, atomic writes, per-object
SHA-256, startup recovery and GC the server runs — with no listener and no
token. A directory written by the library is valid for the server and vice
versa. See [Embedding Jay in Go](https://ivangsm.github.io/jay/guides/embedded/).

**The native protocol client is a proper SDK.** Every operation takes a
`context.Context` and honours its deadline and cancellation; `Dial` takes
functional options; and three operations that only existed over HTTP are now
native too: byte-range reads (`GetObjectRange`), server-side copy
(`CopyObject`) and presigned URLs (`PresignURL`, computed locally, no round
trip).

**The native listener can speak TLS.** Set `JAY_NATIVE_TLS_CERT` and
`JAY_NATIVE_TLS_KEY` — a pair separate from the S3 listener's on purpose — and
the handshake, which carries the token secret, stops travelling in the clear.

### Breaking changes

- **The server moved to `cmd/jay`.** `go install github.com/ivangsm/jay@latest`
  no longer installs it; use `go install github.com/ivangsm/jay/cmd/jay@latest`.
  Building from source is `go build ./cmd/jay`. The Docker image, the release
  archives and every documented path are unchanged.
- **`proto/client` signatures changed.** `Dial(addr, tokenID, secret, poolSize)`
  and `DialWithOptions` are replaced by `Dial(ctx, addr, tokenID, secret,
  opts...)` with `WithPoolSize`, `WithTLS`, `WithLogger`, `WithTimeouts` and
  `WithS3Endpoint`; every method gains a leading `context.Context`. A cancelled
  context aborts the operation in flight and costs the connection it was using
  — the protocol has no cancel frame. Nothing on the wire changed: a 0.16
  client talks to an older server, and the two new opcodes come back as
  `UnknownOp` (`client.IsUnknownOp`) rather than a misparse.

### Added

- `GetObjectRange` (opcode `0x15`) and `CopyObject` (`0x16`) on the native
  protocol, documented in the
  [reference](https://ivangsm.github.io/jay/reference/native-protocol/) and
  pinned by golden tests. `jay cp` between two buckets now copies on the
  server.
- Bucket policies and visibility are configurable through the admin API
  (`/_jay/buckets/{name}/policy`, `/_jay/buckets/{name}/visibility`) and the
  matching `jay-admin` subcommands. Until now a policy could be evaluated but
  never installed. A policy that could not match anything is refused instead
  of installed inert.
- `x-amz-checksum-algorithm` on `CopyObject` is honoured: the digest is
  computed in the same pass that writes the copy and returned in
  `<CopyObjectResult>`. It used to answer 200 with no digest at all.
- Metadata snapshots are configured as `metadata_backup.dir` /
  `JAY_METADATA_BACKUP_DIR`. The old `backup.dir` / `JAY_BACKUP_DIR` still
  works and warns — it promised a backup of the objects and only ever copied
  metadata. `/health/ready` now reports what actually has a recovery path,
  including whether the snapshot directory shares a filesystem with the data.
- A panic in a request handler is recovered, logged in JSON with the request
  id (or opcode and stream id on the native protocol) and counted in
  `panics_recovered`. It used to drop the HTTP connection silently, and on the
  native protocol it took the whole process down.
- The native handshake distinguishes a full server (`ServerBusy`) and a
  non-jay peer (`Malformed`) from a real version mismatch.
- The wire decoder is fuzzed in CI on every push.

### Fixed

- **Security:** object and bucket IDs are joined onto filesystem paths through
  one guarded function; a crafted ID can no longer escape the data directory.
- **Security:** `jay sync` and `jay cp` refuse to write a downloaded key that
  resolves outside the destination directory (`../` in an object key).
- **Security:** the native decoder validates element counts against the bytes
  actually present before allocating; two bytes of hostile input could force a
  multi-megabyte allocation.
- A `rate_burst` of zero or below, or above the limit, is rejected at startup
  instead of silently disabling the rate limiter.
- `ListObjects` on the native protocol formats `last_modified` as real
  RFC 3339 (it stamped a literal `Z` on whatever zone the value carried).
- `ghcr.io/ivangsm/jay:latest` points at a published version again. It had
  been left on a build of a tag that was later deleted.

### Upgrade notes

- No data migration. The data directory layout, the metadata database and the
  wire format are the same as 0.12.
- Go consumers of `proto/client`: add a context to every call and switch to
  the functional `Dial`. The compiler finds every site.
- If you set `JAY_BACKUP_DIR`, rename it to `JAY_METADATA_BACKUP_DIR` at your
  convenience; the old name keeps working.

[Unreleased]: https://github.com/ivangsm/jay/compare/v0.19.0...HEAD
[0.19.0]: https://github.com/ivangsm/jay/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/ivangsm/jay/compare/v0.17.1...v0.18.0
[0.17.1]: https://github.com/ivangsm/jay/compare/v0.17.0...v0.17.1
[0.17.0]: https://github.com/ivangsm/jay/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/ivangsm/jay/compare/v0.12.0...v0.16.0
