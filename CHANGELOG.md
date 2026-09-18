# Changelog

Notes for people upgrading, one section per published version. The commit list
is appended automatically to every GitHub release; this file is the part a
human writes, and the release workflow refuses to publish a tag that has no
section here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions are [SemVer](https://semver.org/) and jay is pre-1.0: a breaking
change bumps the minor version and is called out as such below.

## [Unreleased]

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

[Unreleased]: https://github.com/ivangsm/jay/compare/v0.17.0...HEAD
[0.17.0]: https://github.com/ivangsm/jay/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/ivangsm/jay/compare/v0.12.0...v0.16.0
