---
title: Architecture
description: How a write happens, what runs in the background, and why the layout is the way it is.
---

Jay is one process over one directory. Metadata lives in a single bbolt file;
object bytes live on the filesystem in a two-level sharded layout.

```
JAY_DATA_DIR/
  meta/jay.db      bbolt: buckets, objects, tokens, multipart state
  buckets/         object bytes, sharded two levels deep
  multipart/       parts of uploads still in flight
  tmp/             in-flight writes
  backups/         hourly verified snapshots of jay.db — metadata only
  quarantine/      objects pulled out of service
```

Only two of those are data you would miss: `meta/jay.db` and `buckets/`. Jay
snapshots the first and never copies the second — see
[Backup and restore](/jay/guides/backup-and-restore/).

## One authorization layer, two transports

The S3 handlers and the native protocol handlers both call into
`internal/objops`, which is where object operations and their permission checks
actually live. Neither transport has its own copy.

The account check is a single function called by three gates: the HTTP handler,
the native connection handler, and the shared object operations. A handler added
later inherits it by asking for the token — there is no second rule to forget.

That mattered: until this was centralised, cross-account isolation held for
`DeleteBucket`, `HeadBucket` and `GetBucketLocation`, and was **missing** from
`ListObjectsV2`, `GetObject`, `PutObject`, `DeleteObject`, `DeleteObjects`, the
bucket statistics and all of multipart — on both transports.

## How a write happens

It is not one transaction, and knowing the order is what keeps someone from
"fixing" it:

1. The bytes go to a temp file. SHA-256 is computed in the same pass, along with
   any digest the client declared.
2. The temp file is `fsync`ed.
3. The declared digest is checked. A mismatch stops here, so a refused upload
   never becomes a file.
4. `rename` into the final path — atomic, so there is never a partially visible
   object under the key.
5. The parent directory is `fsync`ed, making the rename itself durable.
6. Metadata is committed in **one** bbolt transaction: the object record and the
   bucket's statistics move together, or neither moves.

If step 6 fails, the file written in step 4 is removed. An object over
`JAY_MAX_OBJECT_SIZE` is removed the same way, and metadata for a rejected
object is never committed.

A crash between the file and the record leaves a file with no record. Startup
recovery reconciles the two before the server accepts traffic and
**quarantines** both directions of inconsistency — a record with no file, and a
file with no record.

It never deletes. An inconsistency is evidence of something that went wrong, and
deleting it destroys the only trace.

:::note
On macOS the directory `fsync` in step 5 is a no-op. The write path is written
for Linux, which is where Jay is meant to run.
:::

## Reads

`GetObject` does not re-verify the checksum. Hashing on the way out would mean
copying every byte back through the process, which forecloses `sendfile(2)`.
Instead the open file is handed to the kernel — on HTTP through a `ReadFrom` on
the response writer, on the native protocol by flushing the frame prelude and
then copying to the raw connection.

Integrity is the scrubber's job, on a background pass where it costs nothing on
the hot path.

## Background loops

| Loop | Cadence | What it does |
|---|---|---|
| Scrubber | Every `JAY_SCRUB_INTERVAL_HOURS` (6h), first tick after 30 s | Walks buckets in parallel, bounded by `NumCPU`, verifying up to `JAY_SCRUB_MAX_PER_RUN` objects **per bucket**, resuming from a per-bucket cursor. Throttled by `JAY_SCRUB_BYTES_PER_SEC` |
| GC | Every 15 min, and on demand after a delete | Old temp files, multipart uploads abandoned for more than 24 h, and orphaned part directories |
| Metadata snapshot | Hourly | Snapshot of bbolt, `fsync`, **verify**, then prune snapshots older than 7 days while keeping at least 3. Metadata only — no object bytes |

Five consequences worth internalising:

- **Scrub coverage is not a percentage.** It is `max_per_run × buckets` objects
  per tick, so a full pass takes as long as the largest bucket needs. To speed
  it up, raise `JAY_SCRUB_MAX_PER_RUN`, and the byte throttle too if I/O is the
  bottleneck.
- **A snapshot that fails verification is deleted.** An unrestorable snapshot is
  worse than no snapshot, because it satisfies a retention policy silently. The
  snapshot loop is also stopped before the database is closed on shutdown.
- **Verification proves the snapshot opens, not that anything is recoverable.**
  It walks the required bbolt buckets and counts what is in them. It has no view
  of the filesystem, so its object count is a count of *records* — restored over
  an empty `buckets/`, every one of them gets quarantined.
- **The default snapshot directory is on the same disk as the data.** Point
  `JAY_METADATA_BACKUP_DIR` elsewhere for real disaster recovery. Jay warns at
  startup while it is not, and says so on `/health/ready`.
- **Object bytes are not backed up by anything here.** All the machinery above —
  checksums, the scrubber, quarantine, startup recovery — *detects* damage.
  None of it *repairs* it. The recovery path for `buckets/` is external and
  documented in [Backup and restore](/jay/guides/backup-and-restore/).

## Auth caching

Bearer authentication is bcrypt, which costs 60–100 ms of CPU per attempt by
design. Doing that per request is not viable, so verified credentials are cached
for five minutes, keyed by a hash of `token_id:secret` — with a **negative
cache** for bad credentials, so a client hammering a wrong secret cannot use
your CPU as a denial of service.

Revocation is not delayed by the cache: every cache hit re-checks whether the
token was revoked with an `O(1)` read, which is orders of magnitude cheaper than
the bcrypt it avoids.

## Dependencies

Four, and it is meant to stay that way:

| Module | For |
|---|---|
| `go.etcd.io/bbolt` | All metadata |
| `golang.org/x/crypto` | bcrypt |
| `golang.org/x/time` | Rate limiting |
| `gopkg.in/yaml.v3` | The config file |

`net/http` from the standard library, with no third-party router. Logging is
`log/slog` in JSON.
