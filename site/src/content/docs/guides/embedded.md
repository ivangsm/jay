---
title: Embedding Jay in a Go program
description: The same engine the server runs, opened in-process — no listener, no token, no serialization.
---

`github.com/ivangsm/jay` is importable. `jay.Open` gives a Go program the
engine the server runs — bbolt metadata, atomic writes, a SHA-256 per object,
startup recovery, garbage collection, the scrubber — as a value in its own
process, with nothing on the network.

```go
import "github.com/ivangsm/jay"

s, err := jay.Open("/var/lib/myapp/objects")
if err != nil {
    log.Fatal(err)
}
defer s.Close()

ctx := context.Background()
_ = s.CreateBucket(ctx, "photos")

obj, err := s.Put(ctx, "photos", "2026/cat.jpg", file,
    &jay.PutOptions{ContentType: "image/jpeg"})

info, body, err := s.Get(ctx, "photos", "2026/cat.jpg")
defer body.Close()
```

## When to embed instead of running the server

A Go program that is the only thing talking to its object store gains nothing
from a protocol: every byte would be framed, sent through a socket and unframed
to land in the same process it started from. The native protocol exists for
**process separation** — for a service that must outlive its callers or serve
several of them — and the library is for when there is no separation to buy.

The two are not exclusive. A directory written by the library is a valid one
for the server, and vice versa: you can develop against `jay.Open` and deploy
behind `cmd/jay`, or open a server's data directory with a one-off Go program
while the server is stopped. bbolt locks the file, so two openers cannot
corrupt each other — the second one fails.

## What the library has, and what it does not

Everything below the transports is shared with the server, through one internal
package. A bug fixed there is fixed in both.

| | Library | Server |
|---|---|---|
| Atomic writes, per-object SHA-256, startup recovery | yes | yes |
| Garbage collection of abandoned uploads | yes, `WithGCInterval` | yes |
| Integrity scrubber with quarantine | opt-in, `WithScrub` | yes |
| Metadata snapshots | opt-in, `WithMetadataSnapshots` | yes |
| Range reads, server-side copy, listing with delimiters | yes | yes |
| Accounts, tokens, scopes, bucket policies | **no** | yes |
| Rate limiting, TLS, health probes, metrics endpoint | **no** | yes |
| Multipart uploads | **no** — `Put` streams any size in one call | yes |

Buckets the library creates have no owner, and every call is authorized by
virtue of being made from inside the process. If the application needs
per-caller permissions, that is the server's job, not something to rebuild on
top of the library.

## Operations

| Method | Notes |
|---|---|
| `CreateBucket`, `DeleteBucket`, `ListBuckets` | S3 naming rules; delete refuses a non-empty bucket with `ErrBucketNotEmpty` |
| `Put(ctx, bucket, key, r, opts)` | Streams `r` to a temp file, fsyncs, renames, commits. Replaces an existing key. `WithMaxObjectSize` refuses oversized bodies **before** committing |
| `Get`, `GetRange(ctx, bucket, key, offset, length)` | Return the object's description and an `io.ReadCloser`. `length <= 0` reads to the end; a range past the object is `ErrInvalidRange` |
| `Head` | Description without opening the file |
| `Delete` | Idempotent: a missing object is not an error, a missing bucket is |
| `Copy` | Server-side; content type and metadata carry over |
| `List(ctx, bucket, opts)` | Pages of up to 10,000 keys, `Prefix`/`Delimiter`/`StartAfter` as in S3 |

Errors are sentinels — `jay.ErrBucketNotFound`, `jay.ErrObjectNotFound`,
`jay.ErrBucketExists`, `jay.ErrBucketNotEmpty`, `jay.ErrInvalidRange`,
`jay.ErrObjectTooLarge`, `jay.ErrClosed` — matched with `errors.Is`.

## Contexts

Every method takes a `context.Context`, and it does more than decorate the
signature. A `Put` whose context is cancelled stops reading its source and
commits nothing: the bytes so far were a temp file, and the temp file is
removed. A `Get` body fails its next `Read` with the context's error once the
context ends. An already-cancelled context fails before touching the store.

## Background loops and `Close`

`Open` runs startup recovery before returning — metadata is reconciled against
the files on disk, and anything that disagrees is **quarantined, never
deleted** — and then starts what the options ask for:

- **GC**, every 15 minutes by default. It reclaims the parts of abandoned
  multipart uploads and the files of deleted objects. `WithGCInterval(0)` turns
  it off, for a program that opens the store for one short operation.
- **The scrubber**, off by default. `WithScrub` re-hashes objects at a bounded
  read rate and quarantines any whose bytes no longer match. It is sustained
  disk I/O, which is a decision for the application.
- **Metadata snapshots**, off by default. `WithMetadataSnapshots(dir, every,
  retention)` copies and verifies the bbolt file on a schedule. **Object bytes
  are not backed up** — by the library any more than by the server. See
  [Backup and restore](/jay/guides/backup-and-restore/).

`Close` stops them in order — snapshots first, so one is never in flight when
bbolt closes underneath it — and then closes the database. Every call after it
returns `ErrClosed`.

Pass `WithLogger` to see what recovery, the GC and the scrubber did. By default
the library is silent.
