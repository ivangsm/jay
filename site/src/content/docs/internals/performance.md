---
title: Performance
description: Measured S3-versus-native benchmarks, and the design decisions behind the numbers.
---

Everything below was measured, not estimated. The command that produced it is at
the bottom of the page; run it on your own hardware before trusting anyone's
numbers, including these.

:::note[Where these came from]
AMD Ryzen 7 7700, 8 cores / 16 threads, 30 GB RAM, NVMe · Linux · Go 1.27.1 ·
Jay development tree at 0.11.0 · `go test -bench -count 5`, medians via
`benchstat` (all differences below are significant at p ≤ 0.008 unless noted).

**This is a desktop, not a fleet.** The absolute numbers say more about this
machine than about Jay; the *ratios* between the two protocols are the part
that transfers — and even those shift with the hardware underneath them, which
is exactly what section below on reproducing this is for.
:::

## S3 HTTP versus the native protocol

### Sequential reads

| Operation | S3 HTTP | Native | Native is | S3 throughput | Native throughput |
|---|---|---|---|---|---|
| GetObject, 1KB | 81.3 µs | 38.9 µs | **2.09× faster** | 12.6 MB/s | 26.3 MB/s |
| GetObject, 64KB | 116.0 µs | 46.1 µs | **2.52× faster** | 565 MB/s | 1.42 GB/s |
| GetObject, 1MB | 323.1 µs | 161.5 µs | **2.00× faster** | 3.25 GB/s | 6.49 GB/s |
| GetObject, 10MB | 1.90 ms | 1.40 ms | **1.36× faster** | 5.52 GB/s | 7.50 GB/s |
| HeadObject | 59.8 µs | 27.0 µs | **2.21× faster** | — | — |
| ListObjects, 1000 keys | 1.43 ms | 1.25 ms | **1.14× faster** | — | — |

### Sequential writes

`PutObject` gets three columns instead of two: by default, jay's native
protocol computes the same MD5 `ETag` the S3 API is required to, so "Native
(default)" and "S3 HTTP" are doing identical work. `SkipETag` (see
[Skipping the S3-only checksum](#skipping-the-s3-only-checksum) below) is what
a native-only caller like `falco` actually uses, since it never reads that
field.

| Operation | S3 HTTP | Native (default) | Native (`SkipETag`) | Native default is | Native `SkipETag` is |
|---|---|---|---|---|---|
| PutObject, 1KB | 184.0 µs | 124.5 µs | 122.0 µs | **1.48× faster** | **1.51× faster** |
| PutObject, 64KB | 334.7 µs | 283.2 µs | 194.9 µs | **1.18× faster** | **1.72× faster** |
| PutObject, 1MB | 2.524 ms | 2.548 ms | 1.195 ms | 1.01× slower | **2.11× faster** |
| PutObject, 10MB | 23.04 ms | 23.75 ms | 10.83 ms | 1.03× slower | **2.13× faster** |
| DeleteObject | 105.9 µs | 67.9 µs | — | **1.56× faster** | — |
| Multipart upload | 37.87 ms | 37.82 ms | — | the same | — |

(PutObject rows: n=20 via `benchstat`, p=0.000, CIs within ±2%.)

### Concurrent reads (equal real concurrency on both sides)

| Operation | S3 HTTP | Native | Native is |
|---|---|---|---|
| GetObject 1KB, 1 in flight | 79.7 µs | 38.5 µs | **2.07× faster** |
| GetObject 1KB, 4 in flight | 30.4 µs | 11.0 µs | **2.76× faster** |
| GetObject 1KB, 16 in flight | 26.3 µs | 5.0 µs | **5.23× faster** |
| GetObject 64KB, 1 in flight | 86.1 µs | 46.9 µs | **1.84× faster** |
| GetObject 64KB, 4 in flight | 30.9 µs | 13.1 µs | **2.35× faster** |
| GetObject 64KB, 16 in flight | 28.5 µs | 6.0 µs | **4.78× faster** |
| GetObject 1MB, 1 in flight | 292.2 µs | 199.9 µs | **1.46× faster** |
| GetObject 1MB, 4 in flight | 83.6 µs | 41.1 µs | **2.04× faster** |
| GetObject 1MB, 16 in flight | 57.6 µs | 20.3 µs | **2.84× faster** |

### Concurrent writes (equal real concurrency on both sides)

| Operation | S3 HTTP | Native | Native is |
|---|---|---|---|
| PutObject 1KB, 1 in flight | 155.3 µs | 101.6 µs | **1.53× faster** |
| PutObject 1KB, 4 in flight | 63.5 µs | 42.0 µs | **1.51× faster** |
| PutObject 1KB, 16 in flight | 55.7 µs | 37.2 µs | **1.50× faster** |
| PutObject 64KB, 1 in flight | 265.1 µs | 222.6 µs | **1.19× faster** |
| PutObject 64KB, 4 in flight | 89.8 µs | 62.1 µs | **1.45× faster** |
| PutObject 64KB, 16 in flight | 73.5 µs | 41.9 µs | **1.75× faster** |
| PutObject 1MB, 1 in flight | 2.01 ms | 1.90 ms | **1.06× faster** |
| PutObject 1MB, 4 in flight | 482.3 µs | 472.8 µs | the same |
| PutObject 1MB, 16 in flight | 191.1 µs | 166.7 µs | **1.15× faster** |

### Allocations per operation

| Operation | S3 HTTP | Native | Reduction |
|---|---|---|---|
| GetObject | 397 | 255 | 36% |
| HeadObject | 370 | 246 | 34% |
| PutObject (default) | 523 | 381 | 27% |
| PutObject (`SkipETag`) | 523 | 375 | 28% |
| Multipart upload | 1631 | 850 | 48% |

## Reading the results

**Reads win outright, and the margin grows with concurrency.** 1.14× to 2.52×
on a single connection, and up to 5.23× at 16 requests in flight for small
objects. The gap comes from what HTTP makes you do around the same
`sendfile(2)` call: parse headers, build a response, verify a signature that
re-hashes the request — fixed per-request costs that a busier server pays more
often, not less.

**Writes favor the native protocol at every size, once it isn't paying for an
ETag it doesn't need.** With `SkipETag` set, native is 1.51× to 2.13× faster
than S3 across the full 1KB-10MB range — the win *grows* with size instead of
shrinking, because the fixed per-request framing saving that dominates at 1KB
gets joined by a saving that scales with the number of bytes hashed once MD5
comes off the write path. Left at its default (still computing the MD5 ETag,
same as S3 must), native is only ahead through 64KB and is a statistical wash
at 1MB and 10MB. **Multipart upload is a tie** at default settings, for the
same reason default `PutObject` is: both compute the same two hashes over the
same bytes.

**Allocations are consistently 27-48% lower** on the native protocol, which is
the binary metadata encoding rather than JSON, plus pooled frame buffers.

## How concurrency is measured

"conc1/4/16" below are literal real goroutines on both transports, not
`b.SetParallelism`, which Go's `testing` package runs as `conc × GOMAXPROCS`
goroutines rather than `conc` — a difference worth knowing if you write a
benchmark like this yourself, since it is easy to end up measuring
`GOMAXPROCS` instead of your intended variable, and the mismatch scales with
the core count of whatever machine runs the suite.

With equal real concurrency on both sides, native wins every row, and the
advantage *increases* with concurrency rather than shrinking: 5.23× at 16
concurrent 1KB reads, versus 2.07× at 1. That is the shape you'd expect from a
protocol with a smaller fixed cost per connection — more concurrent requests
means that fixed cost is paid more often, so shaving it off compounds.

## Why reads are fast

**`sendfile(2)` on both transports.** `GetObject` hands the open file to the
kernel: over HTTP through a `ReadFrom` on the response writer, over the native
protocol by flushing the frame prelude and then copying to the raw connection.
The object's bytes go from page cache to socket without passing through the
process.

**Reads do not re-verify the checksum.** Hashing on the way out would pull every
byte back into userspace and foreclose `sendfile`. Integrity is the
[scrubber's](/jay/internals/architecture/) job, on a throttled background pass.

**Authentication does not run bcrypt per request.** Verified credentials are
cached for five minutes, with a negative cache for bad ones. bcrypt costs 60 to
100 ms of CPU per attempt by design — paying it per request would make every
other number on this page irrelevant. Revocation still takes effect immediately:
each cache hit re-checks it with an `O(1)` read.

**Rate limiting happens before authentication, by IP.** Authenticating is the
expensive part, so an unauthenticated flood has to be stopped before it gets
there.

## Skipping the S3-only checksum

By default, `PutObject` computes two digests over the same bytes on both
transports: the SHA-256 jay uses for its own integrity checking, and an MD5,
purely to fill the `ETag` field — required, byte-for-byte, to be the MD5 hex
digest of the object for S3 API compatibility. On this CPU, MD5 costs **~45%
of the CPU time** a write spends, more than double the ~21% spent on
SHA-256 — this CPU has hardware acceleration (SHA-NI) for SHA-256 and nothing
equivalent for MD5, which is why the older hash costs more than the modern
one.

S3 clients need that ETag, so jay's HTTP handler always computes it — that is
not negotiable without breaking the compatibility that surface exists for. The
native protocol computes it too by default, for response-shape parity with the
S3 handler, but a native-only client doesn't need S3's ETag semantics.
`falco`, the only native-protocol client in this codebase, generates its own
HTTP `ETag` independently and never reads jay's.

`PutOptions.SkipETag` (both `proto/client` and `internal/objops`) makes that
MD5 pass optional, defaulting to `false`: every caller that doesn't set it
gets the ETag computed exactly as before. The field is trailing and optional
on the wire — `DecodePutObjectRequest` only reads it when the buffer has more
to read — so a client and server can be upgraded independently, in either
order, and each falls back to computing the ETag when the other side doesn't
know about the field. `ChecksumSHA256` is unaffected either way; it was never
in question, and the store's own integrity checking never depended on MD5.

## Why writes cost what they cost

A write is two `fsync` calls — one for the object's temp file, one for the
parent directory after the rename — plus one bbolt transaction. That ordering is
what makes a crash recoverable, and it is not negotiable for the sake of a
benchmark.

What *is* optimised is everything around it: the SHA-256, the MD5 (unless
`SkipETag` drops it), and any client-declared digest are computed in the
**same pass** over the bytes, hashers come from a pool rather than being
allocated per request, and the object record and the bucket's statistics
commit in **one** transaction rather than two.

Bucket statistics are counters updated inline, not a `ForEach` scan — an `O(1)`
read where it used to be `O(n)` in the number of objects. `ListObjects` decodes
only the page being returned, after collecting the keys.

## Reproducing this

```bash
git clone https://github.com/ivangsm/jay.git && cd jay
./scripts/bench-compare.sh -count 5
```

The suite covers Put, Get, Head, Delete, List and multipart on both transports,
at 1 KB, 64 KB, 1 MB and 10 MB, with 1, 4 and 16 real goroutines in flight on
both sides, plus `BenchmarkNativePutObjectSkipETag` for the `SkipETag`
numbers above. It runs against the real server — bbolt, the store, startup
recovery, authentication and the admin API — not against mocks. The
`PutObject` rows above use `-count 20`: telling a real ~1-3% effect apart from
noise at 1MB/10MB needs more samples than the rest of this page.

:::caution[Size your connection pool]
Both clients pool connections, and a pool smaller than your concurrency turns a
throughput benchmark into a TCP handshake benchmark. Go's default HTTP transport
keeps only **two** idle connections per host; at 16-way concurrency that closes
14 of every 16 connections and can exhaust the ephemeral port range under
sustained load. The same applies to your application, on any OS: size your
pool above your highest expected concurrency, the way `benchHTTPClient` in
this benchmark does.
:::
