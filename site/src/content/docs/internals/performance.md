---
title: Performance
description: Measured S3-versus-native benchmarks, and the design decisions behind the numbers.
---

Everything below was measured, not estimated. The command that produced it is at
the bottom of the page; run it on your own hardware before trusting anyone's
numbers, including these.

:::note[Where these came from]
Apple M4, 10 cores, 16 GB RAM · macOS · Go 1.27.0 · Jay development tree after
0.10.0 · `go test -bench -count 5`, medians reported.

**This is a laptop with an SSD, not a server.** The absolute numbers say more
about this machine than about Jay; the *ratios* between the two protocols are
the part that transfers.
:::

## S3 HTTP versus the native protocol

### Sequential reads

| Operation | S3 HTTP | Native | Native is | S3 throughput | Native throughput |
|---|---|---|---|---|---|
| GetObject, 1KB | 70.9 µs | 43.2 µs | **1.64× faster** | 14 MB/s | 24 MB/s |
| GetObject, 64KB | 83.9 µs | 52.3 µs | **1.61× faster** | 781 MB/s | 1.2 GB/s |
| GetObject, 1MB | 193.2 µs | 141.8 µs | **1.36× faster** | 5.3 GB/s | 7.2 GB/s |
| GetObject, 10MB | 1.55 ms | 1.21 ms | **1.28× faster** | 6.6 GB/s | 8.5 GB/s |
| HeadObject | 51.7 µs | 27.7 µs | **1.87× faster** | — | — |
| ListObjects, 1000 keys | 1.17 ms | 981.6 µs | **1.19× faster** | — | — |

### Sequential writes

| Operation | S3 HTTP | Native | Native is | S3 throughput | Native throughput |
|---|---|---|---|---|---|
| PutObject, 1KB | 17.89 ms | 21.44 ms | 1.20× slower | 0 MB/s | 0 MB/s |
| PutObject, 64KB | 17.71 ms | 18.55 ms | the same | 4 MB/s | 4 MB/s |
| PutObject, 1MB | 21.49 ms | 22.17 ms | the same | 49 MB/s | 47 MB/s |
| PutObject, 10MB | 42.75 ms | 46.72 ms | 1.09× slower | 245 MB/s | 224 MB/s |
| DeleteObject | 9.92 ms | 8.39 ms | **1.18× faster** | — | — |
| Multipart upload | 153.78 ms | 152.91 ms | the same | 102 MB/s | 103 MB/s |

### Concurrent reads

| Operation | S3 HTTP | Native | Native is | S3 throughput | Native throughput |
|---|---|---|---|---|---|
| GetObject 1KB, 1 in flight | 26.3 µs | 74.1 µs | 2.82× slower | 39 MB/s | 14 MB/s |
| GetObject 1KB, 4 in flight | 23.8 µs | 27.1 µs | 1.14× slower | 43 MB/s | 38 MB/s |
| GetObject 1KB, 16 in flight | 25.7 µs | 14.9 µs | **1.72× faster** | 40 MB/s | 69 MB/s |
| GetObject 64KB, 1 in flight | 31.8 µs | 51.1 µs | 1.61× slower | 2.0 GB/s | 1.3 GB/s |
| GetObject 64KB, 4 in flight | 29.7 µs | 29.7 µs | the same | 2.2 GB/s | 2.2 GB/s |
| GetObject 64KB, 16 in flight | 30.4 µs | 16.1 µs | **1.89× faster** | 2.1 GB/s | 4.0 GB/s |
| GetObject 1MB, 1 in flight | 99.3 µs | 159.6 µs | 1.61× slower | 10.3 GB/s | 6.4 GB/s |
| GetObject 1MB, 4 in flight | 100.9 µs | 74.8 µs | **1.35× faster** | 10.2 GB/s | 13.7 GB/s |
| GetObject 1MB, 16 in flight | 109.1 µs | 55.6 µs | **1.96× faster** | 9.4 GB/s | 18.4 GB/s |

### Concurrent writes

| Operation | S3 HTTP | Native | Native is | S3 throughput | Native throughput |
|---|---|---|---|---|---|
| PutObject 1KB, 1 in flight | 15.95 ms | 16.73 ms | the same | 0 MB/s | 0 MB/s |
| PutObject 1KB, 4 in flight | 21.13 ms | 16.05 ms | **1.32× faster** | 0 MB/s | 0 MB/s |
| PutObject 1KB, 16 in flight | 21.26 ms | 15.75 ms | **1.35× faster** | 0 MB/s | 0 MB/s |
| PutObject 64KB, 1 in flight | 21.41 ms | 17.53 ms | **1.22× faster** | 3 MB/s | 4 MB/s |
| PutObject 64KB, 4 in flight | 21.77 ms | 15.99 ms | **1.36× faster** | 3 MB/s | 4 MB/s |
| PutObject 64KB, 16 in flight | 22.20 ms | 15.62 ms | **1.42× faster** | 3 MB/s | 4 MB/s |
| PutObject 1MB, 1 in flight | 29.82 ms | 21.85 ms | **1.37× faster** | 35 MB/s | 48 MB/s |
| PutObject 1MB, 4 in flight | 25.99 ms | 19.75 ms | **1.32× faster** | 40 MB/s | 53 MB/s |
| PutObject 1MB, 16 in flight | 25.98 ms | 28.46 ms | 1.10× slower | 40 MB/s | 37 MB/s |

### Allocations per operation

| Operation | S3 HTTP | Native | Reduction |
|---|---|---|---|
| GetObject | 396 | 259 | 35% |
| HeadObject | 370 | 246 | 34% |
| PutObject | 520 | 374 | 28% |
| Multipart upload | 1638 | 847 | 48% |

## Reading the results

**Reads are where the native protocol earns its place.** Between 1.28× and 1.87×
on a single connection, and up to 1.96× with 16 reads in flight. The gap comes
from what HTTP makes you do around the same `sendfile(2)` call: parse headers,
build a response, verify a signature that re-hashes the request.

**Sequential writes are a tie, and S3 is marginally ahead.** That is not a
protocol result — it is the disk. Every write does two `fsync` calls, and 17 to
21 ms of `fsync` swamps whatever the wire format costs. If your workload is
write-heavy and sequential, the native protocol will not make it faster. Say so
rather than let a benchmark table imply otherwise.

**Under concurrency the picture changes**, because that is where the framing
cost stops being hidden behind disk latency: 1.35× to 1.42× on concurrent writes
and up to 1.96× on concurrent reads.

**The `conc1` rows are a harness artifact, not a property of Jay.** The native
client is *slower* there than in its own sequential benchmark — 74 µs against
43 µs for the same 1 KB read. A single-parallelism `RunParallel` pass through a
connection pool measures the pool warming up, not steady state. The `conc4` and
`conc16` rows are the ones to read.

**Allocations are consistently about a third lower** on the native protocol,
which is the binary metadata encoding rather than JSON, plus pooled frame
buffers.

## Why reads are fast

**`sendfile(2)` on both transports.** `GetObject` hands the open file to the
kernel: over HTTP through a `ReadFrom` on the response writer, over the native
protocol by flushing the frame prelude and then copying to the raw connection.
The object's bytes go from page cache to socket without passing through the
process. The 6.6 GB/s the HTTP path reaches on 10 MB objects is that call, not
Go code.

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

## Why writes cost what they cost

A write is two `fsync` calls — one for the object's temp file, one for the
parent directory after the rename — plus one bbolt transaction. That ordering is
what makes a crash recoverable, and it is not negotiable for the sake of a
benchmark.

What *is* optimised is everything around it: the SHA-256 and any client-declared
digest are computed in the **same pass** over the bytes, the hasher comes from a
pool rather than being allocated per request, and the object record and the
bucket's statistics commit in **one** transaction rather than two.

Bucket statistics are counters updated inline, not a `ForEach` scan — an `O(1)`
read where it used to be `O(n)` in the number of objects. `ListObjects` decodes
only the page being returned, after collecting the keys.

## Reproducing this

```bash
git clone https://github.com/ivangsm/jay.git && cd jay
./scripts/bench-compare.sh -count 5
```

The suite covers Put, Get, Head, Delete, List and multipart on both transports,
at 1 KB, 64 KB, 1 MB and 10 MB, with 1, 4 and 16 operations in flight. It runs
against the real server — bbolt, the store, startup recovery, authentication and
the admin API — not against mocks.

:::caution[Size your connection pool]
Both clients pool connections, and a pool smaller than your concurrency turns a
throughput benchmark into a TCP handshake benchmark. Go's default HTTP transport
keeps only **two** idle connections per host; at 16-way concurrency that closes
14 of every 16 connections and, on macOS, eventually exhausts the ephemeral port
range. The same applies to your application.
:::
