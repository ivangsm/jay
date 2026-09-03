---
title: Native protocol
description: Frame layout, handshake, opcodes and status codes of Jay's binary transport.
---

A compact binary protocol over TCP, spoken by the Go client and by Jay's own
CLI. For how to use it, see
[the native protocol guide](/jay/guides/native-protocol/).

All integers are **big-endian**.

## Handshake

The client opens with 8 fixed bytes followed by its credentials:

```
[4B magic] [1B version] [1B flags] [2B auth_len]  then auth_len bytes
```

`magic` is `0x4A415900` — the ASCII `JAY\0`. `version` is `0x01`. The credential
payload is `token_id:secret`.

The server answers with 8 bytes:

```
[4B magic] [1B version] [1B status] [2B reserved]
```

| Handshake status | Meaning |
|---|---|
| `0x00` | Accepted |
| `0x01` | Authentication failed |
| `0x02` | Protocol version mismatch |

A peer whose version is not recognised is refused rather than guessed at. On
authentication failure the server drains up to 10 MiB of whatever the client
already sent before closing, so a client that streamed a body into a rejected
connection gets a clean close instead of a reset.

## Frame header

Every request and response frame starts with the same 17 bytes:

```
[1B op/status] [4B stream_id] [4B meta_len] [8B data_len]
```

The header is followed by `meta_len` bytes of metadata and then `data_len` bytes
of body. Metadata is capped at **1 MiB**.

Metadata uses a binary encoding — length-prefixed strings and big-endian
integers — not JSON. That is what removed roughly a fifth of the allocations on
a `GetObject`.

## Opcodes

| Code | Operation |
|---|---|
| `0x01` | CreateBucket |
| `0x02` | DeleteBucket |
| `0x03` | HeadBucket |
| `0x04` | ListBuckets |
| `0x10` | PutObject |
| `0x11` | GetObject |
| `0x12` | HeadObject |
| `0x13` | DeleteObject |
| `0x14` | ListObjects |
| `0x20` | CreateMultipartUpload |
| `0x21` | UploadPart |
| `0x22` | CompleteMultipartUpload |
| `0x23` | AbortMultipartUpload |
| `0x24` | ListParts |
| `0xFF` | Ping |

## Response status

| Code | Meaning |
|---|---|
| `0x00` | OK |
| `0x01` | Not found |
| `0x02` | Conflict |
| `0x03` | Bad request |
| `0x04` | Forbidden |
| `0x05` | Internal error |

## Server limits

| Limit | Value |
|---|---|
| Concurrent connections | 1000 |
| Handshake timeout | 10 s |
| Idle timeout | 60 s |
| Read/write deadline | 30 s floor, plus 1 MB/s of the declared transfer size |
| Shutdown grace | 5 s |
| Rate limiting | Per token ID, shared across that token's connections |

Both ends use 64 KiB buffered readers and writers.

## Why a GetObject body is fast

On a read, the server writes the frame header and metadata through its buffered
writer and **flushes before the body**, then copies the file straight to the raw
connection. That hands the copy to `sendfile(2)`, so the object's bytes go from
page cache to socket without passing through the process.

The same reason explains why a read does not re-verify its checksum: hashing on
the way out would mean pulling every byte back into userspace. Integrity is the
[scrubber's](/jay/internals/architecture/) job.
