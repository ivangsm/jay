---
title: Native protocol v1
description: The wire contract of Jay's binary transport — handshake, framing, encoding, errors and what may change without breaking a peer.
---

A compact binary protocol over TCP, spoken by the Go client and by Jay's own
CLI. For how to use it, see
[the native protocol guide](/jay/guides/native-protocol/).

This page is the **contract**, not a description of the current
implementation. Where the two ever disagree, this page is the bug report.

:::caution[v1 is frozen]
Everything on this page is fixed. A layout described here does not change —
not to add a field, not to reorder one, not to widen an integer. What is
missing is added as a **new opcode**, or waits for v2. See
[Compatibility](#compatibility) for why that rule is stricter than it looks.

The rule is enforced by byte-exact golden tests in `proto/wire_golden_test.go`.
They are not documentation of what the encoder happens to do; they are the
copy of this page that fails a build.
:::

All integers are **big-endian**. All strings are UTF-8, length-prefixed, and
never NUL-terminated.

## Handshake

The client opens with 8 fixed bytes followed by its credentials:

```
[4B magic] [1B version] [1B flags] [2B auth_len]  then auth_len bytes
```

| Field | Value |
|---|---|
| `magic` | `0x4A415900` — ASCII `JAY\0` |
| `version` | `0x01` |
| `flags` | Reserved. Senders MUST write `0x00`; receivers MUST ignore the byte entirely |
| `auth_len` | Length of the credential payload. MUST be non-zero, so at most 65535 bytes |

The server answers with 8 bytes:

```
[4B magic] [1B version] [1B status] [2B reserved]
```

`reserved` is written as zero and MUST be ignored by the client.

| Status | Name | Meaning |
|---|---|---|
| `0x00` | OK | Authenticated; the connection may now carry frames |
| `0x01` | AuthFailed | Credentials rejected, **or** not shaped as `token_id:secret` |
| `0x02` | VersionMismatch | Magic matched, version byte did not |
| `0x03` | ServerBusy | Connection limit reached. No credential was examined |
| `0x04` | Malformed | Bad magic — something that is not a Jay client dialled this port |

Two properties of that table are contract, not implementation detail:

- **A status is a diagnosis.** `VersionMismatch` means the version byte and
  nothing else. It used to be the answer to every handshake failure including a
  severed socket, which made the one thing the client reported the one thing
  that was almost never true.
- **A torn socket gets no answer at all.** If the handshake cannot be read
  because the peer went away, the server closes without writing. Absence of a
  response is therefore *not* a status — a client that sees EOF here saw a
  network failure, or the one flood case described below, never a rejection
  of its credentials.

`ServerBusy` is answered **before** the client's handshake is read. The reply is
self-describing and the client is already blocked waiting for exactly these
bytes, so the exchange completes; it just completes with a refusal.

The server then half-closes and reads out whatever the client sent, until the
client hangs up or 2 seconds pass. That is not politeness: the client's
handshake is usually already in the server's receive buffer, and closing a
socket with unread data makes the kernel send a reset. Linux and macOS still
deliver the status that arrived before a reset, but a TCP stack is allowed to
discard received data once one follows, and the status is the only thing the
refusal exists to say. With the half-close the connection ends in a FIN.

Refusing takes its own goroutine, never the accept loop — over TLS the status
cannot be written before a TLS handshake, which waits on the peer's
ClientHello — and at most **64** refusals are in flight at once. A connection
that arrives while all 64 are busy is closed without a status. Under that
flood a client sees the EOF it saw before `ServerBusy` existed; the bound is
what keeps a flood past the connection cap from spending the file descriptors
the cap exists to protect.

The whole handshake must finish within **10 seconds**.

### Authentication

The credential payload is `token_id:secret` — a literal ASCII colon, split on
the **first** one, so a secret may itself contain colons. A token ID may not.

Authentication happens **once per connection**, at the handshake. There is no
per-frame credential and no way to change identity on a live connection.

The source IP used for bucket-policy evaluation is the **TCP peer address**,
taken from `RemoteAddr`. This transport does not honour `X-Forwarded-For` or
any other proxy header — it has no headers — and `JAY_TRUST_PROXY_HEADERS` does
not apply to it. Whatever holds the socket is the client.

:::danger[There is no transport security below TLS]
`token_id:secret` crosses the wire as plain bytes. Run the native listener
behind TLS (`JAY_NATIVE_TLS_CERT` / `JAY_NATIVE_TLS_KEY`) or on a private
network — see [the deployment guide](/jay/guides/deployment/).
:::

## Frame header

Every request and response frame starts with the same 17 bytes:

```
[1B op/status] [4B stream_id] [4B meta_len] [8B data_len]
```

| Field | Rule |
|---|---|
| `op/status` | Opcode on a request, status on a response |
| `stream_id` | Reserved in v1 — see [Stream IDs](#stream-ids) |
| `meta_len` | Length of the metadata block. Capped at **1 MiB** (`MaxMetaSize`) |
| `data_len` | Length of the body. Signed 64-bit; a negative value is a protocol error |

**`data_len` has no protocol ceiling.** The limit on a body is policy
(`JAY_MAX_OBJECT_SIZE`), not format, and a deployment that raises it does not
change the wire. Do not infer a maximum object size from this protocol.

The header is followed by `meta_len` bytes of metadata, then `data_len` bytes
of body. Both may be zero.

A frame whose `meta_len` exceeds 1 MiB is a protocol error: the server closes
the connection without answering and without reading the block.

**There is no version byte in the frame header.** The version travels in the
handshake only, so it pins the dialect for the connection and cannot report a
change made to any encoder. This is exactly why the compatibility rules below
are enforced by tests rather than by a version check.

## Metadata encoding

Metadata is a **positional** binary encoding. There are no tags, no field
names, no per-record length, and therefore no way for a decoder to skip a field
it does not understand.

| Type | Layout |
|---|---|
| String | `[2B len][len bytes]` — at most 65535 bytes |
| Int32 | 4 bytes |
| Int64 | 8 bytes |
| Bool | 1 byte: `0x00` false, anything else true |
| String list | `[2B count]` then `count` strings |
| Int list | `[2B count]` then `count` × 4 bytes |
| String map | `[2B count]` then `count` × (string key, string value) |

A collection therefore holds at most 65535 elements, and both limits are hard:
an encoder that overruns either **fails** rather than truncating. A map's
iteration order is not specified and carries no meaning.

### Message layouts

Requests:

| Message | Fields, in order |
|---|---|
| CreateBucket, DeleteBucket, HeadBucket | `bucket` |
| ListBuckets | *(empty)* |
| GetObject, HeadObject, DeleteObject | `bucket`, `key` |
| PutObject | `bucket`, `key`, `content_type`, `metadata` map, `skip_etag` bool † |
| ListObjects | `bucket`, `prefix`, `delimiter`, `start_after`, `max_keys` i32 |
| GetObjectRange ‡ | `bucket`, `key`, `offset` i64, `length` i64 |
| CopyObject ‡ | `src_bucket`, `src_key`, `dst_bucket`, `dst_key` |
| CreateMultipartUpload | `bucket`, `key`, `content_type` |
| UploadPart | `bucket`, `key`, `upload_id`, `part_number` i32 |
| CompleteMultipartUpload | `bucket`, `key`, `upload_id`, `part_numbers` int list |
| AbortMultipartUpload, ListParts | `bucket`, `key`, `upload_id` |
| Ping | *(empty)* |

Responses:

| Message | Fields, in order |
|---|---|
| PutObject, UploadPart | `etag`, `checksum` |
| GetObject, HeadObject, GetObjectRange ‡ | `content_type`, `size` i64, `etag`, `checksum`, `last_modified`, `metadata` map |
| CopyObject ‡ | `etag`, `checksum`, `size` i64, `last_modified` |
| ListObjects | `[2B count]` × (`key`, `size` i64, `etag`, `checksum`, `last_modified`, `content_type`), `common_prefixes` string list, `is_truncated` bool, `next_start_after` |
| ListBuckets | `[2B count]` × (`name`, `created_at`) |
| HeadBucket | `bucket_id`, `name`, `created_at`, `visibility` |
| CompleteMultipartUpload | `etag`, `checksum`, `size` i64 |
| ListParts | `[2B count]` × (`part_number` i32, `size` i64, `etag`, `checksum`) |
| Any error | `message`, `code` |

`checksum` is the SHA-256 of the object as **lowercase hex**. This differs from
the S3 API, where `x-amz-checksum-sha256` is base64 by definition — the
conversion happens in the HTTP layer and does not reach this protocol.

`last_modified` is RFC 3339.

† `skip_etag` is the one **trailing optional** field in v1: a request that ends
after `metadata` decodes it as `false`. See
[Compatibility](#compatibility) for why that direction is safe and the other
one is not.

‡ `GetObjectRange` and `CopyObject` arrived after v1 shipped, as **new
opcodes** — the one compatible way to extend the protocol. A server that does
not know them answers `UnknownOp`; their layouts are as frozen as the others.

For `GetObjectRange`, `length <= 0` means "to the end of the object", and a
length past the end is clamped. The response metadata describes the **whole**
object (`size` is the full size) and the frame's `data_len` is the number of
bytes served. A range that does not intersect the object — `offset` at or past
the end, or any range on an empty object — is `BadRequest` / `InvalidRange`
with no body: the counterpart of HTTP 416.

`CopyObject` copies on the server; the bytes never cross the wire. Content type
and user metadata carry over from the source. The token needs `object:get` on
the source and `object:put` on the destination, and a bucket policy that denies
reading the source denies the copy. A not-found or access error carries the
side it is about (`source:` / `destination:`) at the front of its `message`,
because the error model has no resource field; the `code` is the usual one.

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
| `0x15` | GetObjectRange |
| `0x16` | CopyObject |
| `0x20` | CreateMultipartUpload |
| `0x21` | UploadPart |
| `0x22` | CompleteMultipartUpload |
| `0x23` | AbortMultipartUpload |
| `0x24` | ListParts |
| `0xFF` | Ping |

## Error model

A response carries a status byte and, for anything other than OK, an error
message and a machine-readable code.

| Status | Meaning |
|---|---|
| `0x00` | OK |
| `0x01` | Not found |
| `0x02` | Conflict |
| `0x03` | Bad request |
| `0x04` | Forbidden |
| `0x05` | Internal error |

**Six statuses is the whole set in v1**, and it is coarser than the situations
it describes: "you are being rate limited, retry later" and "your request is
malformed, never retry" are both `0x03`. The distinction survives only in the
code, which is why the code is contract and not a log string.

These codes are part of v1. A client may branch on them:

| Code | Status | Meaning |
|---|---|---|
| `AccessDenied` | Forbidden | Token, account or bucket policy refused the operation |
| `BucketAlreadyExists` | Conflict | — |
| `BucketNotEmpty` | Conflict | — |
| `EntityTooLarge` | Bad request | Body exceeds `JAY_MAX_OBJECT_SIZE` |
| `InternalError` | Internal | — |
| `InvalidArgument` | Bad request | Undecodable metadata, or a value out of range |
| `InvalidBucketName` | Bad request | — |
| `InvalidRange` | Bad request | The range does not intersect the object (HTTP 416) |
| `NoSuchBucket` | Not found | — |
| `NoSuchKey` | Not found | — |
| `NoSuchUpload` | Not found | Unknown or expired multipart upload |
| `RateLimitExceeded` | Bad request | **Retryable.** The only retryable `0x03`. May close the connection — see [Refusing a frame](#refusing-a-frame-without-reading-it) |
| `UnknownOp` | Bad request | Opcode this server does not implement |

The `message` field is for humans and may change at any time. **Never branch on
it.**

## Refusing a frame without reading it

The server decides whether to serve a frame from its 17-byte header, before it
reads the metadata or the body. When it refuses one, it has two ways to keep
the stream aligned — read the rest of the frame and throw it away, or close
the connection — and the choice depends on how much is left:

| Refusal | Read and discarded, connection kept | Answered unread, connection closed |
|---|---|---|
| Rate limited (`RateLimitExceeded`) | `data_len` ≤ **10 MiB**; the metadata is read on top | `data_len` > 10 MiB |
| Any other answer to a frame whose body was not read to the end — an error, or a body sent with an operation that takes none | unread rest of the body ≤ **10 MiB** | unread rest > 10 MiB |

In the Go package these are `RateLimitDrainSize` and `MaxDrainSize`. Both
bound the body alone: the metadata is capped by `MaxMetaSize` either way.

**The answer is always written before the close.** A client refused mid-upload
is told why — `RateLimitExceeded`, `AccessDenied`, `EntityTooLarge` — rather
than finding a connection that dropped without a word.

**Today the two thresholds coincide, for the sake of older clients.**
Every native client up to v0.16.0 was built against a server that drained any
rate-limited body up to 10 MiB, and it pools the connection after every answer
it reads. A server that closed on it after a smaller rate-limited upload would
turn its `RateLimitExceeded` into `broken pipe` and, when the body fitted in the
socket buffers, fail its next request on the connection the server closed. So
the rate limiter keeps the rule those clients know, the body against 10 MiB,
and they see no change.

`RateLimitDrainSize` is meant to come down to 1 MiB (`MaxMetaSize`). A rate
limit fires under load, over and over, and draining 10 MiB per refused upload
costs the server the full body in bandwidth every time; 1 MiB is what the server
already reads from any frame before it knows what the frame is for. That waits
until no client older than the release that introduced `RateLimitDrainSize` is
left. Whatever its value, **a server keeps the connection after a rate-limited
body of up to `MaxMetaSize`**: that floor is what current clients rely on.

**Both thresholds are contract, each for a different reader.** A client decides
from `MaxDrainSize` whether a connection survived an error answer, so lowering
it makes a client built against the old value pool connections the server
closed. `RateLimitDrainSize` is what the clients that predate it rely on;
current clients rely only on its floor. Raising either is safe; lowering either
breaks someone.

What a client has to do about it:

1. **When writing a body fails because the peer closed or reset the
   connection, read the answer before reporting the failure.** The server
   answered before closing, so the answer is in the receive buffer; it is the
   true error, where the socket only knows "broken pipe". An answer read this
   way is never `OK`: a body that was not written whole was not stored.
2. **After an error answer, do not reuse the connection** if the request had
   `data_len` > 10 MiB (`MaxDrainSize`), or if the answer is `RateLimitExceeded`
   and the request had `data_len` > 1 MiB (`MaxMetaSize`). When the body fits in
   the socket buffers the client's write completes before the close arrives, it
   reads a perfectly ordinary answer, and nothing on the wire says the server
   closed. The rule errs toward dropping: a connection the server kept costs one
   reconnect, a dead one in the pool costs a failed request.

The rate-limit half of rule 2 uses the floor, not today's
`RateLimitDrainSize`, on purpose. A client that decided by today's value would
have 10 MiB built in, and would pool connections the server closed on the day
the server lowers it. Deciding by the floor costs a reconnect after a
rate-limited upload between 1 and 10 MiB today, and keeps the client right
about either value.

The Go client does both. A client that predates these rules (v0.16.0 and
earlier) never reports a refused request as a success and never hangs on one.
Against today's thresholds, a rate-limited upload of up to 10 MiB still gets it
`RateLimitExceeded` and a connection that keeps working, as it always did.
Anything refused unread — a larger rate-limited body, or a refused body with
more than 10 MiB left unread — reaches it as a transport error
(`broken pipe`, `connection reset by peer`) instead of the code, because it
does not look behind a failed write; the servers it was built against closed
on those frames too.

## Stream IDs

`stream_id` exists in the header and v1 does not use it. A connection carries
**one request at a time**: the client writes a frame and reads its response
before writing another.

The server echoes the value it received and never interprets it. Clients write
zero. It is reserved for a future multiplexing version and is not a promise
that one is coming.

Concurrency in v1 comes from **more connections**, which is what the client's
pool is for — and note that the per-token rate limit is shared across them, so
extra connections buy parallelism, not budget.

## Cancellation and half-close

**There is no cancel frame, and closing the connection is the only way to
abort.** A client that stops caring about an in-flight response closes; the
server discovers it on the next write and drops the connection.

A half-closed connection is not part of the protocol. `data_len` is declared up
front, so neither side signals end-of-body by shutting down its write side, and
a peer that does so is treated as gone.

This is a real limitation, written down rather than left to be discovered: a
cancelled 5 GiB upload costs the connection.

## Back pressure

v1 defines **no flow control of its own** and relies entirely on TCP's. That
is a decision, not a gap. A connection carries one request at a time and
`stream_id` is always zero, so there is no multiplexing whose streams would
need windows or credits of their own. The server reads a body straight into
the file it is writing, synchronously: when the disk falls behind, the copy
slows, the socket buffer fills, and TCP stops the sender. Nothing queues in
memory because nothing is queued. The same holds in the other direction for a
client that stops reading.

What bounds a stalled peer is deadlines, not back pressure. Both directions
scale their deadline with the declared transfer size: a floor of 30 seconds
plus an allowance of 1 MB/s. A transfer slower than that is cut off; a large
transfer that keeps up is not.

What the server adds on top are **limits**, each with its own answer:

| Limit | Scope | Setting (default) | When exceeded |
|---|---|---|---|
| Concurrent connections | Server | `JAY_NATIVE_MAX_CONNS` (1000) | Handshake status `ServerBusy` |
| Requests per second | Token, shared across its connections | `JAY_RATE_LIMIT` / `JAY_RATE_BURST` (100, burst 200) | `RateLimitExceeded`. A refused body up to 10 MiB is read out and the connection kept; a larger one is not read and the connection closes — see [Refusing a frame](#refusing-a-frame-without-reading-it) |
| Body bytes per second | Token, shared across its connections and both directions | `JAY_NATIVE_TOKEN_BYTES_PER_SEC` (0, no cap) | Nothing is refused: the bytes wait |

The byte cap meters object bodies on the wire — `PutObject` and `UploadPart`
bodies read, `GetObject` and `GetObjectRange` bodies written. Server-side work
that moves no bytes over the connection (`CopyObject`, assembling a multipart
upload) and bodies drained after a refusal are not metered. The wait happens
where the bytes are, so the peer is slowed by TCP exactly as it would be by a
slow disk, and the time the server spends waiting is added to its own
deadline: the cap never makes the server time out its client.

It can make the **client** time out its own request. A client that sizes its
deadlines by an expected throughput — the Go client assumes 1 MiB/s, like the
server's floor — fails a large transfer when the cap, divided among that
token's concurrent transfers, falls below it. Size the cap at or above
1 MiB/s per transfer you expect to run at once, or lower the client's
`Timeouts.BytesPerSec` to match.

These limits exist on this transport only. The S3 API has the request rate
limit and no byte cap.

## Connection lifecycle

| Limit | Value |
|---|---|
| Concurrent connections | 1000 by default (`JAY_NATIVE_MAX_CONNS`) |
| Busy refusals in flight | 64; each ends within 2 s |
| Handshake timeout | 10 s |
| Server idle timeout | 60 s |
| Client pooled-idle discard | 45 s |
| Read/write deadline | 30 s floor, plus 1 MB/s of the declared transfer size |
| Shutdown grace | 5 s |

**The 45 s and the 60 s are a contract, not two independent settings.** The
client discards a pooled connection before the server would have closed it, so
the common race — client sends on a connection the server just reaped — stays
rare instead of becoming the normal path. A client that raises its idle window
above the server's timeout is choosing to hit that race on every quiet period.

It cannot be eliminated, only made rare, so the client also **retries once** on
a pooled connection that failed before any response byte was read. Requests
with a body are excluded: the reader may be partially consumed and cannot be
rewound.

Both ends use 64 KiB buffered readers and writers. Rate limiting is per token
ID, shared across that token's connections.

## Compatibility

The rules, in the order they matter:

1. **Adding an opcode is compatible.** A server that does not know an opcode
   answers `BadRequest` / `UnknownOp` and **keeps the connection open**. That
   is the supported path for new operations, and the one `GetObjectRange`
   (`0x15`) and `CopyObject` (`0x16`) took, without touching the version.
   Presigned URLs needed no opcode at all: the SigV4 form is an HMAC over the
   token secret the client already holds, so the client signs locally.
2. **Changing the layout of an existing message is not compatible**, in any
   direction, including appending a field. The encoding is positional, so a
   peer that reads one field too many consumes the next message's bytes and a
   peer that reads one too few leaves them. Neither produces a clean error.
3. **A trailing optional field is the one narrow exception**, and only one way
   round. A decoder may read a final field *only if bytes remain*, which makes
   **old encoder → new decoder** safe. It does nothing for **new encoder → old
   decoder**: the old decoder stops early and silently ignores the field, so
   the sender cannot tell whether its request was understood. Use it only where
   the default is the pre-existing behaviour, as `skip_etag` does.
4. **Reserved bytes stay ignored.** `flags` in the handshake and `reserved` in
   its response are written as zero and must not be validated. A future version
   that assigns them needs peers that did not reject them.

A change that rule 2 forbids requires `Version = 0x02`, at which point the
handshake refuses old peers instead of corrupting them. That is the entire
purpose of the version byte, and the reason it is checked strictly.

## Why a GetObject body is fast

On a read, the server writes the frame header and metadata through its buffered
writer and **flushes before the body**, then copies the file straight to the raw
connection. That hands the copy to `sendfile(2)`, so the object's bytes go from
page cache to socket without passing through the process.

The same reason explains why a read does not re-verify its checksum: hashing on
the way out would mean pulling every byte back into userspace. Integrity is the
[scrubber's](/jay/internals/architecture/) job.

Wrapping the listener in TLS gives that up — encryption has to see the bytes,
so `sendfile(2)` no longer applies. That is the cost of the safe default on an
untrusted network, and it is the reason TLS is opt-in rather than mandatory.
