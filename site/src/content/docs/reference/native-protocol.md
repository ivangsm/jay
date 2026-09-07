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
  network failure, not a rejection.

`ServerBusy` is answered **before** the client's handshake is read. The reply is
self-describing and the client is already blocked waiting for exactly these
bytes, so the exchange completes; it just completes with a refusal.

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
| CreateMultipartUpload | `bucket`, `key`, `content_type` |
| UploadPart | `bucket`, `key`, `upload_id`, `part_number` i32 |
| CompleteMultipartUpload | `bucket`, `key`, `upload_id`, `part_numbers` int list |
| AbortMultipartUpload, ListParts | `bucket`, `key`, `upload_id` |
| Ping | *(empty)* |

Responses:

| Message | Fields, in order |
|---|---|
| PutObject, UploadPart | `etag`, `checksum` |
| GetObject, HeadObject | `content_type`, `size` i64, `etag`, `checksum`, `last_modified`, `metadata` map |
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
| `NoSuchBucket` | Not found | — |
| `NoSuchKey` | Not found | — |
| `NoSuchUpload` | Not found | Unknown or expired multipart upload |
| `RateLimitExceeded` | Bad request | **Retryable.** The only retryable `0x03` |
| `UnknownOp` | Bad request | Opcode this server does not implement |

The `message` field is for humans and may change at any time. **Never branch on
it.**

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

v1 defines **no flow control of its own** and relies entirely on TCP's. A
reader that stops reading stops the writer through the socket buffer; there are
no windows, credits or pause frames.

What bounds a stalled peer is deadlines, not back pressure. Both directions
scale their deadline with the declared transfer size: a floor of 30 seconds
plus an allowance of 1 MB/s. A transfer slower than that is cut off; a large
transfer that keeps up is not.

## Connection lifecycle

| Limit | Value |
|---|---|
| Concurrent connections | 1000 |
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
   is the supported path for new operations — Range, Copy and Presign will
   arrive this way, without touching the version.
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
