---
title: Limits
description: What Jay does not do, and what it will refuse rather than fake.
---

Jay is small on purpose. This page is the list of things it will not do, so you
can rule it out quickly if you need one of them.

## No object versioning

A `PUT` over an existing key replaces the record and deletes the previous file.
The overwritten bytes are gone.

The hourly backup covers **metadata only**, so it does not get them back either.
If you need old versions, keep them under distinct keys or use something else.

## Jay does not back up your objects

The hourly snapshot is of `meta/jay.db` and nothing else. There is no
replication, no sync-out and no remote target for the bytes under `buckets/` —
copying that directory somewhere safe is your job, and Jay cannot be restored
without it.

Everything Jay does have — per-object checksums, the incremental scrubber,
quarantine instead of deletion, startup reconciliation, readiness that fails on
low disk — **detects** damage. None of it repairs any. The procedure that does
is in [Backup and restore](/jay/guides/backup-and-restore/).

## No replication or erasure coding

Jay is a single node over a single directory. There is no clustering, no
sharding across machines and no redundancy beyond whatever your filesystem and
your backups provide.

## No events

Jay does not publish to a message broker and does not consume from one. Every
interaction is synchronous, and the complete state of the server is
`JAY_DATA_DIR`. There is no relational database and no external cache.

## S3 features that answer 501

Versioning, ACL, tagging, lifecycle, CORS, policy endpoints, encryption, object
lock, `GetObjectAttributes` and `SelectObjectContent`.

They answer `501 Not Implemented` — never a `200` that quietly does nothing. See
[S3 compatibility](/jay/reference/s3-compatibility/) for the whole list.

## Bucket policies are configured off the S3 port

`PutBucketPolicy` answers `501` and always will: Jay's policy dialect is its
own, so serving the S3 operation would mean translating between two models that
do not line up. Policies and bucket visibility are installed through the
[admin API](/jay/reference/admin-api/) instead, which is where the rest of the
operator surface already lives.

## aws-chunked bodies are refused

SigV4's streaming upload mode is answered with `501`, which means **`mc` and
`warp` cannot upload over plain HTTP**. Over HTTPS they work completely. The
reasoning is in
[S3 compatibility](/jay/reference/s3-compatibility/).

## No Windows build

The readiness probe checks free disk space with `syscall.Statfs`, which does not
exist on Windows. Releases ship `linux/amd64`, `linux/arm64` and `darwin/arm64`.

## Signed uploads are capped at 32 MiB

SigV4 recomputes the hash of the body and compares it against the declared one,
which means buffering. Larger uploads have to use `UNSIGNED-PAYLOAD`, multipart,
or the [native protocol](/jay/guides/native-protocol/), which has no such limit.

## The native protocol has no TLS

The handshake carries `token_id:secret` in the clear. It is meant for an
internal network. If you do not use it, set `JAY_NATIVE_ADDR` to empty and the
listener never opens.
