---
title: What Jay is
description: An embedded object store in Go with two protocols, one metadata file and a deliberately short list of features.
---

Jay is an object storage server you run as a single process. Metadata lives in
one [bbolt](https://github.com/etcd-io/bbolt) file, object bytes live on the
filesystem, and the whole state of the server is one directory. There is no
database to provision, no message broker to point it at, and no cache to warm.

It speaks two protocols over the same storage engine:

- An **S3-compatible HTTP API**, so the AWS CLI, boto3 and the AWS SDKs work
  against it unchanged.
- A **binary protocol** with a Go client, for callers that would rather not pay
  for HTTP framing, XML parsing and re-hashing the body on every request.

Both go through the same authorization layer, so a permission decision cannot be
right on one transport and wrong on the other.

## What you get

- Buckets, objects, server-side copy, `ListObjectsV2`, batch deletes, ranged
  reads and the full multipart lifecycle.
- Tokens scoped by action, bucket and key prefix, with SigV4 and bearer auth.
- Presigned URLs in the standard SigV4 form and in Jay's own form.
- A SHA-256 digest per object, verified on write and re-verified by a background
  scrubber.
- Startup recovery, quarantine, garbage collection and verified hourly backups
  of the metadata file.
- Health probes, JSON access logs with a request ID that appears in every
  response, and a metrics endpoint.

## What you do not get

Jay is small on purpose. It has [no versioning](/jay/internals/limits/), no
ACLs, no lifecycle rules, no server-side encryption and no object lock. Those
answer `501 Not Implemented` — never a `200` that quietly does nothing.

**It does not back up your object bytes.** The hourly snapshot is of the
metadata file; copying `buckets/` somewhere safe is yours to arrange, and Jay
cannot be restored without it. The procedure, in both directions, is in
[Backup and restore](/jay/guides/backup-and-restore/).

It also has no external dependencies at runtime and four in `go.mod`: bbolt,
`golang.org/x/crypto`, `golang.org/x/time` and `gopkg.in/yaml.v3`.

## When it fits

Jay is a good fit when you want S3 semantics without operating MinIO or paying
for S3: a single-node object store for an application's uploads, a build cache,
a media backend, or a local stand-in for S3 in development and CI.

It is a poor fit when you need multi-node replication, erasure coding, object
versioning, or any of the S3 features listed above. Those are not on the
roadmap; Jay would rather be honest about the surface it has than grow a
half-working version of a big one.

## The one compatibility caveat to know upfront

minio-go clients — `mc` and `warp` — **cannot upload over plain HTTP**. They
sign non-TLS uploads with SigV4's streaming mode, which frames the body in
`aws-chunked`, and Jay refuses that framing with `501` rather than storing it
raw. Over HTTPS the same clients work completely, uploads included. The full
explanation is in [S3 compatibility](/jay/reference/s3-compatibility/).

Everything else — aws-cli, the AWS SDKs, boto3 — works over both.
