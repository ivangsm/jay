---
title: S3 compatibility
description: The complete list of implemented operations, what answers 501, and how the claim is verified.
---

"S3-compatible" here is a specific list, not a boast. This table is the whole
surface. Everything else answers `501 Not Implemented` — never a misleading
`200`.

## Implemented operations

| Operation | Method | Path |
|---|---|---|
| ListBuckets | `GET /` | |
| CreateBucket | `PUT /<bucket>` | |
| HeadBucket | `HEAD /<bucket>` | |
| DeleteBucket | `DELETE /<bucket>` | |
| GetBucketLocation | `GET /<bucket>?location` | Always the empty `<LocationConstraint/>` (us-east-1) |
| ListObjectsV2 | `GET /<bucket>?list-type=2` | |
| DeleteObjects | `POST /<bucket>?delete` | Batch delete, up to 1000 keys |
| PutObject | `PUT /<bucket>/<key>` | Verifies `Content-MD5` and `x-amz-checksum-*` when sent |
| GetObject | `GET /<bucket>/<key>` | Range: `bytes=0-499`, suffix, open-ended |
| HeadObject | `HEAD /<bucket>/<key>` | |
| DeleteObject | `DELETE /<bucket>/<key>` | |
| CopyObject | `PUT /<bucket>/<key>` | With `x-amz-copy-source`. `x-amz-checksum-algorithm` returns that digest inside `<CopyObjectResult>` |
| CreateMultipartUpload | `POST /<bucket>/<key>?uploads` | `x-amz-checksum-algorithm` is refused if Jay cannot compute it, rather than ignored |
| UploadPart | `PUT /<bucket>/<key>?uploadId=X&partNumber=N` | Same digest verification as `PutObject` |
| CompleteMultipartUpload | `POST /<bucket>/<key>?uploadId=X` | A whole-object `x-amz-checksum-*` answers `501`; the parts are what get verified |
| AbortMultipartUpload | `DELETE /<bucket>/<key>?uploadId=X` | |
| ListParts | `GET /<bucket>/<key>?uploadId=X` | |
| ListMultipartUploads | `GET /<bucket>?uploads` | `prefix`, `delimiter`, `key-marker`, `upload-id-marker`, `max-uploads`, `encoding-type` |

Multipart uploads accept up to 10,000 parts.

## What answers 501

Versioning, ACL, tagging, lifecycle, CORS, policy, encryption, object lock,
`GetObjectAttributes` and `SelectObjectContent`.

`PutBucketPolicy` is on that list and stays there, but bucket policies
themselves are **not** unimplemented: they are configured through the
[admin API](/jay/reference/admin-api/). Jay's policy dialect is its own —
`subjects`/`prefixes`/`actions` rather than `Principal`/`Resource`/`Action` — so
serving the S3 operation would mean either translating between two models that
do not line up, or answering an S3 call with a document no S3 client can read.
Bucket visibility has no S3 operation at all; the nearest, `PutBucketAcl`, is a
third model again.

The dispatch rule is asymmetric on purpose. On `PUT`, `POST` and `DELETE` any
unrecognised sub-resource is refused, because guessing wrong destroys an object.
On `GET` and `HEAD` a denylist is enough, because guessing wrong only returns
the bytes instead of an XML document.

That asymmetry is not theoretical: the earlier version dispatched by method, so
`PUT /bucket/key?tagging` overwrote the object with the tagging XML and answered
`200`.

## aws-chunked streaming uploads are not supported

SigV4 has a streaming mode: the client declares
`x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (or a
`STREAMING-*-TRAILER` variant) and sends the body wrapped in `aws-chunked`
framing — `<hex-size>;chunk-signature=<sig>\r\n<data>\r\n`, repeated until a
zero-length chunk.

**Jay has no decoder for that framing, so it refuses the mode.** Any request
carrying it answers `501` and writes nothing: no object, no metadata, no temp
file. The refusal happens before authentication, so it costs the same on every
entry point that takes a body and under every credential form. All three
announcements are treated as framing, because a client may send any of them:
`x-amz-content-sha256: STREAMING-*`, `x-amz-decoded-content-length`, and
`Content-Encoding: aws-chunked`.

Refusing is not the ideal answer. It is the honest one. Jay used to *recognise*
the mode — SigV4 skipped the payload check for `STREAMING-*` — and then store
the body verbatim. A 15-byte file uploaded with `mc` became a 187-byte object
whose content began `f;chunk-signature=…`, answered `200`, and carried an ETag
and a SHA-256 computed over the corrupted bytes. Nothing could detect it
afterwards: the scrubber verified the object against its own bad digest and
reported it healthy forever.

### What it means per client

| Client | Status |
|---|---|
| **AWS CLI**, AWS SDKs, boto3 | Fully working, up and down, single-part and multipart, with or without `--checksum-algorithm`. They send a real payload hash |
| **minio-go over plain HTTP** — `mc`, `warp` | **Uploads fail** with `501`. Downloads, listings, `stat`, presigned URLs and deletes work normally |
| **minio-go over HTTPS** — same clients | **Fully working**, uploads included. minio-go only reaches for the streaming signature when the connection is not secure |
| **Presigned URLs**, both styles | Working. A presigned `PUT` that adds framing is refused like any other |
| **Jay's CLI and native protocol** | Unaffected. The native protocol has no SigV4 and no framing |

The practical workaround, if you need `mc` for uploads, is to
[put Jay behind TLS](/jay/guides/deployment/) rather than to wait for the
decoder.

## Checksums

Every object carries a SHA-256 digest computed while the bytes are written.
`PutObject`, `GetObject` and `HeadObject` return it as `x-amz-checksum-sha256`,
**base64 of the raw digest**, which is what S3 defines and what the AWS CLI
verifies on every download. Internally the digest is hex — that is what the
scrubber compares, what the native protocol carries and what `jay ls -l` prints.

A ranged `GET` (`206`) carries **no** checksum header. The digest covers the
whole object, so a client verifying it against a slice would reject a perfectly
good transfer — which is every download the AWS CLI splits above its 8 MiB
threshold.

### A declared digest is verified

| What arrives | Answer |
|---|---|
| A digest that matches the bytes | `200`, and the response carries the digest for the algorithm that was asked about |
| A digest that does not match | `400 BadDigest`, and **nothing is written** |
| A malformed `Content-MD5` | `400 InvalidDigest` |
| A malformed `x-amz-checksum-*`, two at once, or one that disagrees with `x-amz-sdk-checksum-algorithm` | `400 InvalidRequest` |
| An algorithm Jay cannot compute | `400 InvalidRequest`, never a `200` carrying some other algorithm |

All five algorithms S3 defines for object payloads are implemented: **CRC32,
CRC32C, CRC64NVME, SHA1 and SHA256**. CRC64NVME matters more than it looks — it
is what the AWS CLI declares on every upload it makes.

"Nothing is written" is the load-bearing half, and it is verified against the
data directory rather than against the response. The check runs between the
`fsync` and the `rename`, so a refused upload never becomes a file under
`buckets/`, never leaves a temp file and never commits metadata. Because a
part's path is derived from its number, refusing before the rename is also what
keeps a bad retry from destroying a part that was already accepted.

### CopyObject computes the digest it was asked for

A copy carries no digest to verify — the bytes never left the server, so the
client has nothing to hash. What it can carry is
`x-amz-checksum-algorithm`, which is a request for a digest in the *response*,
and Jay answers it:

| What arrives | Answer |
|---|---|
| `x-amz-checksum-algorithm: CRC32` (or any of the five) | `200` with `<ChecksumCRC32>` inside `<CopyObjectResult>`, computed over the copied bytes |
| An algorithm Jay cannot compute | `400 InvalidRequest`, and **nothing is copied** |
| No header at all | `200` with `<ETag>` and `<LastModified>` only, exactly as before |

The digest goes in the body, not in a header: it describes the object that was
just written, not the (empty) request. Exactly one element is ever populated —
the algorithm that was named. The hashing happens in the same pass that writes
the bytes, so a copy with a checksum costs no extra read.

Two things Jay deliberately does not do:

- **`CompleteMultipartUpload` refuses a whole-object checksum with `501`.** S3
  composes that value from the part digests; Jay does not implement the
  composition, and accepting the header would answer `200` to a verification
  that never happened. Each part is verified instead.
- **The extra digest is not persisted.** A `PutObject` declaring CRC32 gets its
  CRC32 back in that response, but only the SHA-256 is stored. The same holds
  for a copy: the response is computed live, and re-reading the object later
  gives back the SHA-256 alone.

## DeleteObjects

Every key of the request comes back in `<Deleted>` or in `<Error>`, never
omitted: a key that could not be deleted has to be visible to the caller, or a
partial delete reads as a success. `<Quiet>true</Quiet>` suppresses the
successes only — errors are always reported.

The token's actions, bucket scope and prefix scope, and the bucket policy, are
evaluated **per key**. A key outside the caller's reach is an `<Error>` with
`AccessDenied`, not a delete.

| Limit | Behaviour |
|---|---|
| More than 1000 keys | `400 MalformedXML` |
| Body over 4 MiB | `400 MaxMessageLengthExceeded` |
| Malformed or empty `<Delete>` | `400 MalformedXML` |
| `<VersionId>` on an entry | Per-key `<Error>` with `NotImplemented` |

Each of those refuses the whole batch rather than applying part of it.

## How the claim is verified

Everything on this page is checked by `scripts/conformance.sh`, which runs on
every CI build. It boots two throwaway Jays — one plain HTTP, one TLS, both on
random high ports, both deleted on exit — and drives them with clients Jay did
not write.

| Client | What it exercises |
|---|---|
| **aws-cli** (botocore) | `mb`/`rb --force`, `cp` up and down, `sync`, `rm --recursive`, `ListObjectsV2` with prefix and delimiter, multipart upload and ranged download of a 12 MiB object, `presign` including an expired URL, `GetBucketLocation`, `ListMultipartUploads`, `DeleteObjects` whole and partial, a `501` sub-resource, and that `--checksum-algorithm` answers with the algorithm it asked for — all five, on `put-object` and on `copy-object`, the copy compared against the digest the upload returned for the same bytes |
| **curl** | That a deliberately wrong digest is refused and writes nothing. No correct client would ever send one, so it has to be forged by hand |
| **aws-cli, second account** | That a token of account B can neither list, read, write, delete nor batch-delete inside a bucket of account A — each asserted against A's own view of the bucket, not against B's error message |
| **mc** (minio-go) over HTTP | Listing, `stat`, `get`, bucket create/delete, `rm`, a presigned URL minted by minio-go, and that an upload is refused with `501` leaving nothing behind |
| **mc** over HTTPS | That the same client uploads fine over TLS, small and 12 MiB, byte for byte |
| **warp** (minio-go) | That `warp put` over HTTP is refused and writes nothing, and that `warp mixed` over TLS runs PUT/GET/DELETE/STAT with zero errors |

Three things about how it reports:

- **`SKIP` is not `PASS`.** A missing client skips its group and says so; a run
  where every client group skipped exits `2` with `NOTHING WAS PROVEN`. A green
  exit that tested nothing is the failure mode this project cares about most.
- **Every check asserts an effect** — bytes on the wire, an object present or
  absent, a status code — never a confirmation message. `aws s3 cp --quiet`
  hides its own failure line, so the checks read the exit code and then ask the
  server what actually happened.
- **The known limitations are asserted, not tolerated.** The `mc` and `warp`
  upload refusals are checks that pass *because* the answer is `501` and nothing
  was written. If the `aws-chunked` decoder ever lands, they go red on purpose,
  so nobody can ship it without updating this page.
