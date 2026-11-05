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
| PutObject | `PUT /<bucket>/<key>` | Verifies `Content-MD5` and `x-amz-checksum-*` when sent. Accepts SigV4 streaming (`aws-chunked`), [decoded and verified](#aws-chunked-streaming-uploads) |
| GetObject | `GET /<bucket>/<key>` | Range: `bytes=0-499`, suffix, open-ended |
| HeadObject | `HEAD /<bucket>/<key>` | |
| DeleteObject | `DELETE /<bucket>/<key>` | |
| CopyObject | `PUT /<bucket>/<key>` | With `x-amz-copy-source`. `x-amz-checksum-algorithm` returns that digest inside `<CopyObjectResult>` |
| CreateMultipartUpload | `POST /<bucket>/<key>?uploads` | `x-amz-checksum-algorithm` is refused if Jay cannot compute it, rather than ignored |
| UploadPart | `PUT /<bucket>/<key>?uploadId=X&partNumber=N` | Same digest verification and streaming support as `PutObject` |
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

## aws-chunked streaming uploads

SigV4 has a streaming mode: instead of hashing the whole payload before sending
it, the client declares one of the `STREAMING-*` literals in
`x-amz-content-sha256` and sends the body wrapped in `aws-chunked` framing —
`<hex-size>;chunk-signature=<sig>\r\n<data>\r\n`, repeated until a zero-length
chunk, optionally followed by a trailer that carries a checksum.
`Content-Length` counts the framing; the payload's own size travels in
`x-amz-decoded-content-length`.

Jay decodes it on `PutObject` and `UploadPart`, and verifies it before a single
byte is committed:

| `x-amz-content-sha256` | What Jay verifies | Who sends it |
|---|---|---|
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` | Every chunk signature, chained from the request signature, the final empty chunk included | SigV4 streaming clients over plain HTTP |
| `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` | The same, plus the trailer's own signature and the checksum it carries | SigV4 streaming clients with trailing checksum |
| `STREAMING-UNSIGNED-PAYLOAD-TRAILER` | The request signature, and the trailing checksum against the bytes | The AWS CLI and SDKs over HTTPS |

What holds in every mode:

- **The body only ends once everything has verified.** Each chunk signature is
  an HMAC over the previous one, so a chunk cannot be dropped, reordered or
  appended without breaking the chain — and the final empty chunk is signed
  too, so the stream cannot be cut short either. The data streams through as it
  arrives (nothing is buffered beyond one chunk header line), but the object is
  committed only after the end of the body, so a failure anywhere — first chunk,
  last chunk, trailer — leaves **nothing written**: no object, no temp file, no
  metadata, and an existing object under the same key untouched.
- **`x-amz-decoded-content-length` is mandatory and binding.** A chunk larger
  than what remains of it is refused before its data is read, and chunks that
  do not add up to it are refused at the end.
- **A trailing checksum is verified like a header one.** All five algorithms
  are supported; the digest is compared against the bytes before the commit,
  and the response echoes it. A trailer other than one checksum is refused
  before the body is read — never accepted and ignored.
- **The framing never reaches the object.** Size, ETag and SHA-256 are those of
  the payload, and `aws-chunked` is removed from `Content-Encoding`.

| What arrives | Answer |
|---|---|
| A chunk or trailer signature that does not verify | `403 SignatureDoesNotMatch`, nothing written |
| Chunks that do not add up to `x-amz-decoded-content-length` | `400 IncompleteBody`, nothing written |
| Malformed framing: a size that is not 1–16 hex digits, a missing CRLF, a header line over 128 bytes, an unknown chunk extension, a body that ends early | `400 InvalidRequest`, nothing written |
| A trailing checksum that does not match the bytes | `400 BadDigest`, nothing written |
| `x-amz-decoded-content-length` missing or not a number, or framing announced without a `STREAMING-*` literal | `400 InvalidRequest`, before a byte is read |

### What still answers 501

Refused before authentication and before a byte is read, like every other
`501`:

- **SigV4a streaming** (`STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD` and its
  `-TRAILER` form). Jay implements no SigV4a at all.
- **Framing under a bearer token or a presigned URL**, either style. The chunk
  chain is seeded by the request signature, and those credentials have none,
  so the chunks could not be verified.
- **Framing on any operation other than `PutObject` and `UploadPart`.** Those
  two are the only ones that commit at the end of the body. A handler that acts
  while it parses — `DeleteObjects` deleting the keys it reads — would act on
  bytes whose chunk has not been verified yet. No client frames those bodies.

### Why it is this strict

The mode was once *recognised* and not decoded: SigV4 skipped the payload check
for `STREAMING-*` and the body was stored verbatim. A 15-byte file uploaded
with `mc` became a 187-byte object whose content began `f;chunk-signature=…`,
answered `200`, and carried an ETag and a SHA-256 computed over the corrupted
bytes — so the scrubber verified it against its own bad digest and reported it
healthy forever. The fix that closed the data loss was to refuse the mode with
`501`; the decoder replaced that refusal. A decoder that accepted the literal
without verifying the chain would have been the same defect with extra steps,
so the literal is accepted only where the body is actually decoded and
verified.

### What it means per client

| Client | Status |
|---|---|
| **AWS CLI**, AWS SDKs, boto3 over HTTP | Fully working. They send a real payload hash, no framing |
| **AWS CLI** over HTTPS | Fully working. Uploads travel as `STREAMING-UNSIGNED-PAYLOAD-TRAILER` with a CRC64NVME trailer, which is decoded and verified. |
| **MinIO clients** — `mc`, `warp`, minio-go | **Not supported.** Jay does not test them and makes no promise about them |
| **Presigned URLs**, both styles | Working. A presigned `PUT` that adds framing answers `501` |
| **Jay's CLI and native protocol** | Unaffected. The native protocol has no SigV4 and no framing |

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
  that never happened. Each part is verified instead. The AWS CLI does not send
  it; `mc cp --checksum` does, on every multipart upload, so that combination
  fails — `mc` aborts the upload and no object is left.
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
| **aws-cli** over HTTPS | Small and 12 MiB multipart uploads in the unsigned-trailer framing, byte for byte |

Three things about how it reports:

- **`SKIP` is not `PASS`.** A missing client skips its group and says so; a run
  where every client group skipped exits `2` with `NOTHING WAS PROVEN`. A green
  exit that tested nothing is the failure mode this project cares about most.
- **Every check asserts an effect** — bytes on the wire, an object present or
  absent, a status code — never a confirmation message. `aws s3 cp --quiet`
  hides its own failure line, so the checks read the exit code and then ask the
  server what actually happened.
- **Every `aws-chunked` check proves which framing it exercised.** The
  client's own debug trace has to show the `STREAMING-*` literal it sent, or the
  check fails: a round trip that never reached the decoder must not be counted
  as one that did.
