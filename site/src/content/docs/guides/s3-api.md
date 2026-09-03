---
title: The S3 API
description: Using Jay with the AWS CLI, boto3, the AWS SDKs and minio-go clients.
---

Jay's S3 API is an HTTP endpoint your existing tooling can point at. There is no
Jay-specific SDK to adopt: the token ID is the access key and the token secret
is the secret key.

The full list of implemented operations lives in
[S3 compatibility](/jay/reference/s3-compatibility/). This page is about driving
it.

## AWS CLI

```bash
aws configure set aws_access_key_id <token_id>
aws configure set aws_secret_access_key <token-secret>
aws configure set default.region us-east-1

aws --endpoint-url http://localhost:9000 s3 mb s3://mybucket
aws --endpoint-url http://localhost:9000 s3 cp file.txt s3://mybucket/
aws --endpoint-url http://localhost:9000 s3 ls s3://mybucket/
aws --endpoint-url http://localhost:9000 s3 sync ./local-dir s3://mybucket/prefix/
aws --endpoint-url http://localhost:9000 s3 rm --recursive s3://mybucket/prefix/
aws --endpoint-url http://localhost:9000 s3 rb --force s3://mybucket
```

The `s3api` subcommands work too, including the ones the high-level `s3` command
never reaches:

```bash
aws --endpoint-url http://localhost:9000 s3api delete-objects --bucket mybucket \
    --delete 'Objects=[{Key=a.txt},{Key=b.txt}]'
aws --endpoint-url http://localhost:9000 s3api list-multipart-uploads --bucket mybucket
aws --endpoint-url http://localhost:9000 s3api get-bucket-location --bucket mybucket
```

The region is not configured server-side. Jay reads it back out of
`X-Amz-Credential`, so any region works as long as the client signs and sends
the same one.

## boto3

```python
import boto3

s3 = boto3.client(
    "s3",
    endpoint_url="http://localhost:9000",
    aws_access_key_id="TOKEN_ID",
    aws_secret_access_key="TOKEN_SECRET",
    region_name="us-east-1",
)

s3.upload_file("photo.jpg", "media", "photo.jpg")
url = s3.generate_presigned_url(
    "get_object",
    Params={"Bucket": "media", "Key": "photo.jpg"},
    ExpiresIn=3600,
)
```

## Which clients work

| Client | Status |
|---|---|
| AWS CLI (`aws s3`, `aws s3api`), AWS SDKs, boto3 | Fully working, up and down, single-part and multipart, with or without `--checksum-algorithm` |
| minio-go over **HTTPS** — `mc`, `warp` | Fully working, uploads included |
| minio-go over **plain HTTP** — `mc`, `warp` | **Uploads fail with `501`.** Downloads, listings, `stat`, presigned URLs and deletes work normally |
| Presigned URLs, both styles | Working |

The minio-go limitation is not arbitrary. Over a non-TLS connection minio-go
signs uploads with SigV4's *streaming* mode, which wraps the body in
`aws-chunked` framing. Jay has no decoder for that framing, so it refuses the
mode instead of storing the frames as if they were your file. Over TLS minio-go
sends an unframed body and everything works.

**If you need `mc` for uploads, the fix is to put Jay behind TLS**, not to wait
for a decoder. The full story, including what went wrong when Jay used to accept
the mode, is in [S3 compatibility](/jay/reference/s3-compatibility/).

## Checksums are verified, not decorated

If you send `Content-MD5` or `x-amz-checksum-*` on an upload, Jay hashes the
body as it writes and compares. A mismatch answers `400 BadDigest` and **writes
nothing** — no object, no metadata, no leftover temp file.

All five algorithms S3 defines for object payloads are implemented: CRC32,
CRC32C, CRC64NVME, SHA1 and SHA256. That last one matters more than it looks —
CRC64NVME is what the AWS CLI declares on every upload it makes.

On the way back, `GetObject` and `HeadObject` return `x-amz-checksum-sha256`,
base64 of the raw digest. A ranged `GET` carries no checksum header at all,
because the digest covers the whole object and a client comparing it against a
slice would reject a perfectly good transfer.

## Ranged reads

```bash
curl -H "$AUTH" -H 'Range: bytes=0-499' http://localhost:9000/media/big.bin
curl -H "$AUTH" -H 'Range: bytes=-500'  http://localhost:9000/media/big.bin
curl -H "$AUTH" -H 'Range: bytes=500-'  http://localhost:9000/media/big.bin
```

## Presigned URLs

Anything that speaks S3 can mint one, and Jay also mints them from the admin
API. Both forms are covered in [Authentication](/jay/reference/authentication/).
