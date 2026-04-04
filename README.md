# Jay

S3-compatible object storage server with a native binary protocol, written in Go.

Jay provides dual API access: a fully S3-compatible HTTP API and a high-performance native binary protocol for Go clients. It uses bbolt for metadata, atomic file writes with SHA-256 checksums, and includes background integrity scrubbing, garbage collection, and automated backups.

## Features

- **S3-compatible HTTP API** -- works with AWS CLI, SDKs, and any S3 client
- **Native binary protocol** -- efficient Go client with connection pooling
- **Multipart uploads** -- S3-compatible chunked uploads up to 10,000 parts
- **Presigned URLs** -- time-limited delegated access via HMAC-SHA256
- **Range requests** -- partial object reads (`bytes=0-499`, suffix, open-ended)
- **CopyObject** -- server-side copy between buckets
- **Bucket policies** -- prefix-based allow/deny rules with IP conditions
- **Token authentication** -- scoped by actions, buckets, and key prefixes
- **AWS SigV4** -- simplified mode for AWS CLI compatibility
- **Integrity scrubbing** -- periodic SHA-256 verification (10% sample/6h)
- **Quarantine** -- automatic isolation of corrupted objects
- **Rate limiting** -- per-token token bucket with configurable rate/burst
- **TLS** -- optional HTTPS for S3 and admin APIs
- **Health checks** -- liveness and readiness probes
- **Metrics** -- JSON endpoint with operation counters and byte totals
- **Backups** -- hourly metadata snapshots with automatic pruning

## Quick Start

### Docker Compose

```bash
export JAY_ADMIN_TOKEN=my-secret-admin-token
export JAY_SIGNING_SECRET=my-signing-secret
docker compose up -d
```

### Build from Source

```bash
go build -o jay .
JAY_ADMIN_TOKEN=my-secret-admin-token ./jay
```

Jay listens on three ports:
- `:9000` -- S3-compatible API
- `:9001` -- Admin API + health checks
- `:4444` -- Native binary protocol

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `JAY_DATA_DIR` | `./data` | Data directory for objects and metadata |
| `JAY_LISTEN_ADDR` | `:9000` | S3 API listen address |
| `JAY_ADMIN_ADDR` | `:9001` | Admin API listen address |
| `JAY_NATIVE_ADDR` | `:4444` | Native protocol listen address |
| `JAY_ADMIN_TOKEN` | *(required)* | Bearer token for admin API |
| `JAY_SIGNING_SECRET` | *(optional)* | Secret for presigned URL generation |
| `JAY_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `JAY_TLS_CERT` | *(optional)* | Path to TLS certificate file |
| `JAY_TLS_KEY` | *(optional)* | Path to TLS private key file |
| `JAY_RATE_LIMIT` | `0` (disabled) | Requests/sec per token |
| `JAY_RATE_BURST` | `200` | Rate limit burst size |

## Authentication

### Create an Account and Token

```bash
# Create account
curl -X POST http://localhost:9001/_jay/accounts \
  -H "Authorization: Bearer $JAY_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "myapp"}'
# Returns: {"account_id": "...", "name": "myapp", ...}

# Create token
curl -X POST http://localhost:9001/_jay/tokens \
  -H "Authorization: Bearer $JAY_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id": "ACCOUNT_ID", "name": "deploy-token"}'
# Returns: {"token_id": "...", "secret": "..."}
```

### Using Tokens

**Bearer token:**
```
Authorization: Bearer <token_id>:<secret>
```

**AWS SigV4 (simplified):** Use `token_id` as the access key and any value as the secret key. Jay validates the token exists but does not verify the HMAC signature.

### Token Scoping

Tokens can be scoped to specific actions, buckets, and key prefixes:

```json
{
  "account_id": "...",
  "name": "readonly",
  "allowed_actions": ["object:get", "object:list"],
  "bucket_scope": ["public-assets"],
  "prefix_scope": ["images/"]
}
```

Available actions: `bucket:list`, `bucket:read-meta`, `bucket:write-meta`, `object:get`, `object:put`, `object:delete`, `object:list`, `multipart:create`, `multipart:upload-part`, `multipart:complete`, `multipart:abort`.

## S3 API

### Supported Operations

| Operation | Method | Path |
|-----------|--------|------|
| ListBuckets | `GET /` | |
| CreateBucket | `PUT /<bucket>` | |
| HeadBucket | `HEAD /<bucket>` | |
| DeleteBucket | `DELETE /<bucket>` | |
| ListObjectsV2 | `GET /<bucket>?list-type=2` | |
| PutObject | `PUT /<bucket>/<key>` | |
| GetObject | `GET /<bucket>/<key>` | |
| HeadObject | `HEAD /<bucket>/<key>` | |
| DeleteObject | `DELETE /<bucket>/<key>` | |
| CopyObject | `PUT /<bucket>/<key>` | `x-amz-copy-source` header |
| CreateMultipartUpload | `POST /<bucket>/<key>?uploads` | |
| UploadPart | `PUT /<bucket>/<key>?uploadId=X&partNumber=N` | |
| CompleteMultipartUpload | `POST /<bucket>/<key>?uploadId=X` | |
| AbortMultipartUpload | `DELETE /<bucket>/<key>?uploadId=X` | |
| ListParts | `GET /<bucket>/<key>?uploadId=X` | |

### AWS CLI Usage

```bash
# Configure AWS CLI
aws configure set aws_access_key_id <token_id>
aws configure set aws_secret_access_key <any-value>
aws configure set default.region us-east-1

# Basic operations
aws --endpoint-url http://localhost:9000 s3 mb s3://mybucket
aws --endpoint-url http://localhost:9000 s3 cp file.txt s3://mybucket/
aws --endpoint-url http://localhost:9000 s3 ls s3://mybucket/
aws --endpoint-url http://localhost:9000 s3 cp s3://mybucket/file.txt ./downloaded.txt
aws --endpoint-url http://localhost:9000 s3 sync ./local-dir s3://mybucket/prefix/
```

## Native Protocol

Jay's native binary protocol uses a compact frame format for high-throughput scenarios.

### Go Client

```go
import "github.com/ivangsm/jay/proto/client"

// Connect
c, err := client.Dial("localhost:4444", tokenID, secret, 4)
if err != nil {
    log.Fatal(err)
}
defer c.Close()

// Create bucket
_, err = c.CreateBucket("mybucket")

// Upload object
result, err := c.PutObject("mybucket", "hello.txt",
    strings.NewReader("hello world"), 11, nil)

// Download object
obj, err := c.GetObject("mybucket", "hello.txt")
data, _ := io.ReadAll(obj.Body)
obj.Body.Close()

// Multipart upload
uploadID, _ := c.CreateMultipartUpload("mybucket", "large.bin", nil)
etag1, _ := c.UploadPart("mybucket", "large.bin", uploadID, 1, part1Reader, part1Size)
etag2, _ := c.UploadPart("mybucket", "large.bin", uploadID, 2, part2Reader, part2Size)
c.CompleteMultipartUpload("mybucket", "large.bin", uploadID, []client.CompletePart{
    {PartNumber: 1, ETag: etag1},
    {PartNumber: 2, ETag: etag2},
})

// List objects
list, _ := c.ListObjects("mybucket", &client.ListOptions{Prefix: "photos/"})
```

## Admin API

All endpoints require `Authorization: Bearer <JAY_ADMIN_TOKEN>`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/_jay/accounts` | POST | Create account |
| `/_jay/tokens` | POST | Create token |
| `/_jay/tokens` | GET | List tokens |
| `/_jay/tokens/{id}` | DELETE | Revoke token |
| `/_jay/metrics` | GET | Server metrics |
| `/_jay/presign` | POST | Generate presigned URL |
| `/_jay/quarantine` | GET | List quarantined objects |
| `/_jay/quarantine/revalidate` | POST | Revalidate quarantined object |
| `/_jay/quarantine` | DELETE | Purge quarantined objects |

### CLI Admin Tool

```bash
go build -o jay-admin ./cmd/jay-admin

export JAY_ADMIN_TOKEN=my-secret-admin-token

jay-admin create-account -name myapp
jay-admin create-token -account ACCOUNT_ID -name deploy
jay-admin list-tokens
jay-admin revoke-token -id TOKEN_ID
jay-admin metrics
jay-admin presign -bucket mybucket -key file.txt -token-id TOKEN_ID
jay-admin quarantine-list
jay-admin quarantine-purge
```

## Presigned URLs

Generate time-limited URLs via the admin API:

```bash
curl -X POST http://localhost:9001/_jay/presign \
  -H "Authorization: Bearer $JAY_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "token_id": "TOKEN_ID",
    "method": "GET",
    "bucket": "mybucket",
    "key": "secret-file.txt",
    "expires_seconds": 3600
  }'
```

The returned URL contains `X-Jay-Token`, `X-Jay-Expires`, and `X-Jay-Signature` query parameters and can be used without any authorization header.

## Bucket Policies

Set JSON policies on buckets to control access by token, prefix, and IP:

```json
{
  "version": "2024-01-01",
  "statements": [
    {
      "effect": "allow",
      "actions": ["object:get", "object:list"],
      "prefixes": ["public/"],
      "subjects": ["*"],
      "conditions": {
        "ip_whitelist": ["10.0.0.0/8"]
      }
    },
    {
      "effect": "deny",
      "actions": ["*"],
      "prefixes": ["secret/"],
      "subjects": ["*"]
    }
  ]
}
```

Deny statements always take precedence over allow.

## Monitoring

**Health checks** (on admin port, no auth required):
- `GET /health/live` -- liveness probe (always 200)
- `GET /health/ready` -- readiness probe (200 after startup recovery)

**Metrics:**
```bash
curl http://localhost:9001/_jay/metrics \
  -H "Authorization: Bearer $JAY_ADMIN_TOKEN"
```

Returns JSON with counters for PutObject, GetObject, DeleteObject, HeadObject, ListObjects, CreateBucket, DeleteBucket, AuthFailures, ChecksumFailures, BytesUploaded, BytesDownloaded, ObjectsQuarantined, and UptimeSeconds.

## Architecture

- **Metadata**: bbolt embedded key-value store (single-file, ACID)
- **Object storage**: Atomic writes (temp file, fsync, rename, fsync dir) with 2-level sharded directory layout
- **Checksums**: SHA-256 computed on every write, verified probabilistically on reads (5% sample)
- **Scrubber**: Background goroutine checks 10% of objects every 6 hours
- **GC**: Cleans temp files and empty dirs every 15 minutes
- **Backup**: Hourly metadata snapshots, keeps 24, prunes after 7 days
- **Recovery**: On startup, reconciles metadata and physical files, quarantines inconsistencies
