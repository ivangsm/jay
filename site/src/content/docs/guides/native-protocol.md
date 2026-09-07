---
title: The native protocol
description: A Go client over a binary frame protocol, and when it is worth using instead of S3.
---

The native protocol is a binary alternative to the S3 API, on the same server
and the same storage. It exists because HTTP + XML + SigV4 is a lot of ceremony
for a service talking to its own object store — SigV4 in particular re-hashes
the whole request body on every call.

The wire format is documented in
[Native protocol reference](/jay/reference/native-protocol/). This page is about
using it.

## Connecting

```go
import "github.com/ivangsm/jay/proto/client"

// The last argument is the connection pool size.
c, err := client.Dial("localhost:4444", tokenID, secret, 4)
if err != nil {
    log.Fatal(err)
}
defer c.Close()
```

`Dial` opens a pool, not a connection. Sizing it to your expected concurrency is
the single most important thing you can do for throughput — a request that finds
no idle connection pays for a TCP handshake and an auth handshake before it
sends a byte.

The client retries once if a pooled connection turns out to be dead, as long as
nothing has been read from the response yet.

## Operations

```go
// Buckets
_, err = c.CreateBucket("mybucket")

// Upload
result, err := c.PutObject("mybucket", "hello.txt",
    strings.NewReader("hello world"), 11, nil)

// Download
obj, err := c.GetObject("mybucket", "hello.txt")
data, _ := io.ReadAll(obj.Body)
obj.Body.Close()

// Multipart
uploadID, _ := c.CreateMultipartUpload("mybucket", "large.bin", nil)
etag1, _ := c.UploadPart("mybucket", "large.bin", uploadID, 1, part1Reader, part1Size)
etag2, _ := c.UploadPart("mybucket", "large.bin", uploadID, 2, part2Reader, part2Size)
c.CompleteMultipartUpload("mybucket", "large.bin", uploadID, []client.CompletePart{
    {PartNumber: 1, ETag: etag1},
    {PartNumber: 2, ETag: etag2},
})

// Listing
list, _ := c.ListObjects("mybucket", &client.ListOptions{Prefix: "photos/"})
```

## When to reach for it

Use the native protocol when:

- **Your client is Go** and lives on the same trusted network as Jay.
- **You upload bodies larger than 32 MiB in one request.** SigV4 buffers the
  body to recompute its hash, so the S3 path caps signed payloads at 32 MiB;
  larger uploads have to go unsigned or multipart. The native protocol has no
  such limit.
- **Request rate matters more than portability.** The protocol carries no XML,
  no header parsing and no per-request signature.

Use the S3 API when the caller is not Go, when the network is not trusted, or
when you want a tool you did not write to work against Jay.

## Security boundary

**Without TLS the handshake sends `token_id:secret` as plain bytes.** On a
container network or a private subnet that is fine, and it is the default. Over
anything else it publishes the credential to whatever is on the path.

Turn on TLS by giving the native listener its own key pair:

```bash
JAY_NATIVE_TLS_CERT=/etc/jay/native-fullchain.pem
JAY_NATIVE_TLS_KEY=/etc/jay/native-privkey.pem
```

Then dial with a TLS config:

```go
c, err := client.DialWithOptions(addr, tokenID, secret, client.Options{
    PoolSize:  4,
    TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
})
```

Three things about that pair are deliberate:

- **It is separate from `JAY_TLS_CERT`.** Enabling TLS on the S3 port does not
  enable it here. Inheriting that certificate would mean an unrelated setting
  silently changed this transport and broke every client already connected to
  it in the clear.
- **Setting one without the other aborts startup.** It does not warn and serve
  in the clear — that combination would publish every client's credential while
  looking like a working server.
- **There is no negotiation.** A TLS client fails against a plaintext listener
  and a plaintext client fails against a TLS one. A transport that fell back on
  its own would make the encryption unverifiable from the client side.

TLS costs the `sendfile(2)` fast path on downloads, since encryption has to see
every byte. That is the reason it is opt-in rather than the default.

If you do not use the native protocol at all, turn the listener off entirely
with an empty `JAY_NATIVE_ADDR`.

## Limits and timeouts

The server holds up to 1000 concurrent connections. Handshakes must complete
within 10 seconds and an idle connection is dropped after 60.

Read and write deadlines are **scaled to the size of the transfer** rather than
fixed: a floor of 30 seconds plus an allowance of 1 MB/s. A slow client cannot
pin a goroutine or hold a connection slot forever, and a large legitimate
transfer is not cut off halfway.

Rate limiting on this transport is **per token, not per connection**. Opening
more connections with the same token does not buy more budget.
