---
title: Observability
description: Health probes, the access log, the request ID and the metrics endpoint.
---

## Health probes

Both live on the admin port and need no authentication.

```
GET /health/live     always 200 while the process is up
GET /health/ready    200 once startup recovery has finished
```

**Readiness is a live check, not a one-time flag.** It fails if a bbolt read
transaction does not complete within its timeout, or if free space on the data
filesystem drops below `JAY_MIN_FREE_BYTES` (500 MiB by default).

That second condition is deliberate: a full disk corrupts bbolt, so Jay pulls
itself out of a load balancer pool before it gets there. If readiness starts
failing, look at the disk first.

## Access log

Every request writes one JSON line: `request_id`, method, path, `remote_ip`,
status and duration. `remote_ip` is the key the pre-auth rate limiter buckets
by, so a `429` can be attributed to a source.

```bash
grep '"request_id":"cc7a373fb33f4963"' jay.log
```

The `request_id` in the log is the same value the response carries in
`x-amz-request-id` and the same one inside the `<RequestId>` of an error
document — on **every** path, rejections included. An ID quoted in a bug report
finds its request.

That holds because the ID is minted in the outermost middleware, before anything
can answer. When it was minted further in, every log line carried
`"request_id":""` while the client saw a real one, and the responses that matter
most in a report — the rate limiter's `429`, the `501` for `aws-chunked`, a
rejected presigned URL — carried none at all.

The ID is never taken from an incoming header. A client that picks its own can
collide with another request or forge log entries.

## Metrics

```bash
curl http://localhost:9001/_jay/metrics \
  -H "Authorization: Bearer $JAY_ADMIN_TOKEN"
```

```json
{
  "put_object_total": 3, "get_object_total": 2, "head_object_total": 0,
  "delete_object_total": 0, "list_objects_total": 1,
  "create_bucket_total": 1, "delete_bucket_total": 0,
  "bytes_uploaded": 400000, "bytes_downloaded": 400000,
  "auth_failures": 0, "checksum_failures": 0,
  "fsync_failures": 0, "metadata_decode_failures": 0,
  "objects_quarantined": 0, "uptime_seconds": 41
}
```

Four of these are worth an alert rather than a dashboard:

| Counter | What a non-zero value means |
|---|---|
| `objects_quarantined` | Metadata and disk disagreed, or the scrubber found a digest that no longer matches. The object is waiting in [quarantine](/jay/reference/admin-api/) |
| `checksum_failures` | A client's declared digest did not match the bytes that arrived. Nothing was written, but something between you and Jay is corrupting data |
| `fsync_failures` | The filesystem failed to make a write durable. Treat it as a disk problem immediately |
| `metadata_decode_failures` | A record in bbolt could not be decoded |

`auth_failures` is normal in small numbers and worth watching in large ones.

## Log level

`JAY_LOG_LEVEL` takes `debug`, `info`, `warn` or `error`. Output is JSON on
stdout via `log/slog`.
