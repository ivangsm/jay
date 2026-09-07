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

Every readiness response — `200` and `503` alike — carries a `durability` block
saying what this instance has a recovery path for:

```json
{
  "status": "ready",
  "durability": {
    "metadata_backup": "hourly verified snapshot of meta/jay.db (bbolt): accounts, buckets, object records, tokens, multipart state",
    "object_bytes_backup": "none — object bytes under buckets/ — jay keeps no copy of them; back that directory up separately",
    "metadata_backup_dir": "/var/lib/jay/backups",
    "metadata_backup_shares_data_filesystem": true
  }
}
```

It never changes the status code — object bytes having no backup is Jay's design
and not a fault of the instance — but it is on the probe rather than only in the
docs because the probe is what someone reads during an incident. A `true` in the
last field means the snapshots would die with the database they protect.

If Jay could not work out the answer — an unwritable snapshot directory, a path
it cannot stat — the block carries an extra
`metadata_backup_dir_problem` and the boolean holds the **conservative**
answer (`true`), not a measured one. An isolation check that cannot run never
comes back as "isolated". See
[Backup and restore](/jay/guides/backup-and-restore/).

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

## A panic leaves a trace

There is no known input that makes Jay panic. The day there is, the request that
caused it is the one you need to find, and it used to be the only one that left
nothing at all: `net/http` recovered the handler, closed the connection with no
response, and wrote the stack through the package-level `log` — plain text in a
stream that is JSON everywhere else, which a collector that parses JSON drops.

Now a recovered panic produces **two** lines with the same `request_id` as the
response:

```json
{"level":"ERROR","msg":"panic recovered","request_id":"cc7a373fb33f4963",
 "method":"GET","path":"/photos/cat.jpg","remote_ip":"10.0.0.4",
 "response_started":false,"panic":"…","stack":"…"}
{"level":"INFO","msg":"request","request_id":"cc7a373fb33f4963","status":500}
```

The client gets a `500` whose `<RequestId>` is that same string. If the response
had already begun (`"response_started":true`) there is no honest status left to
send, so the connection is torn down instead: a half-written body under a `200`
is a success report for work that did not finish.

The native protocol recovers too, and there the stakes are higher — every
connection is its own goroutine, so an unrecovered panic took the whole process
down. Its line carries the `op`, the `stream_id` and the `token_id`, and the
connection is dropped rather than reused: a handler that panicked mid-frame
leaves the byte stream at an unknown offset.

Recovering keeps the process alive with state that may be inconsistent. That is
a deliberate trade — dying takes every other in-flight request with it and still
explains nothing — and `panics_recovered` plus `/health/ready` are what decide
whether the instance keeps taking traffic.

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
  "panics_recovered": 0,
  "objects_quarantined": 0, "uptime_seconds": 41
}
```

Five of these are worth an alert rather than a dashboard:

| Counter | What a non-zero value means |
|---|---|
| `objects_quarantined` | Metadata and disk disagreed, or the scrubber found a digest that no longer matches. The object is waiting in [quarantine](/jay/reference/admin-api/) |
| `checksum_failures` | A client's declared digest did not match the bytes that arrived. Nothing was written, but something between you and Jay is corrupting data |
| `fsync_failures` | The filesystem failed to make a write durable. Treat it as a disk problem immediately |
| `metadata_decode_failures` | A record in bbolt could not be decoded |
| `panics_recovered` | A handler panicked and was recovered. The process is alive with state that may be inconsistent — find the `panic recovered` line, and consider replacing the instance |

`auth_failures` is normal in small numbers and worth watching in large ones.

## Log level

`JAY_LOG_LEVEL` takes `debug`, `info`, `warn` or `error`. Output is JSON on
stdout via `log/slog`.
