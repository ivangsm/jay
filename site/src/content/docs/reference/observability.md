---
title: Observability
description: Health probes, the access log, the audit trail, the request ID and the metrics endpoints.
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

Every request on the S3 port writes one JSON line: `request_id`, method, path,
`remote_ip`, status and duration. `remote_ip` is the key the pre-auth rate
limiter buckets by, so a `429` can be attributed to a source.

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
most in a report — the rate limiter's `429`, the rejection of an `aws-chunked` body, a
rejected presigned URL — carried none at all.

The ID is never taken from an incoming header. A client that picks its own can
collide with another request or forge log entries.

### The admin listener

Every request on the admin port — `/_jay`, `/metrics`, pprof and the health
probes alike — gets the same treatment: a request ID minted at the edge,
returned in the same `x-amz-request-id` header, and one line with
`"msg":"admin request"`:

```json
{"level":"INFO","msg":"admin request","request_id":"5e0b8f6f2a41c9d3",
 "method":"POST","path":"/_jay/tokens","remote_ip":"10.0.0.7",
 "status":201,"bytes":123,"duration":84211000}
```

`path` never carries the query string, and no body is ever logged: the
response of `POST /_jay/tokens` holds a token secret, and a presigned URL holds
its signature in the query. `remote_ip` is the direct peer — the address the
admin backoff counts failures against — and never a forwarding header.

**Health probes are logged at `DEBUG`**, not excluded. An orchestrator probing
every five seconds would otherwise write some seventeen thousand lines a day
over everything else; at the default `info` level a healthy probe writes
nothing, and `JAY_LOG_LEVEL=debug` shows every one. A probe that answers
anything other than `200` — a readiness check failing — is logged at `WARN`,
because that is exactly the line someone will look for.

A refused credential adds an `admin auth failure` line at `WARN`, with the same
`request_id` and a `reason`.

## Audit trail

Every change made through the admin API also writes an `audit` line, with the
same `request_id` as its access line, the `action`, the `remote_ip`, and the IDs
it touched:

```json
{"level":"INFO","msg":"audit","request_id":"5e0b8f6f2a41c9d3",
 "action":"token.create","remote_ip":"10.0.0.7",
 "token_id":"6f1c…","account_id":"96779f73-…","name":"deploy",
 "allowed_actions":["object:get"],"bucket_scope":null,"prefix_scope":null,
 "expires_at":"never"}
```

| `action` | Endpoint | Recorded |
|---|---|---|
| `account.create` | `POST /_jay/accounts` | `account_id`, `name` |
| `token.create` | `POST /_jay/tokens` | `token_id`, `account_id`, `name`, `allowed_actions`, `bucket_scope`, `prefix_scope`, `expires_at` |
| `token.revoke` | `DELETE /_jay/tokens/{id}` | `token_id` |
| `presign.issue` | `POST /_jay/presign` | `token_id`, `method`, `bucket`, `key`, `style`, `expires_seconds`, `expires_at` |
| `quarantine.revalidate` | `POST /_jay/quarantine/revalidate` | `bucket_id`, `key`, `restored` |
| `quarantine.purge` | `DELETE /_jay/quarantine` (one object) | `bucket_id`, `key` |
| `quarantine.purge_all` | `DELETE /_jay/quarantine` (`mode: all`) | `purged`, `failed` |
| `bucket.policy.put` | `PUT /_jay/buckets/{name}/policy` | `bucket`, `statements` |
| `bucket.policy.delete` | `DELETE /_jay/buckets/{name}/policy` | `bucket` |
| `bucket.visibility.put` | `PUT /_jay/buckets/{name}/visibility` | `bucket`, `visibility` |

Three rules hold for every one of them:

- **It is written after the change commits.** A request that fails leaves its
  access line, with its status, and no audit line — a trail that records
  attempts as changes is worse than none. The one exception is a purge of the
  whole quarantine that removed some objects and not others: those objects are
  gone for good, so the line is written anyway, at `WARN`, with both counts.
- **It never carries a credential.** Not the secret of a new token, not a
  presigned URL, not a signature.
- **Reads write none.** Listing tokens, reading metrics or a bucket's policy
  leave only their access line.

The admin token is shared, so the trail cannot say *who* — only from where,
when, and what. `remote_ip` plus the `request_id` is the handle.

```bash
# when did this token appear, and from where?
grep '"msg":"audit"' jay.log | grep '"token_id":"6f1c…"'
```

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

The admin listener recovers the same way: a JSON `500` carrying the request's
ID, a `panic recovered` line, and an access line that says `500` rather than the
`200` nothing had overwritten yet.

Recovering keeps the process alive with state that may be inconsistent. That is
a deliberate trade — dying takes every other in-flight request with it and still
explains nothing — and `panics_recovered` plus `/health/ready` are what decide
whether the instance keeps taking traffic.

## Metrics

`GET /metrics` on the admin port serves every counter in the
[Prometheus text format](https://prometheus.io/docs/instrumenting/exposition_formats/)
(version 0.0.4), plus two readings that used to exist only inside the readiness
probe. It is generated by hand — Jay has no Prometheus client dependency — and
checked by a parser in the test suite.

### Who may scrape

By default `/metrics` takes the **admin token**, like everything else on that
port. That works, but it hands your monitoring system the credential that mints
tokens. Two settings change it:

| Setting | `/metrics` accepts |
|---|---|
| neither (default) | `Authorization: Bearer $JAY_ADMIN_TOKEN` |
| `JAY_METRICS_TOKEN` | that token, or the admin token. The metrics token opens `/metrics` and **nothing else**: on `/_jay` and pprof it is refused like a wrong one |
| `JAY_METRICS_PUBLIC=true` | anyone who can reach the port. Jay logs a `WARN` at every startup while it is on |

The metrics token is a secret with the admin token's rules: no default, at
least 32 characters, and it must differ from `JAY_ADMIN_TOKEN`. Setting it
together with `JAY_METRICS_PUBLIC=true` is contradictory and aborts startup.

A refused scrape goes through the same gate as the rest of the port: the same
lockout after five failures from one address, and the same
`jay_auth_failures_total{surface="admin"}` counter. A **successful** scrape with
the metrics token does not reset an address's failure count — only the admin
token does, or holding the metrics token would allow unlimited guesses at the
admin one.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: jay
    metrics_path: /metrics
    scheme: http          # https when JAY_TLS_CERT is set
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/jay-metrics-token
    static_configs:
      - targets: ["jay.internal:9001"]
```

With `JAY_METRICS_PUBLIC=true`, drop the `authorization` block.

### What is exposed

| Metric | Type | Meaning |
|---|---|---|
| `jay_operations_total{op}` | counter | Object and bucket operations served, S3 API and native protocol combined. `op` is `put_object`, `get_object`, `head_object`, `delete_object`, `list_objects`, `create_bucket` or `delete_bucket` |
| `jay_uploaded_bytes_total` | counter | Object bytes stored by uploads |
| `jay_downloaded_bytes_total` | counter | Object bytes served in download responses, ranges included |
| `jay_auth_failures_total{surface}` | counter | Requests refused for their credentials. `surface="s3"` is the S3 API; `surface="admin"` is the admin port (`/_jay`, `/metrics`, pprof), including requests refused because their address is locked out |
| `jay_checksum_failures_total` | counter | Objects whose bytes on disk no longer matched their recorded SHA-256 when the scrubber verified them |
| `jay_objects_quarantined_total` | counter | Objects moved to [quarantine](/jay/reference/admin-api/) by startup recovery or the scrubber |
| `jay_fsync_failures_total` | counter | `fsync` calls that failed while making a write durable |
| `jay_metadata_decode_failures_total` | counter | Records in bbolt that could not be decoded and were skipped |
| `jay_panics_recovered_total` | counter | Handler panics recovered by the HTTP listeners or the native protocol |
| `jay_start_time_seconds` | gauge | Unix time the process started. Uptime is `time() - jay_start_time_seconds` |
| `jay_build_info{version,commit}` | gauge | Always `1`; the labels name the running build |
| `jay_data_dir_free_bytes` | gauge | Space available to Jay on the filesystem holding `JAY_DATA_DIR`. Readiness fails below `JAY_MIN_FREE_BYTES`. Absent if the filesystem cannot be read |
| `jay_metadata_db_up` | gauge | `1` when a read transaction on bbolt completed within the readiness timeout during this scrape, `0` when it did not |
| `jay_metadata_db_ping_seconds` | gauge | How long that transaction took. **Absent when it failed**: an error that comes back instantly is not a fast database |

The last three are measured on every scrape — one `statfs` and one read
transaction, the same work a readiness probe does, bounded by the same
two-second timeout. Nothing is cached.

Six are worth an alert rather than a dashboard:

| Metric | What a rising value means |
|---|---|
| `jay_objects_quarantined_total` | Metadata and disk disagreed, or the scrubber found a digest that no longer matches. The object is waiting in quarantine |
| `jay_checksum_failures_total` | Bytes on disk changed under Jay. Together with the one above, the signal that a disk is degrading |
| `jay_fsync_failures_total` | The filesystem failed to make a write durable. Treat it as a disk problem immediately |
| `jay_metadata_decode_failures_total` | A record in bbolt could not be decoded |
| `jay_panics_recovered_total` | A handler panicked and was recovered. The process is alive with state that may be inconsistent — find the `panic recovered` line, and consider replacing the instance |
| `jay_auth_failures_total{surface="admin"}` | Someone is presenting the wrong credential to the admin port, which should sit on a private network |

`jay_auth_failures_total{surface="s3"}` is normal in small numbers — an expired
presigned URL, an anonymous read of a private bucket — and worth watching in
large ones.

```yaml
# rules.yml
groups:
  - name: jay
    rules:
      - alert: JayDiskDegrading
        expr: increase(jay_checksum_failures_total[1h]) > 0 or increase(jay_objects_quarantined_total[1h]) > 0
      - alert: JayMetadataDBDown
        expr: jay_metadata_db_up == 0
      - alert: JayDiskFillingUp
        expr: jay_data_dir_free_bytes < 2 * 524288000   # twice JAY_MIN_FREE_BYTES
```

### The JSON form

`GET /_jay/metrics` still answers the same counters as JSON, behind the admin
token only — `jay-admin metrics` reads it:

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
  "auth_failures": 0, "admin_auth_failures": 0, "checksum_failures": 0,
  "fsync_failures": 0, "metadata_decode_failures": 0,
  "panics_recovered": 0,
  "objects_quarantined": 0, "uptime_seconds": 41
}
```

`auth_failures` is the S3 API's count and `admin_auth_failures` the admin
port's; they are the two series of `jay_auth_failures_total`.

## Log level

`JAY_LOG_LEVEL` takes `debug`, `info`, `warn` or `error`. Output is JSON on
stdout via `log/slog`.
