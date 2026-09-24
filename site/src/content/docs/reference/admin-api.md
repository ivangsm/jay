---
title: Admin API
description: Endpoints for accounts, tokens, metrics, presigned URLs and quarantine, and the trail they leave.
---

The admin API lives on the admin port (`:9001` by default) under the `/_jay`
prefix. Every endpoint requires the admin bearer token:

```
Authorization: Bearer <JAY_ADMIN_TOKEN>
```

**This port should never face an untrusted network.** It mints credentials.

The same port also serves the health probes, pprof, and `GET /metrics` — the
Prometheus endpoint, which can be given its own read-only token so a monitoring
system never holds this one. See [Observability](/jay/reference/observability/#metrics).

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/_jay/accounts` | POST | Create an account |
| `/_jay/tokens` | POST | Create a token |
| `/_jay/tokens` | GET | List tokens |
| `/_jay/tokens/{id}` | DELETE | Revoke a token |
| `/_jay/metrics` | GET | Server metrics |
| `/_jay/presign` | POST | Generate a presigned URL |
| `/_jay/quarantine` | GET | List quarantined objects |
| `/_jay/quarantine/revalidate` | POST | Revalidate a quarantined object |
| `/_jay/quarantine` | DELETE | Purge one quarantined object, or all of them |
| `/_jay/buckets/{name}` | GET | Visibility and policy of one bucket |
| `/_jay/buckets/{name}/policy` | PUT | Install or replace the bucket policy |
| `/_jay/buckets/{name}/policy` | DELETE | Remove the bucket policy |
| `/_jay/buckets/{name}/visibility` | PUT | Switch between `private` and `public-read` |

Token creation and presigning are covered in
[Authentication](/jay/reference/authentication/).

## Errors

Every error is a JSON document with `Content-Type: application/json`:

```json
{"error": "unknown action \"object:read\" in allowed_actions: use \"*\" or any of …"}
```

| Status | When |
|---|---|
| `400` | The body is not valid JSON, has a field the endpoint does not take, or misses or misspells a required one. That includes an account without a `name`, a token without `allowed_actions` or with an action that does not exist, and an `expires_at` that is not a future RFC 3339 time |
| `401` | No admin token, or the wrong one — the metrics token included, which opens `/metrics` and nothing under `/_jay`. After five failures from one address, that address is refused — the right token included — for 15 minutes, on `/_jay`, pprof and `/metrics` alike |
| `404` | No endpoint at that path, or the thing it names does not exist: bucket, token, quarantined object |
| `405` | The path exists, but not with that method. The `Allow` header lists the methods it takes |
| `409` | A quarantine operation named an object that is not in quarantine |
| `413` | A bucket policy larger than 64 KiB |
| `500` | Jay failed: a database read, a file that could not be removed, a purge of the whole quarantine that left objects behind. The message says what |
| `503` | Metrics are not wired into this instance |

A `4xx` means nothing was written.

## Request ID and audit trail

Every response on this port carries an `x-amz-request-id` header — the same
header the S3 API uses — and every request leaves one access line in the log
with that ID. The ID is minted by Jay; one sent by the client is ignored.

Every endpoint that changes something also writes an `audit` line with the same
ID, once the change has committed: `account.create`, `token.create`,
`token.revoke`, `presign.issue`, `quarantine.revalidate`, `quarantine.purge`,
`quarantine.purge_all`, `bucket.policy.put`, `bucket.policy.delete` and
`bucket.visibility.put`. It records the IDs involved — a new token's id,
account, actions, scopes and expiry; a presigned URL's token, method, bucket,
key and expiry — and **never** a token secret, a presigned URL or a signature.
A request that fails writes no audit line. The full list of fields is in
[Observability](/jay/reference/observability/#audit-trail).

When something goes wrong, quote the `x-amz-request-id` of the response: it
finds both lines.

## Tokens

`POST /_jay/tokens` takes `account_id` and `allowed_actions` — both required —
and optionally `name`, `bucket_scope`, `prefix_scope` and `expires_at`. What
each one grants is in [Authentication](/jay/reference/authentication/).

`allowed_actions` is checked where it enters: an action that is not in the
[list](/jay/reference/authentication/#scoping), and not `"*"`, is a `400`.
Accepting it would mint a token that looks right and fails every request that
needed the misspelt action.

`expires_at` is an RFC 3339 timestamp in the future. The token stops
authenticating at that instant, and the response echoes it back so you can see
it was installed:

```json
{"token_id": "…", "secret": "…", "expires_at": "2030-01-02T15:04:05Z"}
```

Without `expires_at` the token does not expire, and the response has no such
field. A time in the past is refused rather than stored: the token would be
dead on arrival.

`DELETE /_jay/tokens/{id}` answers `204` — also for a token that was already
revoked — and `404` for an id that names no token. Revocation takes effect
immediately, including for connections already authenticated: it is re-checked
on every cached auth hit.

## Bucket policy and visibility

These two are what decide who can reach a bucket, so they live here rather than
on the S3 port: Jay's policy dialect is not AWS's, and visibility has no S3
operation at all. See
[S3 compatibility](/jay/reference/s3-compatibility/) for the reasoning, and
[Authentication](/jay/reference/authentication/) for what a policy document
means.

The request body of `PUT .../policy` **is** the policy document — no envelope,
so the file you edit is the file you send. Up to 64 KiB.

```bash
curl -X PUT http://localhost:9001/_jay/buckets/mybucket/policy \
  -H "Authorization: Bearer $JAY_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @policy.json

# → {"bucket":"mybucket","statements":2}
```

The reply counts the statements rather than saying `ok`. On an access-control
change, "it worked" with nothing behind it is worth very little; the count is
the cheapest proof the document was parsed and not merely stored.

```bash
curl -X PUT http://localhost:9001/_jay/buckets/mybucket/visibility \
  -H "Authorization: Bearer $JAY_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"visibility":"public-read"}'
```

Both take effect on the next request: nothing caches a bucket record.

### The document is validated on the way in

A bucket policy that parses can still be inert, and an inert access-control
document is the worst kind — it looks installed and does nothing. So these are
`400` at the door instead of a surprise months later:

| Refused | Why it would otherwise be silent |
|---|---|
| An action outside the [action list](/jay/reference/authentication/) | A misspelt `object:read` matches nothing, so the deny that was meant to close a prefix leaves it open |
| An `effect` that is not `allow` or `deny` | Matches nothing |
| An empty `actions` or `subjects` | Matches nothing. Use `["*"]` for "any authenticated token" |
| A policy with no statements | Grants and denies nothing. Use `DELETE` if that is the intent |
| A malformed CIDR in `ip_whitelist` | The dangerous one: an entry that does not parse is dropped, and an **empty** whitelist matches every address — so `10.0.0/8`, one dot short, turns an internal-only grant into an internet-wide one |

A refused document is not stored, so the previous policy stays in force.

Removing a policy **closes** a bucket rather than opening one: with no policy
there is nothing to grant on, and the default is deny.

## jay-admin

`jay-admin` ships in the release archives and in the container image, and wraps
the same endpoints.

```bash
export JAY_ADMIN_TOKEN=my-secret-admin-token

jay-admin create-account -name myapp
jay-admin create-token -account ACCOUNT_ID -name deploy \
  -actions bucket:write-meta,object:put,object:get,object:list
jay-admin create-token -account ACCOUNT_ID -name reader -actions object:get \
  -bucket-scope mybucket -prefix-scope public/ -expires-at 2030-01-02T15:04:05Z
jay-admin list-tokens
jay-admin revoke-token -id TOKEN_ID
jay-admin metrics
jay-admin presign -bucket mybucket -key file.txt -token-id TOKEN_ID
jay-admin presign -bucket mybucket -key file.txt -token-id TOKEN_ID \
  -style aws -host s3.example.com
jay-admin quarantine-list
jay-admin quarantine-revalidate -bucket-id BUCKET_ID -key file.txt
jay-admin quarantine-purge -bucket-id BUCKET_ID -key file.txt
jay-admin quarantine-purge

jay-admin get-bucket -bucket mybucket
jay-admin set-bucket-policy -bucket mybucket -file policy.json
jay-admin delete-bucket-policy -bucket mybucket
jay-admin set-bucket-visibility -bucket mybucket -visibility public-read
```

`create-token` needs `-actions`: a comma-separated list of the actions in
[Authentication](/jay/reference/authentication/#scoping), or `'*'` — quoted, or
the shell expands it — for all of them. An unknown action is refused before
anything is sent. `-bucket-scope` and `-prefix-scope` are comma-separated too.

`set-bucket-policy` reads the document from a file, or from standard input with
`-file -`, and sends those bytes unchanged — so an error names a line that
exists in the file you wrote.

Every command exits non-zero when the server refuses the call, and prints the
server's reason.

## Quarantine

Quarantined objects are ones where metadata and disk disagree — a record with no
file, or a file with no record — or where the scrubber found a digest that no
longer matches the bytes.

**Jay never deletes an inconsistency on its own.** An inconsistency is the only
evidence of whatever went wrong, and deleting it destroys the trace. Purging is
an explicit operator action.

Both operations act on quarantined objects only, and the check runs in the same
database transaction as the write: an object restored or overwritten in the
meantime is never touched. Naming an object that is not in quarantine is a
`409`, one that does not exist a `404`.

**Revalidate** — `POST /_jay/quarantine/revalidate` with
`{"bucket_id": "…", "key": "…"}` — re-hashes the file and restores the object
if it now matches its recorded checksum. The answer is `{"restored": true}` or
`{"restored": false}`; a `false` leaves the object in quarantine and its bytes
where they are.

**Purge** — `DELETE /_jay/quarantine` — takes either one object or all of them,
never both in the same request:

| Body | Answer |
|---|---|
| `{"bucket_id": "…", "key": "…"}` | `204` once the file and the record are gone |
| `{"mode": "all"}` | `200` with `{"purged": 3, "failed": []}` |
| `{"mode": "all"}`, something failed | `500` with `{"error": "…", "purged": 2, "failed": [{"bucket_id": "…", "key": "…", "error": "…"}]}` |

A purge removes the file first and the record second, and a file that cannot be
removed stops it: the object stays in quarantine and in the listing, and the
purge can be retried. The reverse order would leave a file with no record,
which recovery moves into `quarantine/` at the next start — where nothing lists
or purges it — under a response that said it was gone. A purge of the whole
quarantine keeps going past a failure, and reports each one.

## jay-rekey

`JAY_SIGNING_SECRET` is the AES-GCM key that encrypts token secrets in bbolt.
Changing it directly makes every stored token unreadable. `jay-rekey`
re-encrypts them under a new key instead.

```bash
# jay must be stopped: bbolt holds an exclusive lock while it runs.
JAY_OLD_SIGNING_SECRET=<current secret> \
JAY_SIGNING_SECRET=<new secret> \
jay-rekey -data-dir /data
# Rekeyed 3 token(s) successfully.
```

- It runs **offline**. Against a database the server holds open it fails after
  a second, without touching anything.
- It **never creates a database**. A `-data-dir` or `-db` with no `jay.db` in it
  — a typo, or the `./data` default from the wrong directory — is an error, not
  "nothing rekeyed".
- The new secret must be **at least 32 bytes**, the same floor the server
  enforces at startup; a shorter one is refused before anything is written.
- It is **all or nothing**. If one token decrypts under neither secret — a
  wrong `JAY_OLD_SIGNING_SECRET`, say — nothing is rewritten.
- A **second run** with the same arguments changes nothing and says
  `No tokens under the old secret — nothing rekeyed.`
- Tokens that are **already under the new secret** are left alone. That covers
  a server restarted with the new secret before the rekey, which mints tokens
  under it in the meantime: the rekey moves the old ones and keeps those.
