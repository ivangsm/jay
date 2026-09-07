---
title: Admin API
description: Endpoints for accounts, tokens, metrics, presigned URLs and quarantine.
---

The admin API lives on the admin port (`:9001` by default) under the `/_jay`
prefix. Every endpoint requires the admin bearer token:

```
Authorization: Bearer <JAY_ADMIN_TOKEN>
```

**This port should never face an untrusted network.** It mints credentials.

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
| `/_jay/quarantine` | DELETE | Purge quarantined objects |
| `/_jay/buckets/{name}` | GET | Visibility and policy of one bucket |
| `/_jay/buckets/{name}/policy` | PUT | Install or replace the bucket policy |
| `/_jay/buckets/{name}/policy` | DELETE | Remove the bucket policy |
| `/_jay/buckets/{name}/visibility` | PUT | Switch between `private` and `public-read` |

Token creation and presigning are covered in
[Authentication](/jay/reference/authentication/).

Revoking a token takes effect immediately, including for connections already
authenticated: revocation is re-checked on every cached auth hit.

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
jay-admin create-token -account ACCOUNT_ID -name deploy
jay-admin list-tokens
jay-admin revoke-token -id TOKEN_ID
jay-admin metrics
jay-admin presign -bucket mybucket -key file.txt -token-id TOKEN_ID
jay-admin presign -bucket mybucket -key file.txt -token-id TOKEN_ID \
  -style aws -host s3.example.com
jay-admin quarantine-list
jay-admin quarantine-purge

jay-admin get-bucket -bucket mybucket
jay-admin set-bucket-policy -bucket mybucket -file policy.json
jay-admin delete-bucket-policy -bucket mybucket
jay-admin set-bucket-visibility -bucket mybucket -visibility public-read
```

`set-bucket-policy` reads the document from a file, or from standard input with
`-file -`, and sends those bytes unchanged — so an error names a line that
exists in the file you wrote.

## Quarantine

Quarantined objects are ones where metadata and disk disagree — a record with no
file, or a file with no record — or where the scrubber found a digest that no
longer matches the bytes.

**Jay never deletes an inconsistency on its own.** An inconsistency is the only
evidence of whatever went wrong, and deleting it destroys the trace. Purging is
an explicit operator action.

`revalidate` re-checks a quarantined object and restores it if it now verifies.

## jay-rekey

`JAY_SIGNING_SECRET` is the AES-GCM key that encrypts token secrets in bbolt.
Changing it directly makes every stored token unreadable. `jay-rekey`
re-encrypts them under a new key instead.
