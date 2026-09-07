---
title: Authentication
description: Accounts, tokens, scopes, SigV4, presigned URLs and bucket policies.
---

## Accounts and tokens

An **account** owns buckets. A **token** belongs to an account and carries the
permissions a client presents. Both are created through the
[admin API](/jay/reference/admin-api/).

```bash
curl -X POST http://localhost:9001/_jay/accounts \
  -H "Authorization: Bearer $JAY_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "myapp"}'
# {"account_id": "...", "name": "myapp", ...}

curl -X POST http://localhost:9001/_jay/tokens \
  -H "Authorization: Bearer $JAY_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id": "ACCOUNT_ID", "name": "deploy-token",
       "allowed_actions": ["object:get", "object:put", "object:list"]}'
# {"token_id": "...", "secret": "..."}
```

`allowed_actions` is required. A token that does not say what it may do is not
created — there is no implicit default, and `400 allowed_actions is required` is
the answer. Use `["*"]` if you really want all of them.

The secret is returned once. It is bcrypt-hashed before storage and cannot be
read back.

## Presenting a token

**Bearer:**

```
Authorization: Bearer <token_id>:<secret>
```

**AWS SigV4:** use `token_id` as the access key and the secret as the secret
key. Jay validates the timestamp and verifies the signature. Both SigV4 forms
work — the `Authorization` header and the query-string form used by presigned
URLs.

The region is not server-side configuration. Jay reads it out of
`X-Amz-Credential` and uses it only to derive the signing key, so any region
works as long as the client signs and sends the same one.

## Scoping

```json
{
  "account_id": "...",
  "name": "readonly",
  "allowed_actions": ["object:get", "object:list"],
  "bucket_scope": ["public-assets"],
  "prefix_scope": ["images/"]
}
```

The available actions are `bucket:list`, `bucket:read-meta`,
`bucket:write-meta`, `object:get`, `object:put`, `object:delete`, `object:list`,
`multipart:create`, `multipart:upload-part`, `multipart:complete` and
`multipart:abort`.

## Cross-account access

**A token can only reach the buckets of the account that issued it.** That is
the default and it holds for every operation — objects, listings, multipart and
bucket metadata alike — no matter how wide the token's actions or how empty its
scopes.

Exactly three things open a bucket to an account that does not own it:

| | What it grants |
|---|---|
| `bucket_scope` on the token | Everything the token's actions allow, on the named buckets. Set through the admin API, so it is the operator delegating — not the bucket |
| `visibility: public-read` | `object:get` and `object:list`, to anyone, including callers with no credentials. Never writes |
| An `allow` statement in the bucket policy | Exactly the actions, prefixes and IP ranges the statement names, to the subjects it names |

A bucket that says nothing about a stranger says no.

## Presigned URLs

A presigned URL grants one operation on one key for a limited time, with no
authorization header. Jay accepts two forms.

### SigV4, the standard one

Anything that speaks S3 can mint one — boto3's `generate_presigned_url`,
`aws s3 presign`, minio-go's `PresignedGetObject`, the AWS SDK presigners.

```python
url = s3.generate_presigned_url(
    "get_object",
    Params={"Bucket": "mybucket", "Key": "secret-file.txt"},
    ExpiresIn=3600,
)
```

Rules Jay enforces on every such URL:

- `X-Amz-Expires` is mandatory and capped at 7 days, AWS's own limit. There is
  no presigned URL without a deadline.
- `X-Amz-Date` must be within 15 minutes of server time in the future, and the
  URL dies once signing time plus `X-Amz-Expires` has passed.
- `host` must be among the `SignedHeaders`, so a URL minted for one endpoint
  cannot be replayed against another.
- The signature covers the method, the path and every query parameter except
  `X-Amz-Signature` itself.
- **The URL can never do more than the token that signed it.** Actions, bucket
  scope, prefix scope and bucket policies all still apply.

### Jay's own form

`X-Jay-Token`, `X-Jay-Expires` and `X-Jay-Signature`, HMAC'd with
`JAY_SIGNING_SECRET`. It predates SigV4 support and remains the default of the
admin endpoint.

A request carrying an `Authorization` header is never treated as a presign: the
header form wins, so nobody can attach two credentials and keep whichever one
verifies.

### Minting one from the admin API

```bash
curl -X POST http://localhost:9001/_jay/presign \
  -H "Authorization: Bearer $JAY_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "token_id": "TOKEN_ID",
    "method": "GET",
    "bucket": "mybucket",
    "key": "secret-file.txt",
    "expires_seconds": 3600,
    "style": "aws",
    "host": "s3.example.com"
  }'
```

| Field | Default | Notes |
|---|---|---|
| `style` | `"jay"` | `"aws"` emits SigV4; `"jay"` emits `X-Jay-*` |
| `host` | `JAY_LISTEN_ADDR` | Required for `"aws"` when the listen address has no hostname (`:9000`), because the SigV4 signature covers the host |
| `region` | `"us-east-1"` | `"aws"` only |
| `expires_seconds` | `3600` | A number, not a string; capped at 604800 (7 days) |

`style` defaults to `"jay"` so existing callers keep getting what they got
before. New integrations should ask for `"aws"`.

## Bucket policies

A policy controls access by subject, prefix and IP.

```json
{
  "version": "2024-01-01",
  "statements": [
    {
      "effect": "allow",
      "actions": ["object:get", "object:list"],
      "prefixes": ["public/"],
      "subjects": ["*"],
      "conditions": { "ip_whitelist": ["10.0.0.0/8"] }
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

An `allow` only ever **grants**. It cannot narrow what the owner may do and it
cannot widen what the caller's token was issued for — the token's actions and
scopes are checked first. A `deny` is evaluated afterwards and wins.

:::caution
An allow with `"actions": ["*"]`, `"subjects": ["*"]` and no `prefixes` hands
the whole bucket to every authenticated token of every account, `DeleteBucket`
included. Name the actions and the prefixes.
:::

### Installing one

Through the admin API, not the S3 port — Jay's dialect is not AWS's, and
`PutBucketPolicy` keeps answering `501`:

```bash
jay-admin set-bucket-policy -bucket mybucket -file policy.json
jay-admin delete-bucket-policy -bucket mybucket
jay-admin get-bucket -bucket mybucket
```

The document is validated when it arrives, not when it is evaluated: a misspelt
action, an empty `subjects`, an effect that is neither `allow` nor `deny` or a
CIDR that does not parse are all `400` and nothing is stored. Every one of them
would otherwise produce a policy that looks installed and never matches. The
full list is in [Admin API](/jay/reference/admin-api/).

## Bucket visibility

Every bucket is created `private`. `public-read` is the only other value, and it
grants `object:get` and `object:list` to everyone — including callers with no
credentials at all. Never writes.

```bash
jay-admin set-bucket-visibility -bucket mybucket -visibility public-read
jay-admin set-bucket-visibility -bucket mybucket -visibility private
```

## Rate limiting

Two layers. Before authentication, requests are limited **by source IP**,
because authenticating is expensive — bcrypt for bearer tokens, a database read
plus HMAC for SigV4 — and without that gate an unauthenticated client burns CPU
before the limiter ever sees it. After authentication, the limit is **per
token**.

On the native protocol the budget is per token as well, not per connection:
opening more connections does not buy more.
