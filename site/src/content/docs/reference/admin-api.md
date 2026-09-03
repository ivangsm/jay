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

Token creation and presigning are covered in
[Authentication](/jay/reference/authentication/).

Revoking a token takes effect immediately, including for connections already
authenticated: revocation is re-checked on every cached auth hit.

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
```

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
