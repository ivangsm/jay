---
title: Seed token
description: Creating an account and token at startup, idempotently, without an admin API call.
---

Jay can create an account and a token when it starts, so a fresh deployment does
not need a manual admin API call before clients can authenticate.

| Variable | Purpose |
|---|---|
| `JAY_SEED_TOKEN_ACCOUNT` | Name of the account to create, e.g. `myapp` |
| `JAY_SEED_TOKEN_ID` | Deterministic token ID the client will use |
| `JAY_SEED_TOKEN_SECRET` | Plaintext secret; bcrypt-hashed before storage |

## Rules

- **All three set** → Jay creates the account (idempotent by name) and the token
  (idempotent by ID) with wildcard actions (`"*"`). The same credentials work
  against the S3 API and the native protocol.
- **All three empty** → seeding is skipped. Bootstrap tokens through the admin
  API instead.
- **One or two set** → Jay **refuses to start**. A partially configured seed is
  a deployment mistake, not a mode.

The seeded token is created with **wildcard permissions** — no action list, no
bucket scope, no prefix scope. If you want it narrowed, narrow it afterwards
through the admin API.

## Idempotence and rotation

On every restart Jay looks up the account by name and reuses its ID, then looks
up the token by ID:

- If the stored bcrypt hash matches `JAY_SEED_TOKEN_SECRET`, it logs
  `seed: token already present, reusing` and moves on.
- **If the hash does not match**, it logs a warning —
  `seed: token exists but secret does not match env; refusing to overwrite` —
  and **keeps the old secret**. Jay never silently overwrites a token.

To rotate the secret, either change `JAY_SEED_TOKEN_ID` to a new value (the old
token stays active until you revoke it), or revoke the old token through the
admin API first and then set the new secret and restart.

## Example

```bash
export JAY_SEED_TOKEN_ACCOUNT=myapp
export JAY_SEED_TOKEN_ID=myapp-primary
export JAY_SEED_TOKEN_SECRET=$(openssl rand -base64 32)
./jay
```

First boot:

```
seed: account created name=myapp account_id=...
seed: token created token_id=myapp-primary
```

Every boot after that:

```
seed: account exists, reusing
seed: token already present, reusing
```
