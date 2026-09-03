---
title: Command-line client
description: jay bucket, ls, cp, rm and sync over the native protocol.
---

The server binary is also the client. Any subcommand talks to a running Jay over
the [native protocol](/jay/guides/native-protocol/); with no subcommand, `jay`
starts the server.

```bash
export JAY_TOKEN_ID=<token_id>
export JAY_TOKEN_SECRET=<token-secret>
export JAY_NATIVE_ADDR=localhost:4444

jay bucket mb images
jay cp ./photo.webp jay://images/users/123.webp
jay ls -l jay://images/users/
jay sync ./assets jay://images/assets
jay rm -r jay://images/old/
```

## Commands

| Command | What it does |
|---|---|
| `jay bucket ls` / `mb NAME` / `rb NAME` | List, create or delete buckets |
| `jay ls [-r] [-l] jay://B[/PREFIX]` | List objects; `-r` descends, `-l` adds size, checksum and type |
| `jay cp [-r] SRC DST` | Copy to, from, or between buckets |
| `jay rm [-r] jay://B/KEY` | Delete an object, or everything under a prefix |
| `jay sync SRC DST` | Mirror a directory to or from a bucket |
| `jay version` | Print the build version |

Locations are either local paths or `jay://BUCKET/KEY` URIs. Credentials come
from `JAY_TOKEN_ID` / `JAY_TOKEN_SECRET` (or `client.token_id` /
`client.token_secret` in the YAML config), and every command also accepts
`--addr`, `--token-id` and `--token-secret`.

Unlike the server, the client does **not** require `JAY_ADMIN_TOKEN` or
`JAY_SIGNING_SECRET`. `jay ls` has no business demanding the server's secrets.

## Three behaviours worth knowing

**`sync` compares SHA-256, not timestamps.** Jay stores a checksum for every
object, so an unchanged file is skipped because its contents match — not because
its mtime looks old. The digest of a reassembled multipart object equals the
digest of the whole file, so this holds for large objects too.

**Uploads over 64 MiB are split into multipart automatically**, and a failure
aborts the upload server-side instead of leaving orphan parts behind.

**A partial failure exits non-zero.** `cp -r` and `sync` keep going after a
failed file, print which ones failed, and end with a count. A transfer that
skipped half its files never reports success.

## Prefixes always end in a slash

Recursive operations normalise the prefix: `jay rm -r jay://b/assets` acts on
`assets/`, not on every key beginning with the letters `assets`. Without that,
it would also delete `assets2/`.
