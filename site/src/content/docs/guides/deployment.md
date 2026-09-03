---
title: Deploying Jay
description: TLS, reverse proxies, disk, backups and what to expose.
---

## What to expose

| Listener | Default | Expose to |
|---|---|---|
| S3 API | `:9000` | Whatever needs to store objects, including the public internet if that is your design |
| Admin API | `:9001` | Nothing outside your network. It creates accounts and tokens |
| Native protocol | `:4444` | Nothing outside your network. The handshake carries the token secret in the clear |

If you do not use the native protocol, disable its listener entirely by setting
`JAY_NATIVE_ADDR` to an empty value. The startup line then reports
`"native":"disabled"`.

## TLS

Jay terminates TLS itself when you give it a certificate:

```bash
JAY_TLS_CERT=/etc/jay/fullchain.pem
JAY_TLS_KEY=/etc/jay/privkey.pem
```

This covers the S3 and admin listeners. The native protocol is always plaintext
and belongs on an internal network.

**Enable TLS if you use `mc` or `warp`.** minio-go signs plaintext uploads with
SigV4's streaming mode, which Jay refuses; over TLS the same clients upload
normally. See [S3 compatibility](/jay/reference/s3-compatibility/).

## Behind a reverse proxy

Jay does not trust forwarding headers by default, because a client that can
forge `X-Forwarded-For` can evade the pre-auth rate limiter and poison your
access logs.

```bash
JAY_TRUST_PROXY_HEADERS=true
```

With this on, `X-Forwarded-For` and `X-Real-IP` are honoured **only when the
direct TCP peer is loopback or RFC1918**. A request arriving straight from the
internet carrying the header is still attributed to its real address.

Make sure your proxy does not buffer request bodies to disk if you upload large
objects, and that its own body-size limit is at or above
`JAY_MAX_OBJECT_SIZE` (5 GiB by default).

## Disk

The whole state of the server is `JAY_DATA_DIR`. Back that up and you have
backed up Jay.

Readiness fails when free space on that filesystem drops below
`JAY_MIN_FREE_BYTES` (500 MiB by default), which pulls the instance out of a
load balancer pool before the disk fills. A full disk corrupts bbolt; Jay would
rather stop serving than get there.

## Backups

Jay snapshots its bbolt metadata every hour, verifies each snapshot after
writing it, keeps 24 and prunes after 7 days. **A snapshot that fails
verification is deleted** — an unrestorable backup is worse than none, because
it satisfies a retention policy while being useless.

Two things to be clear about:

- **`JAY_BACKUP_DIR` defaults to `<JAY_DATA_DIR>/backups`**, which is the same
  disk. For real disaster recovery, point it at a separate volume.
- **The backup covers metadata only.** Object bytes are not in it. A `PUT` over
  an existing key replaces the file, and the old bytes are gone — Jay has no
  [versioning](/jay/internals/limits/).

## Health probes

Both are on the admin port and need no authentication:

```
GET /health/live    always 200 while the process is up
GET /health/ready   200 once startup recovery has finished
```

Readiness is a live check, not a one-time flag. It fails if a bbolt read
transaction does not complete within its timeout, or if free space drops below
the floor. If readiness starts failing, look at the disk first.

## Upgrades

Jay is a single process over a single data directory. Stop it, replace the
binary or image, start it. Startup recovery reconciles metadata against the
files on disk before the server accepts traffic, so an unclean stop is a handled
case rather than an incident.
